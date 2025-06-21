import pytest, json
from fastapi.testclient import TestClient
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'app'))
from main import app

client = TestClient(app)

# --- GitHub stub ---------------------------------
class _Blob:
    def __init__(self, content="Hello", sha="deadbeef", size=5):
        self.decoded_content = content.encode() if isinstance(content, str) else content
        self.sha = sha
        self.size = size
        self.encoding = "utf-8"
        self.path = "test/path"

class _Commit:
    def __init__(self, sha="abc123", message="Test commit"):
        self.sha = sha
        self.commit = type('obj', (object,), {
            'message': message,
            'author': type('obj', (object,), {
                'name': 'Test Author',
                'date': type('obj', (object,), {'isoformat': lambda self: '2024-01-01T00:00:00Z'})()
            })()
        })()

class _Branch:
    def __init__(self, name="main", sha="abc123"):
        self.name = name
        self.commit = type('obj', (object,), {'sha': sha})()

class _PullRequest:
    def __init__(self, number=1, title="Test PR", state="open"):
        self.number = number
        self.title = title
        self.state = state
        self.html_url = f"https://github.com/test/repo/pull/{number}"
        
    def create_issue_comment(self, body):
        return type('obj', (object,), {'html_url': 'https://github.com/test/repo/pull/1#comment'})()
    
    def merge(self, commit_title=None, commit_message=None, merge_method=None):
        return type('obj', (object,), {'merged': True, 'message': 'Successfully merged'})()

class _Workflow:
    def __init__(self, id="test.yml"):
        self.id = id
    
    def create_dispatch(self, ref=None, inputs=None):
        return True

class DummyRepo:
    def __init__(self):
        self.name = "test-repo"
        self.full_name = "test/repo"
        self.description = "Test repository"
        self.html_url = "https://github.com/test/repo"
        self.private = False
        self.fork = False
        self.stargazers_count = 10
        self.watchers_count = 5
        self.forks_count = 2
        self.open_issues_count = 1
        self.default_branch = "main"
        self.created_at = type('obj', (object,), {'isoformat': lambda self: '2024-01-01T00:00:00Z'})()
        self.updated_at = type('obj', (object,), {'isoformat': lambda self: '2024-01-01T00:00:00Z'})()
        self.pushed_at = type('obj', (object,), {'isoformat': lambda self: '2024-01-01T00:00:00Z'})()
        self.language = "Python"
        self.size = 1024
        
    def get_contents(self, path, ref="HEAD"):
        return _Blob()
    
    def create_file(self, path, message, content, branch=None):
        return {"status": "success"}
    
    def update_file(self, path, message, content, sha, branch=None):
        return {"status": "success"}
    
    def create_pull(self, title, body, head, base, draft=False):
        return _PullRequest(title=title)
    
    def get_pull(self, number):
        return _PullRequest(number=number)
    
    def get_pulls(self, state="open", head=None, base=None, sort="created", direction="desc"):
        return [_PullRequest(1, "Test PR 1"), _PullRequest(2, "Test PR 2")]
    
    def create_repo(self, name, description, private, auto_init):
        return type('obj', (object,), {'html_url': f'https://github.com/test/{name}'})()
    
    def edit(self, name):
        return True
    
    def delete(self):
        return True
    
    def get_workflow(self, workflow_id):
        return _Workflow(workflow_id)
    
    def get_branch(self, name):
        return _Branch(name)
    
    def create_git_ref(self, ref, sha):
        return True
    
    def get_branches(self):
        return [_Branch("main"), _Branch("develop")]
    
    def get_commits(self, sha=None):
        return [_Commit("abc123", "First commit"), _Commit("def456", "Second commit")]

class DummyUser:
    def get_repo(self, name):
        return DummyRepo()
    
    def create_repo(self, name, description, private, auto_init):
        return DummyRepo()

class DummyGH:
    def get_repo(self, repo_name):
        return DummyRepo()
    
    def get_user(self, username=None):
        return DummyUser()
    
    def search_repositories(self, query):
        return [DummyRepo()]

@pytest.fixture(autouse=True)
def monkey_github(monkeypatch):
    from main import Github
    monkeypatch.setattr("main.Github", lambda *_a, **_k: DummyGH())
    yield

# Test helper
def make_request(op, args=None):
    hdrs = {"Authorization": "Bearer test"}
    body = {"op": op, "args": args or {}}
    return client.post("/", headers=hdrs, json=body)

# --- Tests ---

def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "healthy"

def test_get_file():
    r = make_request("get_file", {"repo": "test/repo", "path": "README.md"})
    assert r.status_code == 200
    assert r.json()["content"] == "Hello"

def test_put_file():
    r = make_request("put_file", {
        "repo": "test/repo",
        "path": "test.txt",
        "content": "Hello World",
        "message": "Add test file"
    })
    assert r.status_code == 200
    assert r.json()["status"] == "success"

def test_create_pr():
    r = make_request("create_pr", {
        "repo": "test/repo",
        "title": "Test PR",
        "head": "feature-branch",
        "base": "main",
        "body": "This is a test PR"
    })
    assert r.status_code == 200
    assert r.json()["status"] == "success"
    assert "pr_number" in r.json()["data"]

def test_merge_pr():
    r = make_request("merge_pr", {
        "repo": "test/repo",
        "pr_number": 1,
        "commit_title": "Merge PR",
        "merge_method": "merge"
    })
    assert r.status_code == 200
    assert r.json()["status"] == "success"
    assert r.json()["data"]["merged"] == True

def test_comment_pr():
    r = make_request("comment_pr", {
        "repo": "test/repo",
        "pr_number": 1,
        "comment_body": "This looks good!"
    })
    assert r.status_code == 200
    assert r.json()["status"] == "success"
    assert "comment_url" in r.json()["data"]

def test_list_prs():
    r = make_request("list_prs", {
        "repo": "test/repo",
        "state": "open"
    })

    assert r.status_code == 200
    assert r.json()["status"] == "success"
    assert len(r.json()["data"]["pull_requests"]) == 2

def test_repo_admin_create():
    r = make_request("repo_admin", {
        "action": "create",
        "new_repo_name": "new-test-repo",
        "description": "A new test repository",
        "private": False,
        "auto_init": True
    })
    assert r.status_code == 200
    assert r.json()["status"] == "success"

def test_repo_admin_rename():
    r = make_request("repo_admin", {
        "action": "rename",
        "repo": "test/old-repo",
        "new_repo_name": "new-repo-name"
    })
    assert r.status_code == 200
    assert r.json()["status"] == "success"

def test_repo_admin_delete():
    r = make_request("repo_admin", {
        "action": "delete",
        "repo": "test/repo-to-delete"
    })
    assert r.status_code == 200
    assert r.json()["status"] == "success"

def test_workflow_dispatch():
    r = make_request("workflow_dispatch", {
        "repo": "test/repo",
        "workflow_id": "ci.yml",
        "ref": "main",
        "inputs": {"version": "1.0.0"}
    })
    assert r.status_code == 200
    assert r.json()["status"] == "success"

def test_list_repos():
    r = make_request("list_repos", {"query": "test"})
    assert r.status_code == 200
    assert "repositories" in r.json()
    assert r.json()["count"] >= 0

def test_get_repo_info():
    r = make_request("get_repo_info", {"repo": "test/repo"})
    assert r.status_code == 200
    assert r.json()["status"] == "success"
    assert r.json()["data"]["name"] == "test-repo"
    assert r.json()["data"]["full_name"] == "test/repo"

def test_create_branch():
    r = make_request("create_branch", {
        "repo": "test/repo",
        "branch_name": "new-feature",
        "source_branch": "main"
    })
    assert r.status_code == 200
    assert r.json()["status"] == "success"

def test_list_branches():
    r = make_request("list_branches", {"repo": "test/repo"})
    assert r.status_code == 200
    assert r.json()["status"] == "success"
    assert len(r.json()["data"]["branches"]) == 2

def test_list_commits():
    r = make_request("list_commits", {"repo": "test/repo", "sha": "main"})
    assert r.status_code == 200
    assert r.json()["status"] == "success"
    assert len(r.json()["data"]["commits"]) == 2

def test_list_operations():
    r = make_request("list_operations")
    assert r.status_code == 200
    assert "operations" in r.json()
    operations = [op["name"] for op in r.json()["operations"]]
    expected_ops = [
        "get_file", "list_repos", "put_file", "create_pr", "merge_pr", 
        "comment_pr", "list_prs", "repo_admin", "workflow_dispatch", 
        "get_repo_info", "create_branch", "list_branches", "list_commits"
    ]
    for op in expected_ops:
        assert op in operations

def test_ping():
    r = make_request("ping")
    assert r.status_code == 200
    assert "message" in r.json()
    assert "timestamp" in r.json()

def test_invalid_operation():
    r = make_request("invalid_op")
    assert r.status_code == 400
    assert "Unsupported operation" in r.json()["detail"]

def test_missing_api_key():
    body = {"op": "ping", "args": {}}
    r = client.post("/", json=body)  # No Authorization header
    assert r.status_code == 403  # FastAPI returns 403 for missing auth

def test_invalid_api_key():
    hdrs = {"Authorization": "Bearer invalid_key"}
    body = {"op": "ping", "args": {}}
    r = client.post("/", headers=hdrs, json=body)
    assert r.status_code == 401
