import pytest, json
from fastapi.testclient import TestClient
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'app'))
from main import app

client = TestClient(app, headers={"Host": "localhost"})

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
    monkeypatch.setattr("main.API_KEY", "test")
    yield

# Test helper
def make_request(request, op, args=None):
    hdrs = {"Authorization": "Bearer test"}
    body = {"op": op, "args": args or {}}
    
    r = client.post("/", headers=hdrs, json=body)
    
    status = "PASS" if r.status_code == 200 and r.json().get("status") == "success" else "FAIL"
    details = ""
    suggested_causes = ""

    if status == "FAIL":
        details = f"Status Code: {r.status_code}, Response: {r.text}"
        if r.status_code == 401:
            suggested_causes = "Permissions issue or expired token."
        elif r.status_code == 404:
            suggested_causes = "API endpoint not found or invalid resource."
        else:
            suggested_causes = "Potential API bug or unexpected server response."
            
    request.node.result_info = {
        "function": op,
        "status": status,
        "details": details,
        "request_payload": body,
        "response_data": r.json() if r.status_code == 200 else r.text,
        "suggested_causes": suggested_causes
    }
    return r

# --- Tests ---

def test_health(request):
    r = client.get("/health")
    status = "PASS" if r.status_code == 200 and r.json().get("status") == "healthy" else "FAIL"
    details = ""
    suggested_causes = ""
    if status == "FAIL":
        details = f"Status Code: {r.status_code}, Response: {r.text}"
        suggested_causes = "Health check failed."
    request.node.result_info = {
        "function": "health_check",
        "status": status,
        "details": details,
        "request_payload": {},
        "response_data": r.json() if r.status_code == 200 else r.text,
        "suggested_causes": suggested_causes
    }
    assert r.status_code == 200
    assert r.json()["status"] == "healthy"

def test_get_file(request):
    r = make_request(request, "get_file", {"repo": "test/repo", "path": "README.md"})
    assert r.status_code == 200
    assert "content" in r.json() and r.json()["content"] != ""
    assert "sha" in r.json()
    assert "size" in r.json()
    assert "encoding" in r.json()

def test_put_file(request):
    r = make_request(request, "put_file", {
        "repo": "test/repo",
        "path": "test.txt",
        "content": "Hello World",
        "message": "Add test file"
    })
    assert r.status_code == 200
    assert r.json()["status"] == "success"

def test_create_pr(request):
    r = make_request(request, "create_pr", {
        "repo": "test/repo",
        "title": "Test PR",
        "head": "feature-branch",
        "base": "main",
        "body": "This is a test PR"
    })
    assert r.status_code == 200
    assert r.json()["status"] == "success"
    assert "pr_number" in r.json()["data"]
    assert r.json()["data"]["pr_number"] > 0

def test_merge_pr(request):
    r = make_request(request, "merge_pr", {
        "repo": "test/repo",
        "pr_number": 1,
        "commit_title": "Merge PR",
        "merge_method": "merge"
    })
    assert r.status_code == 200
    assert r.json()["status"] == "success"
    assert r.json()["data"]["merged"] == True

def test_comment_pr(request):
    r = make_request(request, "comment_pr", {
        "repo": "test/repo",
        "pr_number": 1,
        "comment_body": "This looks good!"
    })
    assert r.status_code == 200
    assert r.json()["status"] == "success"
    assert "comment_url" in r.json()["data"]
    assert r.json()["data"]["comment_url"] != ""

def test_list_prs(request):
    r = make_request(request, "list_prs", {
        "repo": "test/repo",
        "state": "open"
    })

    assert r.status_code == 200
    assert r.json()["status"] == "success"
    assert "pull_requests" in r.json()["data"]
    assert len(r.json()["data"]["pull_requests"]) > 0

def test_repo_admin_create(request):
    r = make_request(request, "repo_admin", {
        "action": "create",
        "new_repo_name": "new-test-repo",
        "description": "A new test repository",
        "private": False,
        "auto_init": True
    })
    # Repository creation through GitHub Apps returns 500 (wrapping 501 Not Implemented)
    assert r.status_code == 500
    assert "not yet implemented" in r.json()["detail"].lower()

def test_repo_admin_rename(request):
    r = make_request(request, "repo_admin", {
        "action": "rename",
        "repo": "test/old-repo",
        "new_repo_name": "new-repo-name"
    })
    assert r.status_code == 200
    assert r.json()["status"] == "success"

def test_repo_admin_delete(request):
    r = make_request(request, "repo_admin", {
        "action": "delete",
        "repo": "test/repo-to-delete"
    })
    assert r.status_code == 200
    assert r.json()["status"] == "success"

def test_workflow_dispatch(request):
    r = make_request(request, "workflow_dispatch", {
        "repo": "test/repo",
        "workflow_id": "ci.yml",
        "ref": "main",
        "inputs": {"version": "1.0.0"}
    })
    assert r.status_code == 200
    assert r.json()["status"] == "success"

def test_list_repos(request):
    r = make_request(request, "list_repos", {"query": "test"})
    assert r.status_code == 200
    assert r.json()["status"] == "error"
    assert "Unable to access repositories" in r.json()["data"]["error"]

def test_get_repo_info(request):
    r = make_request(request, "get_repo_info", {"repo": "test/repo"})
    assert r.status_code == 200
    assert r.json()["status"] == "success"
    assert "name" in r.json()["data"]
    assert r.json()["data"]["full_name"] == "test/repo"

def test_create_branch(request):
    r = make_request(request, "create_branch", {
        "repo": "test/repo",
        "branch_name": "new-feature-branch",
        "source_branch": "main"
    })
    assert r.status_code == 200
    assert r.json()["status"] == "success"

def test_list_branches(request):
    r = make_request(request, "list_branches", {"repo": "test/repo"})
    assert r.status_code == 200
    assert r.json()["status"] == "success"
    assert "branches" in r.json()["data"]
    assert len(r.json()["data"]["branches"]) > 0

def test_list_commits(request):
    r = make_request(request, "list_commits", {"repo": "test/repo", "sha": "main"})
    assert r.status_code == 200
    assert r.json()["status"] == "success"
    assert "commits" in r.json()["data"]
    assert len(r.json()["data"]["commits"]) > 0

def test_list_operations(request):
    # This tests the root endpoint which lists all available operations
    r = make_request(request, "list_operations")
    assert r.status_code == 200
    assert r.json()["status"] == "available"
    assert "operations" in r.json()
    assert len(r.json()["operations"]) > 0

def test_ping(request):
    r = make_request(request, "ping")
    assert r.status_code == 200
    assert "message" in r.json()
    assert r.json()["message"] == "BMAD GitHub Bridge is operational"

def test_invalid_operation(request):
    r = make_request(request, "invalid_op")
    assert r.status_code == 400
    assert "detail" in r.json()
    assert "Unsupported operation" in r.json()["detail"]

def test_missing_api_key(request):
    # Directly use client.post without make_request to test API key handling
    r = client.post("/", json={"op": "list_repos", "args": {}})
    status = "PASS" if r.status_code == 403 and "Not authenticated" in r.json().get("detail") else "FAIL"
    details = ""
    suggested_causes = ""
    if status == "FAIL":
        details = f"Status Code: {r.status_code}, Response: {r.text}"
        suggested_causes = "Authentication bypass or unexpected error."
    request.node.result_info = {
        "function": "missing_api_key",
        "status": status,
        "details": details,
        "request_payload": {"op": "list_repos", "args": {}},
        "response_data": r.json() if r.status_code == 403 else r.text,
        "suggested_causes": suggested_causes
    }
    assert r.status_code == 403
    assert "Not authenticated" in r.json()["detail"]

def test_invalid_api_key(request):
    # Directly use client.post without make_request to test API key handling
    r = client.post("/", headers={"Authorization": "Bearer wrong_key"}, json={"op": "list_repos", "args": {}})
    status = "PASS" if r.status_code == 401 and "Invalid API key" in r.json().get("detail") else "FAIL"
    details = ""
    suggested_causes = ""
    if status == "FAIL":
        details = f"Status Code: {r.status_code}, Response: {r.text}"
        suggested_causes = "Invalid key accepted or unexpected error."
    request.node.result_info = {
        "function": "invalid_api_key",
        "status": status,
        "details": details,
        "request_payload": {"op": "list_repos", "args": {}},
        "response_data": r.json() if r.status_code == 401 else r.text,
        "suggested_causes": suggested_causes
    }
    assert r.status_code == 401
    assert "Invalid API key" in r.json()["detail"]
