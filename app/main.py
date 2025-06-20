from fastapi import FastAPI, HTTPException, Depends, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from pydantic import BaseModel, Field
from github import GithubIntegration, Github
import os
import json
import uvicorn
import time
from typing import Optional, Dict, Any
from datetime import datetime
import logging

# ────────────────────────────  Logging  ────────────────────────────
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ───────────────────  Environment / Security Config  ───────────────────
API_KEY              = os.environ.get("API_KEY", "")                     # Bearer token for ChatGPT Action
WEBHOOK_SECRET       = os.environ.get("WEBHOOK_SECRET", "")              # (unused for now)
ALLOWED_ORIGINS      = os.environ.get("CORS_ORIGINS", "https://chat.openai.com").split(",")
RATE_LIMIT_REQUESTS  = int(os.environ.get("RATE_LIMIT_REQUESTS", "100"))
RATE_LIMIT_WINDOW    = int(os.environ.get("RATE_LIMIT_WINDOW",  "3600"))

# ─────────────────────  GitHub App credentials  ─────────────────────
CLIENT_ID   = os.environ["APP_ID"]                    # GitHub App *client* ID (string)
INSTALL_ID  = int(os.environ["INSTALLATION_ID"])      # Installation ID (int)
PK_PATH     = os.environ["PRIVATE_KEY_PATH"]          # /run/secrets/… path

# NOTE: keep as *string* for older PyGitHub versions
if API_KEY != "test":
    with open(PK_PATH, "rb") as f:
        PRIVATE_KEY = f.read().decode("utf-8")
    git_integration = GithubIntegration(CLIENT_ID, PRIVATE_KEY)
else:
    class DummyGitIntegration:
        def get_access_token(self, *_):
            class DummyAccessToken:
                token = "dummy_token"
            return DummyAccessToken()
    git_integration = DummyGitIntegration()

# ─────────────────────  FastAPI initialisation  ─────────────────────
app = FastAPI(
    title="GitHub App Bridge",
    version="3.0.1",
    description="Secure bridge for GitHub repository operations",
    docs_url=None,
    redoc_url=None,
)

# ─────────────────────  Middleware  ─────────────────────
# app.add_middleware(
#     TrustedHostMiddleware,
#     allowed_hosts=["bmad.onemainarmy.com", "localhost", "127.0.0.1"],
# )
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)

# ─────────────────────  Helper utilities  ─────────────────────
security = HTTPBearer()
rate_limit_storage: Dict[str, list[float]] = {}


def get_install_token() -> str:
    return git_integration.get_access_token(INSTALL_ID).token


def verify_api_key(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> str:
    if not API_KEY:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="API key not configured on server",
        )
    if credentials.credentials != API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
        )
    return credentials.credentials


def rate_limit_check(request: Request) -> None:
    now = time.time()
    ip = request.client.host
    history = [t for t in rate_limit_storage.get(ip, []) if now - t < RATE_LIMIT_WINDOW]
    rate_limit_storage[ip] = history
    if len(history) >= RATE_LIMIT_REQUESTS:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded: {RATE_LIMIT_REQUESTS} per {RATE_LIMIT_WINDOW} s",
        )
    history.append(now)


# ─────────────────────  Custom OpenAPI (servers fixed)  ─────────────────────
def custom_openapi_schema():
    if app.openapi_schema:
        return app.openapi_schema
    
    openapi_schema = {
        "openapi": "3.1.0",
        "info": {
            "title": "GitHub App Bridge",
            "version": "3.0.1",
            "description": "Secure bridge for GitHub repository operations via ChatGPT Actions",
        },
        "servers": [
            {
                "url": "https://bmad.onemainarmy.com/github",
                "description": "Production server",
            }
        ],
        "security": [{"BearerAuth": []}],
        "paths": {
            "/": {
                "post": {
                    "operationId": "bridgeCall",
                    "summary": "Execute GitHub repository operations",
                    "description": "Bridge endpoint for secure GitHub repository operations via ChatGPT Actions",
                    "security": [{"BearerAuth": []}],
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/Payload"}
                            }
                        },
                    },
                    "responses": {
                        "200": {
                            "description": "Operation successful",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "status": {"type": "string"},
                                            "data": {"type": "object"},
                                            "message": {"type": "string"}
                                        },
                                        "additionalProperties": True
                                    }
                                }
                            }
                        },
                        "400": {"description": "Bad request - invalid operation"},
                        "401": {"description": "Unauthorized - invalid API key"},
                        "429": {"description": "Rate limit exceeded"},
                        "500": {"description": "Internal server error"}
                    },
                }
            },
            "/health": {
                "get": {
                    "operationId": "healthCheck",
                    "summary": "Health Check",
                    "description": "Check if the API service is running and healthy",
                    "responses": {
                        "200": {
                            "description": "Service is healthy",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "status": {"type": "string"},
                                            "timestamp": {"type": "string"}
                                        }
                                    }
                                }
                            }
                        }
                    },
                }
            },
        },
        "components": {
            "securitySchemes": {
                "BearerAuth": {"type": "http", "scheme": "bearer"}
            },
            "schemas": {
                "Payload": {
                    "type": "object",
                    "required": ["op"],
                    "properties": {
                        "op": {"type": "string"},
                        "args": {"type": "object", "additionalProperties": True},
                    },
                }
            },
        },
    }
    app.openapi_schema = openapi_schema
    return openapi_schema

app.openapi = custom_openapi_schema

@app.get("/openapi.json", include_in_schema=False)
async def custom_openapi():
    return custom_openapi_schema()


# ─────────────────────  Pydantic models  ─────────────────────
class Payload(BaseModel):
    op: str = Field(..., description="Operation to perform")
    args: Dict[str, Any] = Field(default_factory=dict, description="Operation args")

class PutFilePayload(BaseModel):
    repo: str = Field(..., description="Repository name (owner/repo)")
    path: str = Field(..., description="File path in repository")
    content: str = Field(..., description="Content to write to file")
    message: str = Field(..., description="Commit message")
    branch: Optional[str] = Field(None, description="Optional: Branch name (default: default branch)")
    sha: Optional[str] = Field(None, description="Optional: SHA of the file to update (required for updates)")

class CreatePRPayload(BaseModel):
    repo: str = Field(..., description="Repository name (owner/repo)")
    title: str = Field(..., description="Pull request title")
    head: str = Field(..., description="Branch where changes are implemented")
    base: str = Field(..., description="Branch to merge changes into")
    body: Optional[str] = Field(None, description="Optional: Pull request body")
    draft: Optional[bool] = Field(None, description="Optional: Create as draft PR")

class MergePRPayload(BaseModel):
    repo: str = Field(..., description="Repository name (owner/repo)")
    pr_number: int = Field(..., description="Pull request number")
    commit_title: Optional[str] = Field(None, description="Optional: Title for merge commit")
    commit_message: Optional[str] = Field(None, description="Optional: Extra detail for merge commit")
    merge_method: Optional[str] = Field(None, description="Optional: Merge method (merge, squash, rebase)")

class CommentPRPayload(BaseModel):
    repo: str = Field(..., description="Repository name (owner/repo)")
    pr_number: int = Field(..., description="Pull request number")
    comment_body: str = Field(..., description="Comment to add to the pull request")

class ListPRsPayload(BaseModel):
    repo: str = Field(..., description="Repository name (owner/repo)")
    state: Optional[str] = Field(None, description="Optional: Filter by state (open, closed, all)")
    head: Optional[str] = Field(None, description="Optional: Filter by head user/org and branch")
    base: Optional[str] = Field(None, description="Optional: Filter by base branch")
    sort: Optional[str] = Field(None, description="Optional: Sort by (created, updated, popularity, long-running)")
    direction: Optional[str] = Field(None, description="Optional: Sort direction (asc, desc)")

class RepoAdminPayload(BaseModel):
    action: str = Field(..., description="Action to perform (create, rename, delete)")
    repo: str = Field(..., description="Repository name (owner/repo) - required for rename, delete")
    new_repo_name: Optional[str] = Field(None, description="New repository name (required for rename)")
    description: Optional[str] = Field(None, description="Optional: Repository description (required for create)")
    private: Optional[bool] = Field(None, description="Optional: Whether repo should be private (required for create)")
    auto_init: Optional[bool] = Field(None, description="Optional: Initialize with README (required for create)")

class WorkflowDispatchPayload(BaseModel):
    repo: str = Field(..., description="Repository name (owner/repo)")
    workflow_id: str = Field(..., description="Workflow file name or ID")
    ref: Optional[str] = Field(None, description="Optional: The ref (branch or tag) to trigger the workflow on (default: default branch)")
    inputs: Optional[Dict[str, Any]] = Field(None, description="Optional: Inputs to pass to the workflow")

class GetRepoInfoPayload(BaseModel):
    repo: str = Field(..., description="Repository name (owner/repo)")

class CreateBranchPayload(BaseModel):
    repo: str = Field(..., description="Repository name (owner/repo)")
    branch_name: str = Field(..., description="Name for the new branch")
    source_branch: Optional[str] = Field(None, description="Optional: Source branch to create from (default: default branch)")

class ListBranchesPayload(BaseModel):
    repo: str = Field(..., description="Repository name (owner/repo)")

class ListCommitsPayload(BaseModel):
    repo: str = Field(..., description="Repository name (owner/repo)")
    sha: Optional[str] = Field(None, description="Optional: SHA or branch name to list commits from")


# ─────────────────────  Health endpoint  ─────────────────────
@app.get("/health", include_in_schema=False)
async def health_check():
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}


# ─────────────────────  Main bridge endpoint  ─────────────────────
@app.post("/")
async def bridge_call(
    payload: Payload,
    request: Request,
    _api_key_ok: str = Depends(verify_api_key),
):
    rate_limit_check(request)
    logger.info("Op %s Args %s", payload.op, json.dumps(payload.args))

    gh = Github(get_install_token(), per_page=100)

    try:
        if payload.op == "get_file":
            return await handle_get_file(gh, payload.args)
        elif payload.op == "list_repos":
            return await handle_list_repos(gh, payload.args)
        elif payload.op == "list_operations":
            return {
                "operations": [
                    {
                        "name": "get_file",
                        "description": "Get file contents from a GitHub repository",
                        "args": {
                            "repo": "Repository name (owner/repo)",
                            "path": "File path in repository",
                            "ref": "Optional: Branch/commit reference (default: HEAD)"
                        }
                    },
                    {
                        "name": "list_repos",
                        "description": "Search GitHub repositories (GitHub App has limited access)",
                        "args": {
                            "type": "Optional: Repository type filter (all, owner, member, public, private)",
                            "query": "Optional: Search query (e.g., 'user:username', 'org:orgname', 'repo-name in:name')"
                        }
                    },
                    {
                        "name": "put_file",
                        "description": "Create or update a file in a GitHub repository",
                        "args": {
                            "repo": "Repository name (owner/repo)",
                            "path": "File path in repository",
                            "content": "Content to write to file",
                            "message": "Commit message",
                            "branch": "Optional: Branch name (default: default branch)",
                            "sha": "Optional: SHA of the file to update (required for updates)"
                        }
                    },
                    {
                        "name": "create_pr",
                        "description": "Create a new pull request",
                        "args": {
                            "repo": "Repository name (owner/repo)",
                            "title": "Pull request title",
                            "head": "Branch where changes are implemented",
                            "base": "Branch to merge changes into",
                            "body": "Optional: Pull request body",
                            "draft": "Optional: Create as draft PR"
                        }
                    },
                    {
                        "name": "merge_pr",
                        "description": "Merge a pull request",
                        "args": {
                            "repo": "Repository name (owner/repo)",
                            "pr_number": "Pull request number",
                            "commit_title": "Optional: Title for merge commit",
                            "commit_message": "Optional: Extra detail for merge commit",
                            "merge_method": "Optional: Merge method (merge, squash, rebase)"
                        }
                    },
                    {
                        "name": "comment_pr",
                        "description": "Add a comment to a pull request",
                        "args": {
                            "repo": "Repository name (owner/repo)",
                            "pr_number": "Pull request number",
                            "comment_body": "Comment to add to the pull request"
                        }
                    },
                    {
                        "name": "list_prs",
                        "description": "List pull requests in a GitHub repository",
                        "args": {
                            "repo": "Repository name (owner/repo)",
                            "state": "Optional: Filter by state (open, closed, all)",
                            "head": "Optional: Filter by head user/org and branch",
                            "base": "Optional: Filter by base branch",
                            "sort": "Optional: Sort by (created, updated, popularity, long-running)",
                            "direction": "Optional: Sort direction (asc, desc)"
                        }
                    },
                    {
                        "name": "repo_admin",
                        "description": "Perform repository administration actions (create, rename, delete)",
                        "args": {
                            "action": "Action to perform (create, rename, delete)",
                            "repo": "Repository name (owner/repo) - required for rename, delete",
                            "new_repo_name": "New repository name (required for rename)",
                            "description": "Optional: Repository description (required for create)",
                            "private": "Optional: Whether repo should be private (required for create)",
                            "auto_init": "Optional: Initialize with README (required for create)"
                        }
                    },
                    {
                        "name": "workflow_dispatch",
                        "description": "Trigger a GitHub Actions workflow dispatch event",
                        "args": {
                            "repo": "Repository name (owner/repo)",
                            "workflow_id": "Workflow file name or ID",
                            "ref": "Optional: The ref (branch or tag) to trigger the workflow on (default: default branch)",
                            "inputs": "Optional: Inputs to pass to the workflow (JSON object)"
                        }
                    },
                    {
                        "name": "get_repo_info",
                        "description": "Get information about a GitHub repository",
                        "args": {
                            "repo": "Repository name (owner/repo)"
                        }
                    },
                    {
                        "name": "create_branch",
                        "description": "Create a new branch in a GitHub repository",
                        "args": {
                            "repo": "Repository name (owner/repo)",
                            "branch_name": "Name for the new branch",
                            "source_branch": "Optional: Source branch to create from (default: default branch)"
                        }
                    },
                    {
                        "name": "list_branches",
                        "description": "List branches in a GitHub repository",
                        "args": {
                            "repo": "Repository name (owner/repo)"
                        }
                    },
                    {
                        "name": "list_commits",
                        "description": "List commits in a GitHub repository",
                        "args": {
                            "repo": "Repository name (owner/repo)",
                            "sha": "Optional: SHA or branch name to list commits from"
                        }
                    }
                ],
                "status": "available"
            }
        elif payload.op == "ping":
            return {
                "message": "BMAD GitHub Bridge is operational",
                "timestamp": datetime.utcnow().isoformat(),
                "version": "3.0.1"
            }
        elif payload.op == "put_file":
            return await handle_put_file(gh, PutFilePayload(**payload.args))
        elif payload.op == "create_pr":
            return await handle_create_pr(gh, CreatePRPayload(**payload.args))
        elif payload.op == "merge_pr":
            return await handle_merge_pr(gh, MergePRPayload(**payload.args))
        elif payload.op == "comment_pr":
            return await handle_comment_pr(gh, CommentPRPayload(**payload.args))
        elif payload.op == "list_prs":
            return await handle_list_prs(gh, ListPRsPayload(**payload.args))
        elif payload.op == "repo_admin":
            return await handle_repo_admin(gh, RepoAdminPayload(**payload.args))
        elif payload.op == "workflow_dispatch":
            return await handle_workflow_dispatch(gh, WorkflowDispatchPayload(**payload.args))
        elif payload.op == "get_repo_info":
            return await handle_get_repo_info(gh, GetRepoInfoPayload(**payload.args))
        elif payload.op == "create_branch":
            return await handle_create_branch(gh, CreateBranchPayload(**payload.args))
        elif payload.op == "list_branches":
            return await handle_list_branches(gh, ListBranchesPayload(**payload.args))
        elif payload.op == "list_commits":
            return await handle_list_commits(gh, ListCommitsPayload(**payload.args))
        else:
            raise HTTPException(
                status_code=400, 
                detail=f"Unsupported operation '{payload.op}'. Available operations: get_file, list_repos, list_operations, ping, put_file, create_pr, merge_pr, comment_pr, list_prs, repo_admin, workflow_dispatch, get_repo_info, create_branch, list_branches, list_commits"
            )
    except HTTPException:
        raise  # Re-raise HTTP exceptions as-is
    except Exception as exc:
        logger.error("Error in %s: %s", payload.op, exc)
        raise HTTPException(
            status_code=500, 
            detail=f"Operation '{payload.op}' failed: {str(exc)}"
        )


# ─────────────────────  Operation handlers  ─────────────────────
async def handle_get_file(gh: Github, args: dict):
    repo = gh.get_repo(args["repo"])
    blob = repo.get_contents(args["path"], ref=args.get("ref", "HEAD"))
    return {
        "content": blob.decoded_content.decode(),
        "sha": blob.sha,
        "size": blob.size,
        "encoding": blob.encoding,
    }


async def handle_list_repos(gh: Github, args: dict):
    repo_type = args.get("type", "all")
    query = args.get("query", "")
    
    try:
        # For GitHub Apps, we need to use search or specific repo access
        # since we can't list all user repos with app permissions
        
        if query:
            # Search for repositories with the given query
            search_result = gh.search_repositories(query)
            repos = list(search_result)
        else:
            # Try to access some known repositories or provide a helpful message
            # Since GitHub Apps have limited repo access, we'll search for public repos
            # from common organizations or provide instructions
            search_queries = [
                "user:DrJLabs"
            ]

            repos = []
            for search_query in search_queries:
                try:
                    search_result = gh.search_repositories(search_query)
                    repos.extend(list(search_result)[:10])  # Limit results per query
                except Exception as e:
                    logger.warning(f"Search query '{search_query}' failed: {e}")
                    continue
            
            # Remove duplicates based on full_name
            seen = set()
            unique_repos = []
            for repo in repos:
                if repo.full_name not in seen:
                    seen.add(repo.full_name)
                    unique_repos.append(repo)
            repos = unique_repos
    
        # Convert to list with essential information
        repo_list = []
        for repo in repos:
            try:
                repo_list.append({
                    "name": repo.name,
                    "full_name": repo.full_name,
                    "description": repo.description,
                    "private": repo.private,
                    "url": repo.html_url,
                    "clone_url": repo.clone_url,
                    "default_branch": repo.default_branch,
                    "created_at": repo.created_at.isoformat() if repo.created_at else None,
                    "updated_at": repo.updated_at.isoformat() if repo.updated_at else None,
                    "language": repo.language,
                    "size": repo.size,
                    "stargazers_count": repo.stargazers_count,
                    "forks_count": repo.forks_count
                })
            except Exception as e:
                logger.warning(f"Error processing repo {repo.full_name}: {e}")
                continue
        
        return {
            "repositories": repo_list,
            "count": len(repo_list),
            "filter": repo_type,
            "query": query,
            "note": "GitHub App has limited repository access. Use 'query' parameter to search for specific repositories."
        }
        
    except Exception as e:
        logger.error(f"Error in list_repos: {e}")
        return {
            "repositories": [],
            "count": 0,
            "error": str(e),
            "note": "GitHub App repository access is limited. Try using the 'query' parameter to search for specific repositories."
        }


async def handle_put_file(gh: Github, args: PutFilePayload):
    owner, repo_name = args.repo.split("/")
    repo = gh.get_user(owner).get_repo(repo_name)
    try:
        contents = repo.get_contents(args.path, ref=args.branch if args.branch else repo.default_branch)
        repo.update_file(contents.path, args.message, args.content, contents.sha, branch=args.branch if args.branch else repo.default_branch)
        return {"status": "success", "data": {"message": "File updated successfully"}}
    except Exception as e:
        # If file does not exist, create it
        if "not found" in str(e).lower():
            repo.create_file(args.path, args.message, args.content, branch=args.branch if args.branch else repo.default_branch)
            return {"status": "success", "data": {"message": "File created successfully"}}
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"GitHub API error: {e}")

async def handle_create_pr(gh: Github, args: CreatePRPayload):
    owner, repo_name = args.repo.split("/")
    repo = gh.get_user(owner).get_repo(repo_name)
    try:
        pull_request = repo.create_pull(
            title=args.title,
            body=args.body,
            head=args.head,
            base=args.base,
            draft=args.draft if args.draft is not None else False
        )
        return {"status": "success", "data": {"pr_number": pull_request.number, "url": pull_request.html_url}}
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"GitHub API error: {e}")

async def handle_merge_pr(gh: Github, args: MergePRPayload):
    owner, repo_name = args.repo.split("/")
    repo = gh.get_user(owner).get_repo(repo_name)
    try:
        pull = repo.get_pull(args.pr_number)
        merge_result = pull.merge(
            commit_title=args.commit_title,
            commit_message=args.commit_message,
            merge_method=args.merge_method
        )
        return {"status": "success", "data": {"merged": merge_result.merged, "message": merge_result.message}}
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"GitHub API error: {e}")

async def handle_comment_pr(gh: Github, args: CommentPRPayload):
    owner, repo_name = args.repo.split("/")
    repo = gh.get_user(owner).get_repo(repo_name)
    try:
        pull = repo.get_pull(args.pr_number)
        comment = pull.create_issue_comment(args.comment_body)
        return {"status": "success", "data": {"comment_url": comment.html_url}}
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"GitHub API error: {e}")

async def handle_list_prs(gh: Github, args: ListPRsPayload):
    owner, repo_name = args.repo.split("/")
    repo = gh.get_user(owner).get_repo(repo_name)
    try:
        pulls = repo.get_pulls(
            state=args.state if args.state else "open",
            head=args.head if args.head else Github.UNKNOWN,
            base=args.base if args.base else Github.UNKNOWN,
            sort=args.sort if args.sort else "created",
            direction=args.direction if args.direction else "desc"
        )
        pr_list = [{"number": pr.number, "title": pr.title, "url": pr.html_url, "state": pr.state} for pr in pulls]
        return {"status": "success", "data": {"pull_requests": pr_list}}
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"GitHub API error: {e}")

async def handle_repo_admin(gh: Github, args: RepoAdminPayload):
    owner_login = args.repo.split("/")[0] if args.repo else None
    org_or_user = gh.get_user(owner_login) if owner_login else gh.get_user() # Get authenticated user if no owner provided for create

    try:
        if args.action == "create":
            if not args.new_repo_name or args.description is None or args.private is None or args.auto_init is None:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing required arguments for repository creation")
            new_repo = org_or_user.create_repo(
                name=args.new_repo_name,
                description=args.description,
                private=args.private,
                auto_init=args.auto_init
            )
            return {"status": "success", "data": {"message": "Repository created successfully", "repo_url": new_repo.html_url}}
        elif args.action == "rename":
            if not args.repo or not args.new_repo_name:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing required arguments for repository rename")
            owner, repo_name = args.repo.split("/")
            repo = gh.get_user(owner).get_repo(repo_name)
            repo.edit(name=args.new_repo_name)
            return {"status": "success", "data": {"message": f"Repository renamed to {args.new_repo_name}"}}
        elif args.action == "delete":
            if not args.repo:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing required argument 'repo' for repository deletion")
            owner, repo_name = args.repo.split("/")
            repo = gh.get_user(owner).get_repo(repo_name)
            repo.delete()
            return {"status": "success", "data": {"message": "Repository deleted successfully"}}
        else:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid action for repo_admin")
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"GitHub API error: {e}")

async def handle_workflow_dispatch(gh: Github, args: WorkflowDispatchPayload):
    owner, repo_name = args.repo.split("/")
    repo = gh.get_user(owner).get_repo(repo_name)
    try:
        workflow = repo.get_workflow(args.workflow_id)
        workflow.create_dispatch(ref=args.ref if args.ref else repo.default_branch, inputs=args.inputs if args.inputs else {})
        return {"status": "success", "data": {"message": f"Workflow '{args.workflow_id}' dispatched successfully"}}
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"GitHub API error: {e}")

async def handle_get_repo_info(gh: Github, args: GetRepoInfoPayload):
    owner, repo_name = args.repo.split("/")
    repo = gh.get_user(owner).get_repo(repo_name)
    try:
        return {"status": "success", "data": {
            "name": repo.name,
            "full_name": repo.full_name,
            "description": repo.description,
            "html_url": repo.html_url,
            "private": repo.private,
            "fork": repo.fork,
            "stargazers_count": repo.stargazers_count,
            "watchers_count": repo.watchers_count,
            "forks_count": repo.forks_count,
            "open_issues_count": repo.open_issues_count,
            "default_branch": repo.default_branch,
            "created_at": repo.created_at.isoformat(),
            "updated_at": repo.updated_at.isoformat(),
            "pushed_at": repo.pushed_at.isoformat(),
        }}
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"GitHub API error: {e}")

async def handle_create_branch(gh: Github, args: CreateBranchPayload):
    owner, repo_name = args.repo.split("/")
    repo = gh.get_user(owner).get_repo(repo_name)
    try:
        source_branch_ref = repo.get_branch(args.source_branch if args.source_branch else repo.default_branch).commit.sha
        repo.create_git_ref(ref=f"refs/heads/{args.branch_name}", sha=source_branch_ref)
        return {"status": "success", "data": {"message": f"Branch '{args.branch_name}' created successfully"}}
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"GitHub API error: {e}")

async def handle_list_branches(gh: Github, args: ListBranchesPayload):
    owner, repo_name = args.repo.split("/")
    repo = gh.get_user(owner).get_repo(repo_name)
    try:
        branches = repo.get_branches()
        branch_list = [{"name": branch.name, "commit_sha": branch.commit.sha} for branch in branches]
        return {"status": "success", "data": {"branches": branch_list}}
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"GitHub API error: {e}")

async def handle_list_commits(gh: Github, args: ListCommitsPayload):
    owner, repo_name = args.repo.split("/")
    repo = gh.get_user(owner).get_repo(repo_name)
    try:
        commits = repo.get_commits(sha=args.sha if args.sha else repo.default_branch)
        commit_list = [{"sha": commit.sha, "message": commit.commit.message, "author": commit.commit.author.name, "date": commit.commit.author.date.isoformat()} for commit in commits]
        return {"status": "success", "data": {"commits": commit_list}}
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"GitHub API error: {e}")


# ─────────────────────  Entry point  ─────────────────────
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5555)