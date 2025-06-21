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
import requests
from typing import Optional, Dict, Any
from datetime import datetime
import logging
from fastapi.responses import JSONResponse

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

# Load private key for JWT signing
if API_KEY != "test":
    with open(PK_PATH, "rb") as f:
        PRIVATE_KEY = f.read().decode("utf-8")
else:
    PRIVATE_KEY = None

# Token cache with expiry
_token_cache = {
    "token": None,
    "expires_at": 0
}

def generate_jwt() -> str:
    """Generate a fresh JWT for GitHub App authentication"""
    if API_KEY == "test":
        return "dummy_jwt"
    
    if not PRIVATE_KEY:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Private key not available"
        )
    
    try:
        import jwt
        
        # JWT payload - expires in 10 minutes max, issued 60 seconds ago for clock drift
        now = int(time.time())
        payload = {
            'iat': now - 60,  # Issued 60 seconds ago to account for clock drift
            'exp': now + 600,  # Expires in 10 minutes (max allowed)
            'iss': CLIENT_ID   # GitHub App client ID
        }
        
        # Generate JWT using RS256 algorithm - use the private key string directly
        token = jwt.encode(payload, PRIVATE_KEY, algorithm='RS256')
        logger.info(f"Generated fresh JWT for GitHub App {CLIENT_ID}")
        return token
        
    except Exception as e:
        logger.error(f"Failed to generate JWT: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"JWT generation failed: {str(e)}"
        )

def get_install_token() -> str:
    """Get installation access token with proper caching and expiry checking"""
    if API_KEY == "test":
        return "dummy_token"
    
    now = time.time()
    
    # Check if cached token is still valid (with 5-minute buffer before expiry)
    if (_token_cache["token"] and 
        _token_cache["expires_at"] > now + 300):  # 5 min buffer
        logger.debug("Using cached installation token")
        return _token_cache["token"]
    
    # Generate fresh JWT and get new installation token
    try:
        jwt_token = generate_jwt()
        
        # Request installation access token using fresh JWT
        headers = {
            'Authorization': f'Bearer {jwt_token}',
            'Accept': 'application/vnd.github+json',
            'X-GitHub-Api-Version': '2022-11-28'
        }
        
        response = requests.post(
            f'https://api.github.com/app/installations/{INSTALL_ID}/access_tokens',
            headers=headers,
            timeout=30
        )
        response.raise_for_status()
        
        token_data = response.json()
        access_token = token_data['token']
        
        # Parse expiry time (GitHub returns ISO format)
        expires_at_str = token_data['expires_at']
        expires_at = datetime.fromisoformat(expires_at_str.replace('Z', '+00:00')).timestamp()
        
        # Cache the token
        _token_cache["token"] = access_token
        _token_cache["expires_at"] = expires_at
        
        logger.info(f"Generated fresh installation token, expires at {expires_at_str}")
        return access_token
        
    except Exception as e:
        logger.error(f"Failed to get installation token: {e}")
        # Clear cache on error
        _token_cache["token"] = None
        _token_cache["expires_at"] = 0
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"GitHub authentication failed: {str(e)}"
        )

# ─────────────────────  FastAPI initialisation  ─────────────────────
app = FastAPI(
    title="GitHub App Bridge",
    version="3.0.1",
    description="Secure bridge for GitHub repository operations",
    docs_url=None,
    redoc_url=None,
)

# ─────────────────────  Middleware  ─────────────────────
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["bmad.onemainarmy.com", "localhost", "127.0.0.1"],
)
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
    ip = request.client.host if request.client else "unknown"
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
    
    import time
    current_timestamp = str(int(time.time()))
    
    openapi_schema = {
        "openapi": "3.1.0",
        "info": {
            "title": "GitHub App Bridge",
            "version": f"3.0.1-{current_timestamp}",
            "description": "Secure bridge for GitHub repository operations via ChatGPT Actions",
        },
        "servers": [
            {
                "url": "https://bmad.onemainarmy.com",
                "description": "Production Server"
            }
        ],
        "security": [{"BearerAuth": []}],
        "paths": {
            "/list-repositories": {
                "post": {
                    "operationId": "listRepositories",
                    "summary": "List accessible repositories",
                    "description": "Get a list of repositories accessible to the authenticated GitHub App",
                    "security": [{"BearerAuth": []}],
                    "requestBody": {
                        "required": False,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "query": {"type": "string", "description": "Optional search query"},
                                        "filter": {"type": "string", "description": "Optional filter (all, private, public)"}
                                    }
                                }
                            }
                        }
                    },
                    "responses": {
                        "200": {
                            "description": "List of repositories",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "status": {"type": "string"},
                                            "data": {
                                                "type": "object",
                                                "properties": {
                                                    "repositories": {
                                                        "type": "array",
                                                        "items": {
                                                            "type": "object",
                                                            "properties": {
                                                                "name": {"type": "string"},
                                                                "full_name": {"type": "string"},
                                                                "description": {"type": "string"},
                                                                "private": {"type": "boolean"},
                                                                "url": {"type": "string"},
                                                                "clone_url": {"type": "string"},
                                                                "default_branch": {"type": "string"},
                                                                "language": {"type": "string"}
                                                            }
                                                        }
                                                    },
                                                    "count": {"type": "integer"}
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "/get-file": {
                "post": {
                    "operationId": "getFile",
                    "summary": "Get file contents from repository",
                    "description": "Retrieve the contents of a specific file from a repository",
                    "security": [{"BearerAuth": []}],
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["repo", "path"],
                                    "properties": {
                                        "repo": {"type": "string", "description": "Repository name (owner/repo)"},
                                        "path": {"type": "string", "description": "File path in repository"},
                                        "branch": {"type": "string", "description": "Optional branch name"}
                                    }
                                }
                            }
                        }
                    },
                    "responses": {
                        "200": {
                            "description": "File contents",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "status": {"type": "string"},
                                            "data": {
                                                "type": "object",
                                                "properties": {
                                                    "content": {"type": "string"},
                                                    "encoding": {"type": "string"},
                                                    "size": {"type": "integer"},
                                                    "sha": {"type": "string"}
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "/": {
                "post": {
                    "operationId": "bridgeCall",
                    "summary": "Execute GitHub repository operations",
                    "description": "Main endpoint for GitHub operations - supports all repository management functions including file operations, PR management, branch operations, and more",
                    "security": [{"BearerAuth": []}],
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["op"],
                                    "properties": {
                                        "op": {
                                            "type": "string",
                                            "enum": [
                                                "list_repos", "get_file", "put_file", "create_pr", "merge_pr", 
                                                "comment_pr", "list_prs", "repo_admin", "workflow_dispatch", 
                                                "get_repo_info", "create_branch", "list_branches", "list_commits",
                                                "list_operations", "ping"
                                            ],
                                            "description": "Operation to perform"
                                        },
                                        "args": {
                                            "type": "object",
                                            "description": "Operation arguments - structure varies by operation type",
                                            "properties": {
                                                "repo": {
                                                    "type": "string",
                                                    "description": "Repository name (owner/repo) - required for most operations"
                                                },
                                                "path": {
                                                    "type": "string", 
                                                    "description": "File path in repository - required for file operations"
                                                },
                                                "content": {
                                                    "type": "string",
                                                    "description": "File content - required for put_file operation"
                                                },
                                                "message": {
                                                    "type": "string",
                                                    "description": "Commit message - required for put_file operation"
                                                },
                                                "title": {
                                                    "type": "string",
                                                    "description": "Pull request title - required for create_pr operation"
                                                },
                                                "head": {
                                                    "type": "string",
                                                    "description": "Source branch - required for create_pr operation"
                                                },
                                                "base": {
                                                    "type": "string",
                                                    "description": "Target branch - required for create_pr operation"
                                                },
                                                "pr_number": {
                                                    "type": "integer",
                                                    "description": "Pull request number - required for PR operations"
                                                },
                                                "branch_name": {
                                                    "type": "string",
                                                    "description": "Branch name - required for create_branch operation"
                                                },
                                                "comment_body": {
                                                    "type": "string",
                                                    "description": "Comment text - required for comment_pr operation"
                                                },
                                                "action": {
                                                    "type": "string",
                                                    "enum": ["create", "rename", "delete"],
                                                    "description": "Repository action - required for repo_admin operation"
                                                },
                                                "workflow_id": {
                                                    "type": "string",
                                                    "description": "Workflow ID - required for workflow_dispatch operation"
                                                },
                                                "branch": {
                                                    "type": "string",
                                                    "description": "Optional: Branch name for various operations"
                                                },
                                                "sha": {
                                                    "type": "string",
                                                    "description": "Optional: SHA for file updates or commit references"
                                                },
                                                "ref": {
                                                    "type": "string",
                                                    "description": "Optional: Git reference (branch/tag/commit)"
                                                },
                                                "body": {
                                                    "type": "string",
                                                    "description": "Optional: Pull request description"
                                                },
                                                "draft": {
                                                    "type": "boolean",
                                                    "description": "Optional: Create as draft PR"
                                                },
                                                "state": {
                                                    "type": "string",
                                                    "enum": ["open", "closed", "all"],
                                                    "description": "Optional: Filter PRs by state"
                                                },
                                                "sort": {
                                                    "type": "string",
                                                    "enum": ["created", "updated", "popularity", "long-running"],
                                                    "description": "Optional: Sort order for listings"
                                                },
                                                "direction": {
                                                    "type": "string",
                                                    "enum": ["asc", "desc"],
                                                    "description": "Optional: Sort direction"
                                                },
                                                "merge_method": {
                                                    "type": "string",
                                                    "enum": ["merge", "squash", "rebase"],
                                                    "description": "Optional: PR merge method"
                                                },
                                                "commit_title": {
                                                    "type": "string",
                                                    "description": "Optional: Merge commit title"
                                                },
                                                "commit_message": {
                                                    "type": "string",
                                                    "description": "Optional: Merge commit message"
                                                },
                                                "source_branch": {
                                                    "type": "string",
                                                    "description": "Optional: Source branch for branch creation"
                                                },
                                                "new_repo_name": {
                                                    "type": "string",
                                                    "description": "Optional: New repository name for rename operation"
                                                },
                                                "description": {
                                                    "type": "string",
                                                    "description": "Optional: Repository description"
                                                },
                                                "private": {
                                                    "type": "boolean",
                                                    "description": "Optional: Whether repository should be private"
                                                },
                                                "auto_init": {
                                                    "type": "boolean",
                                                    "description": "Optional: Initialize repository with README"
                                                },
                                                "inputs": {
                                                    "type": "object",
                                                    "description": "Optional: Workflow inputs for workflow_dispatch"
                                                },
                                                "type": {
                                                    "type": "string",
                                                    "description": "Optional: Repository type filter for list_repos"
                                                },
                                                "query": {
                                                    "type": "string",
                                                    "description": "Optional: Search query for list_repos"
                                                }
                                            },
                                                                                         "additionalProperties": False
                                         }
                                     },
                                     "additionalProperties": False
                                }
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
                "ListReposPayload": {
                    "type": "object",
                    "required": ["op"],
                    "properties": {
                        "op": {"type": "string", "enum": ["list_repos"], "description": "List repositories operation"},
                        "args": {
                            "type": "object",
                            "properties": {
                                "type": {"type": "string", "description": "Optional: Repository type filter (all, owner, member, public, private)"},
                                "query": {"type": "string", "description": "Optional: Search query"}
                            },
                            "additionalProperties": False
                        }
                    }
                },
                "GetFilePayload": {
                    "type": "object",
                    "required": ["op"],
                    "properties": {
                        "op": {"type": "string", "enum": ["get_file"], "description": "Get file contents operation"},
                        "args": {
                            "type": "object",
                            "required": ["repo", "path"],
                            "properties": {
                                "repo": {"type": "string", "description": "Repository name (owner/repo)"},
                                "path": {"type": "string", "description": "File path in repository"},
                                "ref": {"type": "string", "description": "Optional: Branch/commit reference"}
                            },
                            "additionalProperties": False
                        }
                    }
                },
                "PutFilePayload": {
                    "type": "object",
                    "required": ["op"],
                    "properties": {
                        "op": {"type": "string", "enum": ["put_file"], "description": "Create or update file operation"},
                        "args": {
                            "type": "object",
                            "required": ["repo", "path", "content", "message"],
                            "properties": {
                                "repo": {"type": "string", "description": "Repository name (owner/repo)"},
                                "path": {"type": "string", "description": "File path in repository"},
                                "content": {"type": "string", "description": "Content to write to file"},
                                "message": {"type": "string", "description": "Commit message"},
                                "branch": {"type": "string", "description": "Optional: Branch name"},
                                "sha": {"type": "string", "description": "Optional: SHA of the file to update"}
                            },
                            "additionalProperties": False
                        }
                    }
                },
                "CreatePRPayload": {
                    "type": "object",
                    "required": ["op"],
                    "properties": {
                        "op": {"type": "string", "enum": ["create_pr"], "description": "Create pull request operation"},
                        "args": {
                            "type": "object",
                            "required": ["repo", "title", "head", "base"],
                            "properties": {
                                "repo": {"type": "string", "description": "Repository name (owner/repo)"},
                                "title": {"type": "string", "description": "Pull request title"},
                                "head": {"type": "string", "description": "Branch where changes are implemented"},
                                "base": {"type": "string", "description": "Branch to merge changes into"},
                                "body": {"type": "string", "description": "Optional: Pull request body"},
                                "draft": {"type": "boolean", "description": "Optional: Create as draft PR"}
                            },
                            "additionalProperties": False
                        }
                    }
                },
                "MergePRPayload": {
                    "type": "object",
                    "required": ["op"],
                    "properties": {
                        "op": {"type": "string", "enum": ["merge_pr"], "description": "Merge pull request operation"},
                        "args": {
                            "type": "object",
                            "required": ["repo", "pr_number"],
                            "properties": {
                                "repo": {"type": "string", "description": "Repository name (owner/repo)"},
                                "pr_number": {"type": "integer", "description": "Pull request number"},
                                "commit_title": {"type": "string", "description": "Optional: Title for merge commit"},
                                "commit_message": {"type": "string", "description": "Optional: Extra detail for merge commit"},
                                "merge_method": {"type": "string", "enum": ["merge", "squash", "rebase"], "description": "Optional: Merge method"}
                            },
                            "additionalProperties": False
                        }
                    }
                },
                "CommentPRPayload": {
                    "type": "object",
                    "required": ["op"],
                    "properties": {
                        "op": {"type": "string", "enum": ["comment_pr"], "description": "Add comment to pull request operation"},
                        "args": {
                            "type": "object",
                            "required": ["repo", "pr_number", "comment_body"],
                            "properties": {
                                "repo": {"type": "string", "description": "Repository name (owner/repo)"},
                                "pr_number": {"type": "integer", "description": "Pull request number"},
                                "comment_body": {"type": "string", "description": "Comment to add to the pull request"}
                            },
                            "additionalProperties": False
                        }
                    }
                },
                "ListPRsPayload": {
                    "type": "object",
                    "required": ["op"],
                    "properties": {
                        "op": {"type": "string", "enum": ["list_prs"], "description": "List pull requests operation"},
                        "args": {
                            "type": "object",
                            "required": ["repo"],
                            "properties": {
                                "repo": {"type": "string", "description": "Repository name (owner/repo)"},
                                "state": {"type": "string", "enum": ["open", "closed", "all"], "description": "Optional: Filter by state"},
                                "head": {"type": "string", "description": "Optional: Filter by head user/org and branch"},
                                "base": {"type": "string", "description": "Optional: Filter by base branch"},
                                "sort": {"type": "string", "enum": ["created", "updated", "popularity", "long-running"], "description": "Optional: Sort by"},
                                "direction": {"type": "string", "enum": ["asc", "desc"], "description": "Optional: Sort direction"}
                            },
                            "additionalProperties": False
                        }
                    }
                },
                "RepoAdminPayload": {
                    "type": "object",
                    "required": ["op"],
                    "properties": {
                        "op": {"type": "string", "enum": ["repo_admin"], "description": "Repository administration operation"},
                        "args": {
                            "type": "object",
                            "required": ["action"],
                            "properties": {
                                "action": {"type": "string", "enum": ["create", "rename", "delete"], "description": "Action to perform"},
                                "repo": {"type": "string", "description": "Repository name (owner/repo) - required for rename, delete"},
                                "new_repo_name": {"type": "string", "description": "New repository name (required for rename)"},
                                "description": {"type": "string", "description": "Optional: Repository description (required for create)"},
                                "private": {"type": "boolean", "description": "Optional: Whether repo should be private (required for create)"},
                                "auto_init": {"type": "boolean", "description": "Optional: Initialize with README (required for create)"}
                            },
                            "additionalProperties": False
                        }
                    }
                },
                "WorkflowDispatchPayload": {
                    "type": "object",
                    "required": ["op"],
                    "properties": {
                        "op": {"type": "string", "enum": ["workflow_dispatch"], "description": "Trigger GitHub Actions workflow operation"},
                        "args": {
                            "type": "object",
                            "required": ["repo", "workflow_id"],
                            "properties": {
                                "repo": {"type": "string", "description": "Repository name (owner/repo)"},
                                "workflow_id": {"type": "string", "description": "Workflow file name or ID"},
                                "ref": {"type": "string", "description": "Optional: The ref (branch or tag) to trigger the workflow on"},
                                "inputs": {"type": "object", "description": "Optional: Inputs to pass to the workflow"}
                            },
                            "additionalProperties": False
                        }
                    }
                },
                "GetRepoInfoPayload": {
                    "type": "object",
                    "required": ["op"],
                    "properties": {
                        "op": {"type": "string", "enum": ["get_repo_info"], "description": "Get repository information operation"},
                        "args": {
                            "type": "object",
                            "required": ["repo"],
                            "properties": {
                                "repo": {"type": "string", "description": "Repository name (owner/repo)"}
                            },
                            "additionalProperties": False
                        }
                    }
                },
                "CreateBranchPayload": {
                    "type": "object",
                    "required": ["op"],
                    "properties": {
                        "op": {"type": "string", "enum": ["create_branch"], "description": "Create new branch operation"},
                        "args": {
                            "type": "object",
                            "required": ["repo", "branch_name"],
                            "properties": {
                                "repo": {"type": "string", "description": "Repository name (owner/repo)"},
                                "branch_name": {"type": "string", "description": "Name for the new branch"},
                                "source_branch": {"type": "string", "description": "Optional: Source branch to create from"}
                            },
                            "additionalProperties": False
                        }
                    }
                },
                "ListBranchesPayload": {
                    "type": "object",
                    "required": ["op"],
                    "properties": {
                        "op": {"type": "string", "enum": ["list_branches"], "description": "List branches operation"},
                        "args": {
                            "type": "object",
                            "required": ["repo"],
                            "properties": {
                                "repo": {"type": "string", "description": "Repository name (owner/repo)"}
                            },
                            "additionalProperties": False
                        }
                    }
                },
                "ListCommitsPayload": {
                    "type": "object",
                    "required": ["op"],
                    "properties": {
                        "op": {"type": "string", "enum": ["list_commits"], "description": "List commits operation"},
                        "args": {
                            "type": "object",
                            "required": ["repo"],
                            "properties": {
                                "repo": {"type": "string", "description": "Repository name (owner/repo)"},
                                "sha": {"type": "string", "description": "Optional: SHA or branch name to list commits from"}
                            },
                            "additionalProperties": False
                        }
                    }
                },
                "ListOperationsPayload": {
                    "type": "object",
                    "required": ["op"],
                    "properties": {
                        "op": {"type": "string", "enum": ["list_operations"], "description": "List available operations"},
                        "args": {
                            "type": "object",
                            "additionalProperties": False
                        }
                    }
                },
                "PingPayload": {
                    "type": "object",
                    "required": ["op"],
                    "properties": {
                        "op": {"type": "string", "enum": ["ping"], "description": "Ping the service"},
                        "args": {
                            "type": "object",
                            "additionalProperties": False
                        }
                    }
                }
            }
        }
    }
    
    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi_schema

@app.get("/openapi.json", include_in_schema=False)
async def custom_openapi(v: Optional[str] = None):
    # Clear the cached schema to ensure updates are reflected
    app.openapi_schema = None
    schema = custom_openapi_schema()
    
    # Add timestamp to force cache invalidation
    timestamp = str(int(time.time()))
    
    # Return response with aggressive cache-busting headers
    # Note: Cloudflare may override some headers, but the schema version changes
    return JSONResponse(
        content=schema,
        headers={
            "Access-Control-Allow-Origin": "https://chat.openai.com",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization",
            "Cache-Control": "no-cache, no-store, must-revalidate, max-age=0",
            "Pragma": "no-cache",
            "Expires": "Thu, 01 Jan 1970 00:00:00 GMT",
            "ETag": f'"{timestamp}"',
            "Last-Modified": f"{timestamp}",
            "X-Cache-Bust": timestamp,
            "Vary": "Accept-Encoding, Authorization",
            "X-Schema-Version": timestamp
        }
    )

@app.options("/openapi.json", include_in_schema=False)
async def openapi_options():
    # Handle CORS preflight for OpenAPI endpoint
    return JSONResponse(
        content={},
        headers={
            "Access-Control-Allow-Origin": "https://chat.openai.com",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization",
        }
    )

@app.get("/openai.json", include_in_schema=False)
async def openai_json_alias(v: Optional[str] = None):
    # Alias for common typo: openai.json instead of openapi.json
    app.openapi_schema = None
    schema = custom_openapi_schema()
    
    # Add timestamp to force cache invalidation
    timestamp = str(int(time.time()))
    
    return JSONResponse(
        content=schema,
        headers={
            "Access-Control-Allow-Origin": "https://chat.openai.com",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization",
            "Cache-Control": "no-cache, no-store, must-revalidate, max-age=0",
            "Pragma": "no-cache",
            "Expires": "Thu, 01 Jan 1970 00:00:00 GMT",
            "ETag": f'"{timestamp}"',
            "Last-Modified": f"{timestamp}",
            "X-Cache-Bust": timestamp,
            "Vary": "Accept-Encoding, Authorization",
            "X-Schema-Version": timestamp
        }
    )


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
    repo: Optional[str] = Field(None, description="Repository name (owner/repo) - required for rename, delete")
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


# ─────────────────────  NEW: Direct endpoints for better ChatGPT integration  ─────────────────────

@app.post("/list-repositories")
async def list_repositories_direct(
    request: Request,
    payload: Optional[dict] = None,
    _api_key_ok: str = Depends(verify_api_key),
):
    """Direct endpoint for listing repositories - better for ChatGPT Actions"""
    try:
        rate_limit_check(request)
        
        # Get access token
        access_token = get_install_token()
        gh = Github(access_token)
        
        # Use empty args if no payload provided
        args = payload or {}
        
        # Call the existing handler
        result = await handle_list_repos(gh, args)
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in list_repositories_direct: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Operation failed: {str(e)}"
        )


@app.post("/get-file")
async def get_file_direct(
    request: Request,
    payload: dict,
    _api_key_ok: str = Depends(verify_api_key),
):
    """Direct endpoint for getting file contents - better for ChatGPT Actions"""
    try:
        rate_limit_check(request)
        
        # Validate required fields
        if not payload.get("repo") or not payload.get("path"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Both 'repo' and 'path' are required"
            )
        
        # Get access token
        access_token = get_install_token()
        gh = Github(access_token)
        
        # Call the existing handler
        result = await handle_get_file(gh, payload)
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in get_file_direct: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Operation failed: {str(e)}"
        )


# ─────────────────────  Main bridge endpoint  ─────────────────────
@app.post("/")
async def bridge_call(
    payload: Payload,
    request: Request,
    _api_key_ok: str = Depends(verify_api_key),
):
    rate_limit_check(request)
    logger.info("Op %s Args %s", payload.op, json.dumps(payload.args))

    # Create GitHub client using the installation token
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
    contents = repo.get_contents(args["path"], ref=args.get("ref", "HEAD"))
    # get_contents can return a list for directories, but we expect a single file
    if isinstance(contents, list):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Path is a directory, not a file")
    return {
        "content": contents.decoded_content.decode(),
        "sha": contents.sha,
        "size": contents.size,
        "encoding": contents.encoding,
    }


async def handle_list_repos(gh: Github, args: dict):
    repo_type = args.get("type", "all")
    query = args.get("query", "")
    
    try:
        # For GitHub Apps, we need to get repositories accessible to this specific installation
        # We cannot use get_user() because that requires different permissions
        
        logger.info(f"Attempting to list repositories for installation {INSTALL_ID}")
        
        # Get repositories accessible to this GitHub App installation
        try:
            # Use the direct GitHub API to get installation repositories
            # This is the correct way for GitHub Apps
            token = get_install_token()
            gh_installation = Github(token)
            
            # Get installation repositories using the proper endpoint
            headers = {
                'Authorization': f'token {token}',
                'Accept': 'application/vnd.github.v3+json'
            }
            
            # Use the installation repositories endpoint
            response = requests.get(
                f'https://api.github.com/installation/repositories',
                headers=headers
            )
            
            if response.status_code == 200:
                data = response.json()
                repos_data = data.get('repositories', [])
                logger.info(f"Successfully retrieved {len(repos_data)} repositories from installation")
                
                # Convert to list with essential information
                repo_list = []
                for repo_data in repos_data:
                    try:
                        # If query is provided, filter repositories locally by name
                        if query and (
                            query.lower() not in repo_data['name'].lower() and 
                            query.lower() not in repo_data['full_name'].lower()
                        ):
                            continue
                            
                        repo_list.append({
                            "name": repo_data['name'],
                            "full_name": repo_data['full_name'],
                            "description": repo_data.get('description'),
                            "private": repo_data['private'],
                            "url": repo_data['html_url'],
                            "clone_url": repo_data['clone_url'],
                            "default_branch": repo_data['default_branch'],
                            "created_at": repo_data['created_at'],
                            "updated_at": repo_data['updated_at'],
                            "language": repo_data.get('language'),
                            "size": repo_data['size'],
                            "stargazers_count": repo_data['stargazers_count'],
                            "forks_count": repo_data['forks_count']
                        })
                    except Exception as e:
                        logger.warning(f"Error processing repo {repo_data.get('full_name', 'unknown')}: {e}")
                        continue
                
                return {
                    "status": "success",
                    "data": {
                        "repositories": repo_list,
                        "count": len(repo_list),
                        "total_accessible": len(repos_data),
                        "filter": repo_type,
                        "query": query,
                        "access_method": "github_app_installation",
                        "note": "GitHub App shows repositories where it has been installed. Query parameter filters within your accessible repositories only."
                    }
                }
            else:
                logger.error(f"GitHub API error: {response.status_code} - {response.text}")
                raise Exception(f"GitHub API returned {response.status_code}: {response.text}")
                
        except Exception as e:
            logger.error(f"Error accessing installation repositories: {e}")
            return {
                "status": "error", 
                "data": {
                    "repositories": [],
                    "count": 0,
                    "error": f"Unable to access repositories: {str(e)}",
                    "note": "GitHub App repository access requires proper installation and permissions. Please ensure the GitHub App is installed on your repositories.",
                    "installation_id": INSTALL_ID,
                    "troubleshooting": "Visit https://github.com/settings/installations to check GitHub App installations"
                }
            }
        
    except Exception as e:
        logger.error(f"Error in list_repos: {e}")
        return {
            "status": "error", 
            "data": {
                "repositories": [],
                "count": 0,
                "error": str(e),
                "note": "GitHub App repository access failed. Please check GitHub App installation and permissions."
            }
        }


async def handle_put_file(gh: Github, args: PutFilePayload):
    repo = gh.get_repo(args.repo)
    try:
        contents = repo.get_contents(args.path, ref=args.branch if args.branch else repo.default_branch)
        # get_contents can return a list for directories, but we expect a single file
        if isinstance(contents, list):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Path is a directory, not a file")
        repo.update_file(contents.path, args.message, args.content, contents.sha, branch=args.branch if args.branch else repo.default_branch)
        return {"status": "success", "data": {"message": "File updated successfully"}}
    except Exception as e:
        # If file does not exist, create it
        if "not found" in str(e).lower():
            repo.create_file(args.path, args.message, args.content, branch=args.branch if args.branch else repo.default_branch)
            return {"status": "success", "data": {"message": "File created successfully"}}
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"GitHub API error: {e}")

async def handle_create_pr(gh: Github, args: CreatePRPayload):
    repo = gh.get_repo(args.repo)
    try:
        pull_request = repo.create_pull(
            title=args.title,
            body=args.body or "",
            head=args.head,
            base=args.base,
            draft=args.draft if args.draft is not None else False
        )
        return {"status": "success", "data": {"pr_number": pull_request.number, "url": pull_request.html_url}}
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"GitHub API error: {e}")

async def handle_merge_pr(gh: Github, args: MergePRPayload):
    repo = gh.get_repo(args.repo)
    try:
        pull = repo.get_pull(args.pr_number)
        # Handle optional parameters properly
        merge_kwargs = {}
        if args.commit_title:
            merge_kwargs["commit_title"] = args.commit_title
        if args.commit_message:
            merge_kwargs["commit_message"] = args.commit_message
        if args.merge_method:
            merge_kwargs["merge_method"] = args.merge_method
            
        merge_result = pull.merge(**merge_kwargs)
        return {"status": "success", "data": {"merged": merge_result.merged, "message": merge_result.message}}
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"GitHub API error: {e}")

async def handle_comment_pr(gh: Github, args: CommentPRPayload):
    repo = gh.get_repo(args.repo)
    try:
        pull = repo.get_pull(args.pr_number)
        comment = pull.create_issue_comment(args.comment_body)
        return {"status": "success", "data": {"comment_url": comment.html_url}}
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"GitHub API error: {e}")

async def handle_list_prs(gh: Github, args: ListPRsPayload):
    repo = gh.get_repo(args.repo)
    try:
        # Handle optional parameters properly
        pulls_kwargs = {
            "state": args.state if args.state else "open",
            "sort": args.sort if args.sort else "created",
            "direction": args.direction if args.direction else "desc"
        }
        if args.head:
            pulls_kwargs["head"] = args.head
        if args.base:
            pulls_kwargs["base"] = args.base
            
        pulls = repo.get_pulls(**pulls_kwargs)
        pr_list = [{"number": pr.number, "title": pr.title, "url": pr.html_url, "state": pr.state} for pr in pulls]
        return {"status": "success", "data": {"pull_requests": pr_list}}
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"GitHub API error: {e}")

async def handle_repo_admin(gh: Github, args: RepoAdminPayload):
    try:
        if args.action == "create":
            if not args.new_repo_name or args.description is None or args.private is None or args.auto_init is None:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing required arguments for repository creation")
            # For GitHub Apps, repository creation is more complex and may require organization context
            # For now, we'll return an error indicating this operation needs additional implementation
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED, 
                detail="Repository creation through GitHub App is not yet implemented. Use GitHub's web interface or a personal access token."
            )
        elif args.action == "rename":
            if not args.repo or not args.new_repo_name:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing required arguments for repository rename")
            repo = gh.get_repo(args.repo)
            repo.edit(name=args.new_repo_name)
            return {"status": "success", "data": {"message": f"Repository renamed to {args.new_repo_name}"}}
        elif args.action == "delete":
            if not args.repo:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing required argument 'repo' for repository deletion")
            repo = gh.get_repo(args.repo)
            repo.delete()
            return {"status": "success", "data": {"message": "Repository deleted successfully"}}
        else:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid action for repo_admin")
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"GitHub API error: {e}")

async def handle_workflow_dispatch(gh: Github, args: WorkflowDispatchPayload):
    repo = gh.get_repo(args.repo)
    try:
        workflow = repo.get_workflow(args.workflow_id)
        workflow.create_dispatch(ref=args.ref if args.ref else repo.default_branch, inputs=args.inputs if args.inputs else {})
        return {"status": "success", "data": {"message": f"Workflow '{args.workflow_id}' dispatched successfully"}}
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"GitHub API error: {e}")

async def handle_get_repo_info(gh: Github, args: GetRepoInfoPayload):
    repo = gh.get_repo(args.repo)
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
    repo = gh.get_repo(args.repo)
    try:
        source_branch_ref = repo.get_branch(args.source_branch if args.source_branch else repo.default_branch).commit.sha
        repo.create_git_ref(ref=f"refs/heads/{args.branch_name}", sha=source_branch_ref)
        return {"status": "success", "data": {"message": f"Branch '{args.branch_name}' created successfully"}}
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"GitHub API error: {e}")

async def handle_list_branches(gh: Github, args: ListBranchesPayload):
    repo = gh.get_repo(args.repo)
    try:
        branches = repo.get_branches()
        branch_list = [{"name": branch.name, "commit_sha": branch.commit.sha} for branch in branches]
        return {"status": "success", "data": {"branches": branch_list}}
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"GitHub API error: {e}")

async def handle_list_commits(gh: Github, args: ListCommitsPayload):
    repo = gh.get_repo(args.repo)
    try:
        commits = repo.get_commits(sha=args.sha if args.sha else repo.default_branch)
        commit_list = [{"sha": commit.sha, "message": commit.commit.message, "author": commit.commit.author.name, "date": commit.commit.author.date.isoformat()} for commit in commits]
        return {"status": "success", "data": {"commits": commit_list}}
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"GitHub API error: {e}")


# ─────────────────────  Entry point  ─────────────────────
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5555)