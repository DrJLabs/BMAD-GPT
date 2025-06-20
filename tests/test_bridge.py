import pytest, json
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

# --- GitHub stub ---------------------------------
class _Blob:
    def __init__(self):
        self.decoded_content = b"Hello"
        self.sha = "deadbeef"
        self.size = 5
        self.encoding = "utf-8"

class DummyRepo:
    def get_contents(self, *a, **k):
        return _Blob()

class DummyGH:
    def get_repo(self, *_):
        return DummyRepo()

@pytest.fixture(autouse=True)
def monkey_github(monkeypatch):
    from main import Github
    monkeypatch.setattr("main.Github", lambda *_a, **_k: DummyGH())
    yield
# --------------------------------------------------

def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "healthy"

def test_get_file():
    hdrs = {"Authorization": "Bearer test"}
    body = {"op":"get_file","args":{"repo":"x/y","path":"README.md"}}
    r = client.post("/", headers=hdrs, json=body)
    assert r.status_code == 200
    assert r.json()["content"] == "Hello"
