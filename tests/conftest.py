import pytest

_test_results = []

@pytest.fixture(scope="function", autouse=True)
def collect_test_results(request):
    yield
    # After the test function has run
    result = {
        "name": request.node.name,
        "status": "FAIL",
        "details": "",
        "request_payload": {},
        "response_data": {}
    }
    if hasattr(request.node, "result_info"): # Custom attribute set by our tests
        result.update(request.node.result_info)
    _test_results.append(result)

def pytest_sessionfinish(session):
    print("\n\n--- GitHub API Integration Test Summary ---")
    if not _test_results:
        print("No tests were run.")
        return

    headers = ["Function", "Status", "Details", "Suggested Causes"]
    data = []
    for res in _test_results:
        status = res.get("status", "UNKNOWN")
        details = res.get("details", "")
        suggested_causes = res.get("suggested_causes", "")
        
        # For make_request, we use "function" for the op name, for other tests, it's the test name itself
        function_name = res.get("function") if "function" in res else res["name"] 
        
        data.append([function_name, status, details, suggested_causes])

    # Basic table formatting
    col_widths = [max(len(str(item)) for item in col) for col in zip(*data)]
    print(" | ".join(header.ljust(width) for header, width in zip(headers, col_widths)))
    print("-+-".join("-" * width for width in col_widths))
    for row in data:
        print(" | ".join(str(item).ljust(width) for item, width in zip(row, col_widths)))
    print("-------------------------------------------\n")

    pass_count = sum(1 for res in _test_results if res.get("status") == "PASS")
    fail_count = len(_test_results) - pass_count
    print(f"Total Tests: {len(_test_results)}, Passed: {pass_count}, Failed: {fail_count}") 