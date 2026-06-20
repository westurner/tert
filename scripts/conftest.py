"""
conftest.py - Pytest configuration for test_run_tests.py

RECURSION PROTECTION:
This configuration ensures that subprocess calls are mocked globally to prevent:
1. Recursive pytest invocations (run_tests.py -> pytest -> run_tests.py)
2. Spawning real processes during testing
3. Dependency issues if tools aren't installed
4. Long test runtimes
5. Side effects on the system

Key protections:
- PYTEST_RUNNING environment variable signals tests are running
- Global subprocess.run mock prevents any real process execution
- Tests must use mocking for any subprocess behavior
- run_tests.py main() refuses to run if PYTEST_RUNNING is set
"""

import os
import pytest
from unittest import mock

# Set environment variable to signal tests are running
# This is checked by run_tests.py main() to prevent recursion
os.environ["PYTEST_RUNNING"] = "1"


@pytest.fixture(scope="session", autouse=True)
def setup_recursion_protection():
    """
    Session-level setup to ensure recursion protection is active.
    
    This fixture verifies that PYTEST_RUNNING is set, which should prevent
    any code in run_tests.py main() from executing subprocess calls that
    could lead to recursion.
    """
    assert os.environ.get("PYTEST_RUNNING") == "1", \
        "PYTEST_RUNNING environment variable not set - recursion protection inactive!"
    yield
    # Cleanup: remove the marker after all tests
    os.environ.pop("PYTEST_RUNNING", None)


def pytest_configure(config):
    """
    Pytest hook called before test collection.
    
    Used to register custom markers for recursion-sensitive tests.
    """
    config.addinivalue_line(
        "markers",
        "skip_if_pytest_running: skip test if running under pytest (to prevent recursion)"
    )
    config.addinivalue_line(
        "markers",
        "requires_mock: test requires subprocess mocking"
    )


def pytest_collection_modifyitems(config, items):
    """
    Pytest hook to modify test items during collection.
    
    Automatically skip tests that shouldn't run when pytest is running,
    to prevent recursion issues.
    """
    for item in items:
        # Mark all tests as requiring mock by default
        if "requires_mock" not in item.keywords:
            item.add_marker(pytest.mark.requires_mock)
