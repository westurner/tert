"""Pytest configuration for tert test suite."""

import os
import pytest


# RECURSION PROTECTION: Set env var to signal tests are running
@pytest.fixture(scope="session", autouse=True)
def set_pytest_running():
    """Signal that pytest is running to prevent subprocess recursion."""
    os.environ["PYTEST_RUNNING"] = "1"
    yield
    # Clean up
    os.environ.pop("PYTEST_RUNNING", None)


def pytest_configure(config):
    """Register custom markers."""
    config.addinivalue_line(
        "markers",
        "requires_mock: marks tests as requiring subprocess mocking (deselect with '-m \"not requires_mock\"')",
    )


@pytest.fixture(scope="session")
def mock_subprocess_globally():
    """
    Global subprocess mock that applies to all tests.

    RECURSION PROTECTION:
    - Tests that call main() or actual subprocess operations must be marked with @pytest.mark.requires_mock
    - These tests must use mocking to prevent recursive pytest invocations
    - The conftest.py session fixture sets PYTEST_RUNNING env var
    - run_tests.py checks this env var and refuses to run pytest
    """
    from unittest import mock

    with mock.patch("subprocess.run") as mock_run:
        mock_run.return_value = mock.Mock(returncode=0)
        yield mock_run
