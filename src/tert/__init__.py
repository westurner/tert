"""Test Execution Report Tracker (tert) - Python package."""

__version__ = "0.1.0"
__author__ = "westurner"

from .shellwrap import Shellwrap
from .fetch import (
    CryptoConfig,
    FetchResult,
    FetchError,
    CurlStrategy,
    WgetStrategy,
    RustStrategy,
    get_strategy,
    fetch,
    verify_crypto_config,
    discover_ca_bundle,
)
from .run_tests import (
    ReplogDB,
    TertTestRun,
    TertTestRunner,
    PytestRunner,
    CargoRunner,
    GoRunner,
    JestRunner,
    VitestRunner,
    ToxRunner,
    get_runner,
    run_tests,
    query_runs,
    query_artifacts,
    query_coverage_lines,
)

__all__ = [
    "Shellwrap",
    "CryptoConfig",
    "FetchResult",
    "FetchError",
    "CurlStrategy",
    "WgetStrategy",
    "RustStrategy",
    "get_strategy",
    "fetch",
    "verify_crypto_config",
    "discover_ca_bundle",
    "ReplogDB",
    "TertTestRun",
    "TertTestRunner",
    "PytestRunner",
    "CargoRunner",
    "GoRunner",
    "JestRunner",
    "VitestRunner",
    "ToxRunner",
    "get_runner",
    "run_tests",
    "query_runs",
    "query_artifacts",
    "query_coverage_lines",
]
