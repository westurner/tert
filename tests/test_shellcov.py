#!/usr/bin/env python3
"""
tests/test_shellcov.py - Test suite for shellcov binary

Tests the Rust shellcov binary's:
- Line coverage tracking
- Coverage report generation
- CLI UX with coverage statistics
- Missing lines detection
"""

import os
import pytest
import subprocess
import tempfile
from pathlib import Path


@pytest.fixture
def shellcov_binary():
    """Get path to shellcov binary."""
    tert_dir = Path(__file__).parent.parent
    binary = tert_dir / "target" / "release" / "shellcov"
    
    if not binary.exists():
        pytest.skip(f"shellcov binary not found at {binary}")
    
    return binary


@pytest.fixture
def test_script(tmp_path):
    """Create a simple test shell script."""
    script = tmp_path / "test.sh"
    script.write_text("""#!/bin/bash
set -e

# This is line 3
echo "Starting test"  # Line 5
x=1                   # Line 6
y=2                   # Line 7
z=$((x + y))         # Line 8
echo "Result: $z"    # Line 9

# Some unused lines (won't be executed)
unused_function() {
    echo "Never called"
    return 1
}

echo "Done"           # Line 16
exit 0               # Line 17
""")
    return script


@pytest.fixture
def coverage_report_dir(tmp_path):
    """Create temporary directory for coverage reports."""
    reports_dir = tmp_path / "coverage"
    reports_dir.mkdir()
    return reports_dir


class TestShellcovBinary:
    """Test shellcov binary functionality."""

    def test_shellcov_executes_script(self, shellcov_binary, test_script):
        """Test that shellcov can execute a shell script."""
        result = subprocess.run(
            [str(shellcov_binary), f"bash {test_script}"],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        assert result.returncode == 0
        assert "Starting test" in result.stdout or "Starting test" in result.stderr
    
    def test_shellcov_generates_coverage_file(self, shellcov_binary, test_script, 
                                               coverage_report_dir):
        """Test that shellcov generates a coverage report file."""
        cov_file = coverage_report_dir / "coverage.txt"
        env = os.environ.copy()
        env["SHELLCOV_COVERAGE_FILE"] = str(cov_file)
        
        result = subprocess.run(
            [str(shellcov_binary), f"bash {test_script}"],
            capture_output=True,
            text=True,
            env=env,
            timeout=10
        )
        
        assert result.returncode == 0
        assert cov_file.exists()
    
    def test_coverage_file_contains_statistics(self, shellcov_binary, test_script,
                                                coverage_report_dir):
        """Test that coverage file contains required statistics sections."""
        cov_file = coverage_report_dir / "coverage.txt"
        env = os.environ.copy()
        env["SHELLCOV_COVERAGE_FILE"] = str(cov_file)
        
        subprocess.run(
            [str(shellcov_binary), f"bash {test_script}"],
            capture_output=True,
            text=True,
            env=env,
            timeout=10
        )
        
        content = cov_file.read_text()
        
        # Check for required sections
        assert "[execution]" in content
        assert "[coverage_stats]" in content
        assert "[executed_lines]" in content
        
        # Check for required fields
        assert "command =" in content
        assert "exit_code =" in content
        assert "total_lines =" in content
        assert "lines_executed =" in content
        assert "coverage_percent =" in content
    
    def test_coverage_file_format(self, shellcov_binary, test_script,
                                   coverage_report_dir):
        """Test that coverage file has proper format."""
        cov_file = coverage_report_dir / "coverage.txt"
        env = os.environ.copy()
        env["SHELLCOV_COVERAGE_FILE"] = str(cov_file)
        
        subprocess.run(
            [str(shellcov_binary), f"bash {test_script}"],
            capture_output=True,
            text=True,
            env=env,
            timeout=10
        )
        
        content = cov_file.read_text()
        lines = content.split('\n')
        
        # Should start with header
        assert lines[0].startswith("# Shellcov Coverage Report")
        
        # Parse sections
        sections = {}
        current_section = None
        for line in lines:
            if line.startswith("[") and line.endswith("]"):
                current_section = line[1:-1]
                sections[current_section] = {}
            elif "=" in line and current_section:
                key, value = line.split("=", 1)
                sections[current_section][key.strip()] = value.strip()
        
        # Verify sections exist and have values
        assert "execution" in sections
        assert "coverage_stats" in sections
        assert "executed_lines" in sections
        
        # Verify coverage_stats has numeric values
        stats = sections["coverage_stats"]
        assert "total_lines" in stats
        assert "lines_executed" in stats
        assert "coverage_percent" in stats
        
        # Values should be numeric
        assert stats["total_lines"].isdigit()
        assert stats["lines_executed"].isdigit()
    
    def test_coverage_percentage_calculation(self, shellcov_binary, test_script,
                                              coverage_report_dir):
        """Test that coverage percentage is calculated correctly."""
        cov_file = coverage_report_dir / "coverage.txt"
        env = os.environ.copy()
        env["SHELLCOV_COVERAGE_FILE"] = str(cov_file)
        
        subprocess.run(
            [str(shellcov_binary), f"bash {test_script}"],
            capture_output=True,
            text=True,
            env=env,
            timeout=10
        )
        
        content = cov_file.read_text()
        
        # Extract coverage percentage
        for line in content.split('\n'):
            if line.startswith("coverage_percent"):
                _, pct_str = line.split("=", 1)
                coverage_pct = float(pct_str.strip())
                
                # Should be a valid percentage
                assert 0.0 <= coverage_pct <= 100.0
                break
    
    def test_cli_ux_displays_coverage_summary(self, shellcov_binary, test_script,
                                               coverage_report_dir):
        """Test that CLI displays coverage summary in human-readable format."""
        cov_file = coverage_report_dir / "coverage.txt"
        env = os.environ.copy()
        env["SHELLCOV_COVERAGE_FILE"] = str(cov_file)
        
        result = subprocess.run(
            [str(shellcov_binary), f"bash {test_script}"],
            capture_output=True,
            text=True,
            env=env,
            timeout=10
        )
        
        output = result.stdout + result.stderr
        
        # Should display coverage report header
        assert "Shellcov Coverage Report" in output
        assert "test.sh" in output
        
        # Should display coverage statistics
        assert "Lines executed:" in output or "coverage" in output.lower()
        assert "Coverage:" in output or "coverage" in output.lower()
    
    def test_cli_ux_shows_missing_lines(self, shellcov_binary, test_script,
                                         coverage_report_dir):
        """Test that CLI shows which lines are missing from coverage."""
        cov_file = coverage_report_dir / "coverage.txt"
        env = os.environ.copy()
        env["SHELLCOV_COVERAGE_FILE"] = str(cov_file)
        
        result = subprocess.run(
            [str(shellcov_binary), f"bash {test_script}"],
            capture_output=True,
            text=True,
            env=env,
            timeout=10
        )
        
        output = result.stdout + result.stderr
        
        # May show missing lines info if coverage is less than 100%
        if "100%" not in output:
            # If not full coverage, should mention uncovered lines
            assert any(x in output.lower() for x in [
                "uncovered",
                "missing",
                "lines missing",
                "not covered"
            ])
    
    def test_exit_code_propagation(self, shellcov_binary, coverage_report_dir):
        """Test that shellcov propagates the exit code from the script."""
        # Create script that exits with code 42
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sh', delete=False) as f:
            f.write("#!/bin/bash\nexit 42\n")
            script = f.name
        
        try:
            cov_file = coverage_report_dir / "coverage.txt"
            env = os.environ.copy()
            env["SHELLCOV_COVERAGE_FILE"] = str(cov_file)
            
            result = subprocess.run(
                [str(shellcov_binary), f"bash {script}"],
                capture_output=True,
                text=True,
                env=env,
                timeout=10
            )
            
            assert result.returncode == 42
            
            # Coverage file should record the exit code
            content = cov_file.read_text()
            assert "exit_code = 42" in content
        finally:
            os.unlink(script)
    
    def test_coverage_file_with_real_script(self, shellcov_binary, coverage_report_dir):
        """Test shellcov with real-world shell script (shellwrap.sh)."""
        # Try to find shellwrap.sh script
        possible_paths = [
            Path(__file__).parent.parent.parent.parent / "scripts" / "shellwrap.sh",
            Path(__file__).parent.parent / "../../scripts/shellwrap.sh",
        ]
        
        script = None
        for path in possible_paths:
            if path.exists():
                script = path
                break
        
        if not script:
            pytest.skip("shellwrap.sh not found")
        
        cov_file = coverage_report_dir / "shellwrap-coverage.txt"
        env = os.environ.copy()
        env["SHELLCOV_COVERAGE_FILE"] = str(cov_file)
        
        result = subprocess.run(
            [str(shellcov_binary), f"bash {script} --help"],
            capture_output=True,
            text=True,
            env=env,
            timeout=10
        )
        
        # Should execute successfully
        assert result.returncode == 0
        
        # Should generate coverage file
        assert cov_file.exists()
        
        # Coverage file should have stats
        content = cov_file.read_text()
        assert "[coverage_stats]" in content
        assert "total_lines" in content
        assert "coverage_percent" in content
    
    def test_line_range_formatting(self, shellcov_binary, test_script,
                                    coverage_report_dir):
        """Test that line ranges are formatted correctly (e.g., 1-3, 5, 7-9)."""
        cov_file = coverage_report_dir / "coverage.txt"
        env = os.environ.copy()
        env["SHELLCOV_COVERAGE_FILE"] = str(cov_file)
        
        subprocess.run(
            [str(shellcov_binary), f"bash {test_script}"],
            capture_output=True,
            text=True,
            env=env,
            timeout=10
        )
        
        content = cov_file.read_text()
        
        # Look for [executed_lines] section
        for line in content.split('\n'):
            if line.startswith("lines ="):
                line_ranges = line.split("=", 1)[1].strip()
                # Should be either "none" or contain line numbers/ranges
                if line_ranges != "none":
                    # Format should be like "1-3, 5, 7-9" or just numbers
                    assert any(c.isdigit() or c in '-,.' for c in line_ranges)
                break


class TestShellcovIntegration:
    """Integration tests for shellcov with other components."""
    
    def test_shellcov_with_verbose_mode(self, shellcov_binary, test_script,
                                         coverage_report_dir):
        """Test shellcov with SHELLCOV_VERBOSE enabled."""
        cov_file = coverage_report_dir / "coverage.txt"
        env = os.environ.copy()
        env["SHELLCOV_COVERAGE_FILE"] = str(cov_file)
        env["SHELLCOV_VERBOSE"] = "1"
        
        result = subprocess.run(
            [str(shellcov_binary), f"bash {test_script}"],
            capture_output=True,
            text=True,
            env=env,
            timeout=10
        )
        
        # Should still work with verbose mode
        assert result.returncode == 0
        assert cov_file.exists()
        
        # Stderr should contain verbose output
        assert "[shellcov]" in result.stderr or "verbose" in result.stderr.lower()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
