"""Pytest tests for tert.shellwrap"""
import os
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch
import pytest
import sys

# Import from the tert package
from tert.shellwrap import Shellwrap


class TestShellwrapAnsiStripping:
    """Test ANSI escape sequence removal."""
    
    @pytest.mark.parametrize("input_text,expected_output", [
        ("plain text", "plain text"),
        ("\x1b[31mred\x1b[0m", "red"),
        ("\x1b[1;32mbold green\x1b[0m", "bold green"),
        ("\x1b[38;5;196mcolor196\x1b[0m", "color196"),
        ("\x1b[31mred\x1b[0m and \x1b[34mblue\x1b[0m", "red and blue"),
        ("", ""),
        ("\x1b[m", ""),
    ])
    def test_strip_ansi(self, input_text, expected_output):
        """Test ANSI stripping with various patterns."""
        sw = Shellwrap()
        assert sw.strip_ansi(input_text) == expected_output


class TestShellwrapEnvironmentVariables:
    """Test environment variable handling."""
    
    def test_set_color_env_always(self):
        """Test that color environment variables are set when color_mode is 'always'."""
        sw = Shellwrap(color_mode='always')
        
        # Clear any existing values
        os.environ.pop('CARGO_TERM_COLOR', None)
        os.environ.pop('FORCE_COLOR', None)
        os.environ.pop('PYTEST_ADDOPTS', None)
        os.environ.pop('NO_COLOR', None)
        
        sw.set_color_env()
        
        assert os.environ['CARGO_TERM_COLOR'] == 'always'
        assert os.environ['FORCE_COLOR'] == '1'
        assert os.environ['PYTEST_ADDOPTS'] == '--color=yes'
    
    def test_set_color_env_never(self):
        """Test that NO_COLOR is set when color_mode is 'never'."""
        sw = Shellwrap(color_mode='never')
        
        os.environ.pop('NO_COLOR', None)
        os.environ.pop('FORCE_COLOR', None)
        
        sw.set_color_env()
        
        assert os.environ['NO_COLOR'] == '1'


class TestShellwrapInit:
    """Test Shellwrap initialization."""
    
    def test_default_initialization(self):
        """Test default values."""
        sw = Shellwrap()
        assert sw.log_file == "build.log"
        assert sw.log_file_ansi == "build.log.ansi"
        assert sw.keep_ansi is False
        assert sw.trace is True
        assert sw.commands == []
        assert sw.argv == []
    
    @pytest.mark.parametrize("log_file,ansi_log,keep,trace", [
        ("custom.log", "custom.ansi", True, False),
        ("/tmp/build.log", "/tmp/build.ansi", False, True),
    ])
    def test_custom_initialization(self, log_file, ansi_log, keep, trace):
        """Test custom initialization parameters."""
        sw = Shellwrap(
            log_file=log_file,
            log_file_ansi=ansi_log,
            keep_ansi=keep,
            trace=trace
        )
        assert sw.log_file == log_file
        assert sw.log_file_ansi == ansi_log
        assert sw.keep_ansi == keep
        assert sw.trace == trace


class TestShellwrapArgumentParsing:
    """Test command-line argument parsing."""
    
    def test_parse_single_cmdstr(self):
        """Test parsing single command string."""
        args = Shellwrap.parse_args(['echo "hello"'])
        assert args.cmdstr == 'echo "hello"'
        assert args.commands == []
    
    def test_parse_single_c_mode(self):
        """Test -c flag with single command."""
        args = Shellwrap.parse_args(['-c', 'echo "hello"'])
        assert args.commands == ['echo "hello"']
        assert args.cmdstr is None
    
    def test_parse_multiple_c_mode(self):
        """Test -c flag with multiple commands."""
        args = Shellwrap.parse_args(['-c', 'cmd1', '-c', 'cmd2', '-c', 'cmd3'])
        assert args.commands == ['cmd1', 'cmd2', 'cmd3']
    
    def test_parse_help_flag(self):
        """Test --help flag."""
        args = Shellwrap.parse_args(['--help'])
        assert args.help is True
    
    def test_parse_double_dash_command_syntax(self):
        """Test -- command syntax."""
        args = Shellwrap.parse_args(['--', 'ls', '-al'])
        assert args.explicit_argv_list == ['ls', '-al']
        assert args.cmdstr is None
        assert args.commands == []
    
    def test_parse_color_option(self):
        """Test --color option."""
        args = Shellwrap.parse_args(['--color', 'always', 'echo test'])
        assert args.color_mode == 'always'
        assert args.cmdstr == 'echo test'


class TestShellwrapExecution:
    """Test command execution with mocking."""
    
    @patch('tert.shellwrap.subprocess.Popen')
    def test_execute_single_command(self, mock_popen):
        """Test executing a single command."""
        mock_process = Mock()
        mock_process.stdout = iter(['output line 1\n', 'output line 2\n'])
        mock_process.stderr = iter([])
        mock_process.wait.return_value = 0
        mock_popen.return_value = mock_process
        
        with tempfile.TemporaryDirectory() as tmpdir:
            sw = Shellwrap(
                log_file=os.path.join(tmpdir, 'build.log'),
                log_file_ansi=os.path.join(tmpdir, 'build.log.ansi'),
                keep_ansi=False,
                trace=False
            )
            sw.commands = ['echo "test"']
            
            exit_code = sw.execute()
            
            assert exit_code == 0
    
    @patch('tert.shellwrap.subprocess.Popen')
    def test_execute_with_ansi_output(self, mock_popen):
        """Test that ANSI output is properly handled."""
        mock_process = Mock()
        mock_process.stdout = iter(['\x1b[31mred\x1b[0m\n'])
        mock_process.stderr = iter([])
        mock_process.wait.return_value = 0
        mock_popen.return_value = mock_process
        
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = os.path.join(tmpdir, 'build.log')
            log_file_ansi = os.path.join(tmpdir, 'build.log.ansi')
            
            sw = Shellwrap(
                log_file=log_file,
                log_file_ansi=log_file_ansi,
                keep_ansi=True,
                trace=False
            )
            sw.commands = ['echo test']
            
            sw.execute()
            
            # Check plain log has ANSI stripped
            with open(log_file, 'r') as f:
                plain_content = f.read()
            assert '\x1b[31m' not in plain_content
    
    @patch('tert.shellwrap.subprocess.Popen')
    def test_execute_removes_ansi_log_by_default(self, mock_popen):
        """Test that ANSI log is removed when keep_ansi is False."""
        mock_process = Mock()
        mock_process.stdout = iter(['output\n'])
        mock_process.stderr = iter([])
        mock_process.wait.return_value = 0
        mock_popen.return_value = mock_process
        
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file_ansi = os.path.join(tmpdir, 'build.log.ansi')
            
            sw = Shellwrap(
                log_file=os.path.join(tmpdir, 'build.log'),
                log_file_ansi=log_file_ansi,
                keep_ansi=False,
                trace=False
            )
            sw.commands = ['echo test']
            
            sw.execute()
            
            assert not os.path.exists(log_file_ansi)
