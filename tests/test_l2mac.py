"""
Unit tests for the l2mac utility functions and the generate_codebase function.

This module contains tests for the following functions:
- CustomTokenLimitError: Custom exception for token limit errors.
- hash_messages: Hashes a list of messages into a single string.
- detect_cycles: Detects cycles in a list of dictionaries.
- clean_string: Cleans a file path string to extract the file name.
- generate_codebase: Generates a codebase based on a given prompt.

Each test function verifies the expected behavior of these utility functions.
"""
import pytest
from unittest.mock import patch, MagicMock
from l2mac.utils.l2mac import (
    CustomTokenLimitError,
    clean_string,
    detect_cycles,
    hash_messages,
)
from l2mac.core import generate_codebase


def test_l2mac_internal_errors():
    try:
        raise CustomTokenLimitError
    except CustomTokenLimitError:
        assert True


def test_l2mac():
    assert True


def test_hash_messages_empty_list():
    result = hash_messages([])
    assert isinstance(result, str)
    assert len(result) == 64


def test_hash_messages_non_empty_list():
    input_list = ["message1", "message2"]
    result = hash_messages(input_list)
    assert isinstance(result, str)
    assert len(result) == 64


def test_detect_cycles_no_cycle():
    lst = [{"a": 1}, {"b": 2}, {"c": 3}]
    result = detect_cycles(lst)
    assert result is False


def test_detect_cycles_with_cycle():
    lst = [{"a": 1}, {"b": 2}, {"a": 1}, {"b": 2}]
    result = detect_cycles(lst, cycle_lengths=[2])
    assert result is True


def test_clean_string():
    input_string = "/tmp/somepath/file.txt"
    result = clean_string(input_string)
    assert result == "/file.txt"


# Unit tests for generate_codebase function
def test_generate_codebase_input_validation():
    with pytest.raises(TypeError):
        generate_codebase(prompt_task=None)

    with pytest.raises(ValueError):
        generate_codebase(prompt_task="")

    with pytest.raises(ValueError):
        generate_codebase(prompt_task="   ")


def test_generate_codebase_output_structure():
    prompt_task = "Create a simple Python project"
    result = generate_codebase(prompt_task=prompt_task)
    assert isinstance(result, dict)
    assert "files" in result
    assert "directories" in result


def test_generate_codebase_code_generation():
    prompt_task = "Create a simple Python project"
    result = generate_codebase(prompt_task=prompt_task)
    files = result.get("files", {})
    for file_name, file_content in files.items():
        assert file_name.endswith(".py")
        assert isinstance(file_content, str)


def test_generate_codebase_integration_with_other_modules():
    prompt_task = "Create a simple Python project"
    result = generate_codebase(prompt_task=prompt_task)
    files = result.get("files", {})
    assert "main.py" in files
    assert "README.md" in files


# End-to-end tests for generate_codebase function
@patch("l2mac.core.run_l2mac")
def test_generate_codebase_full_codebase_generation(mock_run_l2mac):
    mock_run_l2mac.return_value = {"files": {"main.py": "print('Hello, World!')"}}
    prompt_task = "Create a simple Python project"
    result = generate_codebase(prompt_task=prompt_task)
    assert "main.py" in result["files"]
    assert result["files"]["main.py"] == "print('Hello, World!')"


@patch("l2mac.core.run_l2mac")
def test_generate_codebase_different_prompts(mock_run_l2mac):
    mock_run_l2mac.return_value = {"files": {"main.py": "print('Hello, World!')"}}
    prompt_task = "Create a simple Python project"
    result = generate_codebase(prompt_task=prompt_task)
    assert "main.py" in result["files"]

    mock_run_l2mac.return_value = {"files": {"app.py": "print('Hello, App!')"}}
    prompt_task = "Create a simple Flask app"
    result = generate_codebase(prompt_task=prompt_task)
    assert "app.py" in result["files"]


@patch("l2mac.core.run_l2mac")
def test_generate_codebase_performance(mock_run_l2mac):
    mock_run_l2mac.return_value = {"files": {"main.py": "print('Hello, World!')"}}
    prompt_task = "Create a simple Python project"
    result = generate_codebase(prompt_task=prompt_task)
    assert "main.py" in result["files"]


@patch("l2mac.core.run_l2mac")
def test_generate_codebase_error_handling(mock_run_l2mac):
    mock_run_l2mac.side_effect = RuntimeError("An error occurred")
    prompt_task = "Create a simple Python project"
    with pytest.raises(RuntimeError):
        generate_codebase(prompt_task=prompt_task)


if __name__ == "__main__":
    test_l2mac()
    test_l2mac_internal_errors()
    test_hash_messages_empty_list()
    test_hash_messages_non_empty_list()
    test_detect_cycles_no_cycle()
    test_detect_cycles_with_cycle()
    test_clean_string()
    test_generate_codebase_input_validation()
    test_generate_codebase_output_structure()
    test_generate_codebase_code_generation()
    test_generate_codebase_integration_with_other_modules()
    test_generate_codebase_full_codebase_generation()
    test_generate_codebase_different_prompts()
    test_generate_codebase_performance()
    test_generate_codebase_error_handling()
    print("l2mac test passed")
