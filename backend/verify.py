import pytest
import sys

if __name__ == "__main__":
    # Run pytest on our tests and save output to test_output.log
    with open("test_output.log", "w") as f:
        sys.stdout = f
        sys.stderr = f
        exit_code = pytest.main(["-v", "tests/test_scans.py", "tests/test_stress.py"])
        print(f"\nPytest exited with code: {exit_code}", file=f)
    sys.exit(exit_code)
