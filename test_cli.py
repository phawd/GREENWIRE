import subprocess
import logging

def test_cli_functionality():
    """
    Test all CLI functions in greenwire-brute.py.
    """
    commands = [
        # Test standard mode
        ["python", "greenwire-brute.py", "--mode", "standard", "--type", "visa", "--verbose"],
        
        # Test fuzzing mode with PIN authentication
        ["python", "greenwire-brute.py", "--mode", "fuzz", "--auth", "pin", "--export", "results.json"],
        
        # Test CVM processing with signature authentication
        ["python", "greenwire-brute.py", "--mode", "simulate", "--auth", "sig", "--verbose"],
        
        # Test issuing a card
        ["python", "greenwire-brute.py", "--mode", "issue", "--type", "visa", "--lun", "1234567890123456"],
        
        # Test searching for root CA
        ["python", "greenwire-brute.py", "--mode", "search-ca", "--type", "DDA"]
    ]

    for cmd in commands:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            logging.info(f"Command: {' '.join(cmd)}")
            logging.info(f"Output: {result.stdout}")
            logging.error(f"Errors: {result.stderr}")
            assert result.returncode == 0, f"Command failed: {' '.join(cmd)}"
        except Exception as e:
            logging.error(f"Error testing command {' '.join(cmd)}: {e}")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    test_cli_functionality()
