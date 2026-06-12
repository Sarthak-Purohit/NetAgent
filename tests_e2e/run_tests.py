import os
import sys
import time
import socket
import subprocess

REQUIRED_MODULES = ["pytest", "httpx", "playwright", "fastapi", "uvicorn", "scapy"]

def check_and_install_dependencies():
    """Checks for required Python modules and installs them if missing."""
    missing = False
    for module in REQUIRED_MODULES:
        try:
            __import__(module)
        except ImportError:
            missing = True
            print(f"Module '{module}' is not installed.")
            
    requirements_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "requirements.txt")
    if missing:
        print(f"Installing dependencies from {requirements_path}...")
        try:
            subprocess.run([sys.executable, "-m", "pip", "install", "-r", requirements_path], check=True)
        except subprocess.CalledProcessError as e:
            print(f"Failed to install dependencies: {e}")
            sys.exit(1)
        
        print("Installing Playwright chromium browser binary...")
        try:
            subprocess.run([sys.executable, "-m", "playwright", "install", "chromium"], check=True)
        except subprocess.CalledProcessError as e:
            print(f"Failed to install Playwright browser binaries: {e}")
            sys.exit(1)
    else:
        print("All dependencies are already present.")

def generate_pcaps():
    """Generates the mock PCAP traffic files by calling generate_test_pcaps.py."""
    generator_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "generate_test_pcaps.py")
    print("Generating mock PCAP traffic file...")
    try:
        subprocess.run([sys.executable, generator_path], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Failed to generate mock PCAP: {e}")
        sys.exit(1)

def wait_for_port(port, host="127.0.0.1", timeout=10.0):
    """Waits for a port to start listening."""
    start_time = time.time()
    while True:
        try:
            with socket.create_connection((host, port), timeout=1.0):
                return True
        except (socket.timeout, ConnectionRefusedError):
            if time.time() - start_time > timeout:
                return False
            time.sleep(0.5)

def is_port_in_use(port, host="127.0.0.1"):
    """Checks if a port is already in use."""
    try:
        with socket.create_connection((host, port), timeout=1.0):
            return True
    except (socket.timeout, ConnectionRefusedError):
        return False

def main():
    # 1. Dependency Management
    check_and_install_dependencies()

    # 2. Generate Test PCAPs
    generate_pcaps()

    # 3. Start Mock Server
    mock_server_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mock_server.py")
    port = 8000
    host = "127.0.0.1"

    if is_port_in_use(port, host):
        print(f"Warning: Port {port} is already in use. Assuming a server is already running.")
        server_process = None
    else:
        print(f"Starting mock server on {host}:{port}...")
        server_process = subprocess.Popen(
            [sys.executable, mock_server_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        # Wait for the server to be ready
        if not wait_for_port(port, host, timeout=10.0):
            print("Error: Mock server failed to start in time.")
            # Retrieve errors from stderr
            if server_process:
                server_process.terminate()
                stdout, stderr = server_process.communicate()
                print(f"Server stderr: {stderr.decode('utf-8', errors='ignore')}")
            sys.exit(1)
        print("Mock server is up and running.")

    # 4. Run Pytest
    test_args = [sys.executable, "-m", "pytest", "tests_e2e"]
    # Forward any arguments passed to this script to pytest
    if len(sys.argv) > 1:
        test_args.extend(sys.argv[1:])
    
    print(f"Running tests: {' '.join(test_args)}")
    try:
        result = subprocess.run(test_args)
        exit_code = result.returncode
    except KeyboardInterrupt:
        print("Tests execution interrupted.")
        exit_code = 1
    finally:
        # 5. Stop Mock Server
        if server_process:
            print("Stopping mock server...")
            server_process.terminate()
            try:
                server_process.wait(timeout=5.0)
                print("Mock server stopped.")
            except subprocess.TimeoutExpired:
                print("Mock server did not stop gracefully, killing process.")
                server_process.kill()
                server_process.wait()
                print("Mock server killed.")

    sys.exit(exit_code)

if __name__ == "__main__":
    main()
