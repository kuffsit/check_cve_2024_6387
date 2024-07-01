import socket
import sys

def check_vulnerability(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((ip, port))

        # Send SSH version string
        sock.sendall(b'SSH-2.0-OpenSSH\r\n')
        response = sock.recv(1024)

        # Check for vulnerable OpenSSH versions
        vulnerable_versions = [
            b'SSH-2.0-OpenSSH_8.5p1',
            b'SSH-2.0-OpenSSH_8.6p1',
            b'SSH-2.0-OpenSSH_8.7p1',
            b'SSH-2.0-OpenSSH_8.8p1',
            b'SSH-2.0-OpenSSH_8.9p1',
            b'SSH-2.0-OpenSSH_9.0p1',
            b'SSH-2.0-OpenSSH_9.1p1',
            b'SSH-2.0-OpenSSH_9.2p1',
            b'SSH-2.0-OpenSSH_9.3p1',
            b'SSH-2.0-OpenSSH_9.4p1',
            b'SSH-2.0-OpenSSH_9.5p1',
            b'SSH-2.0-OpenSSH_9.6p1',
            b'SSH-2.0-OpenSSH_9.7p1'
        ]

        if any(version in response for version in vulnerable_versions):
            print(f"[+] Server at {ip}:{port} is running a vulnerable version of OpenSSH")
            return True
        else:
            print(f"[-] Server at {ip}:{port} is not running a vulnerable version of OpenSSH")
            return False
    except Exception as e:
        print(f"[-] Failed to connect to {ip}:{port}: {e}")
        return False

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <ip> <port or file path>")
        sys.exit(1)

    ip_or_file = sys.argv[1]
    port = int(sys.argv[2])

    # Check if ip_or_file is a file
    try:
        with open(ip_or_file, 'r') as file:
            ips = file.readlines()
    except IOError:
        ips = [ip_or_file]

    for ip in ips:
        ip = ip.strip()
        if check_vulnerability(ip, port):
            print(f"[+] Server at {ip}:{port} is likely vulnerable to CVE-2024-6387.")
        else:
            print(f"[-] Server at {ip}:{port} is not vulnerable to CVE-2024-6387.")
