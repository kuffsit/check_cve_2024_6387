import socket
import sys

def check_vulnerability(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((ip, port))

        # Отправляем строку версии SSH
        sock.sendall(b'SSH-2.0-OpenSSH\r\n')
        response = sock.recv(1024)

        # Проверяем, есть ли уязвимая версия OpenSSH
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
            print(f"[+] Сервер по адресу {ip}:{port} использует уязвимую версию OpenSSH")
            return True
        else:
            print(f"[-] Сервер по адресу {ip}:{port} не использует уязвимую версию OpenSSH")
            return False
    except Exception as e:
        print(f"[-] Не удалось подключиться к {ip}:{port}: {e}")
        return False

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Использование: {sys.argv[0]} <ip> <port или путь к файлу>")
        sys.exit(1)

    ip_or_file = sys.argv[1]
    port = int(sys.argv[2])

    # Проверка, если ip_or_file является файлом
    try:
        with open(ip_or_file, 'r') as file:
            ips = file.readlines()
    except IOError:
        ips = [ip_or_file]

    for ip in ips:
        ip = ip.strip()
        if check_vulnerability(ip, port):
            print(f"[+] Сервер по адресу {ip}:{port} вероятно уязвим к CVE-2024-6387.")
        else:
            print(f"[-] Сервер по адресу {ip}:{port} не уязвим к CVE-2024-6387.")
