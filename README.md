![image](https://github.com/kuffsit/check_cve_2024_6387/assets/117442973/f3c921bd-c45d-4a5a-b1d2-c31a772c0949)# check_cve_2024_6387

README
Description
This script checks if a given IP or list of IPs is running a version of OpenSSH that is vulnerable to CVE-2024-6387.

Usage
Single IP Check

To check a single IP, run the script with the IP address and port as arguments.

python3 check_cve_2024_6387.py <ip> <port>

Example:
```sh
python3 check_cve_2024_6387.py 192.168.1.1 22

Multiple IPs Check

To check multiple IPs, provide a file containing a list of IP addresses (one per line) as the first argument, and the port as the second argument.
```sh
python3 check_cve_2024_6387.py <file> <port>

Example:
```sh
python3 check_cve_2024_6387.py ip_list.txt 22

Notes
The script sends an SSH version string to the specified IP and port.
It then checks the server response for known vulnerable OpenSSH versions.
If a vulnerable version is found, the script prints a message indicating that the server is likely vulnerable to CVE-2024-6387.
Dependencies
Python 3.x
Example Output

python3 check_cve_2024_6387.py 192.168.1.1 22
[+] Server at 192.168.1.1:22 is running a vulnerable version of OpenSSH
[+] Server at 192.168.1.1:22 is likely vulnerable to CVE-2024-6387.

python3 check_cve_2024_6387.py ip_list.txt 22
[-] Server at 192.168.1.2:22 is not running a vulnerable version of OpenSSH
[+] Server at 192.168.1.3:22 is running a vulnerable version of OpenSSH
[+] Server at 192.168.1.3:22 is likely vulnerable to CVE-2024-6387.
This setup ensures that you can check both single and multiple IPs for the vulnerability in a straightforward manner.
