import requests, socket, json, hashlib
from phonenumbers import parse, geocoder
import os, sys

BANNER = """
\033[92m
███╗   ██╗███████╗██╗████████╗██╗  ██╗
████╗  ██║██╔════╝██║╚══██╔══╝██║  ██║
██╔██╗ ██║█████╗  ██║   ██║   ███████║
██║╚██╗██║██╔══╝  ██║   ██║   ██╔══██║
██║ ╚████║███████╗██║   ██║   ██║  ██║
╚═╝  ╚═══╝╚══════╝╚═╝   ╚═╝   ╚═╝  ╚═╝
\033[97mOSINT & VULN Toolkit - By Nolan
"""

MENU = """
[1] WHOIS Lookup
[2] DNS Lookup
[3] IP Geolocation
[4] Phone Number OSINT
[5] Subdomain Enumeration
[6] Port Scanner
[7] Vulnerability Scanner
[8] SQL Injection & XSS Scanner
[9] Malware Detection (Hash)
[0] Exit
"""

def whois_lookup(domain):
    res = requests.get(f"https://api.hackertarget.com/whois/?q={domain}")
    print(res.text)

def dns_lookup(domain):
    res = requests.get(f"https://api.hackertarget.com/dnslookup/?q={domain}")
    print(res.text)

def ip_geo(ip):
    res = requests.get(f"http://ip-api.com/json/{ip}")
    data = res.json()
    for k, v in data.items():
        print(f"{k.capitalize()}: {v}")

def phone_osint(number):
    p = parse(number)
    print("Location:", geocoder.description_for_number(p, "en"))

def subdomain_enum(domain):
    print("[*] Scanning subdomains (passive)...")
    try:
        res = requests.get(f"https://api.hackertarget.com/hostsearch/?q={domain}")
        print(res.text)
    except:
        print("Failed to fetch subdomains")

def port_scan(host):
    print("[*] Scanning ports (1-1024)...")
    for port in range(1, 1025):
        try:
            s = socket.socket()
            s.settimeout(0.3)
            s.connect((host, port))
            print(f"[+] Open port: {port}")
            s.close()
        except:
            pass

def vuln_scan(domain):
    print("[*] Scanning for known vulnerabilities (passive)...")
    res = requests.get(f"https://api.hackertarget.com/page-link-extractor/?q={domain}")
    links = res.text.splitlines()
    for link in links:
        if any(x in link.lower() for x in ['id=', 'page=', 'php?']):
            print(f"[!] Potential vulnerable parameter: {link}")

def sqli_xss_scanner(url):
    print("[*] Testing for SQL Injection & XSS...")
    test_payloads = {
        "SQLi": "' OR '1'='1",
        "XSS": "<script>alert(1)</script>"
    }
    for label, payload in test_payloads.items():
        test_url = f"{url}{payload}"
        res = requests.get(test_url)
        if payload in res.text:
            print(f"[!!] Vulnerable to {label}: {test_url}")
        else:
            print(f"[-] Not vulnerable to {label}")

def malware_check(hash_val):
    print("[*] Checking hash via VirusTotal (public API)")
    api = "https://www.virustotal.com/api/v3/files/"
    headers = {
        "x-apikey": "YOUR_API_KEY"  # replace with your real API key
    }
    r = requests.get(api + hash_val, headers=headers)
    if r.status_code == 200:
        data = r.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        print("Malware Stats:", stats)
    else:
        print("Hash not found or API error")

def main():
    os.system("clear" if os.name != "nt" else "cls")
    print(BANNER)
    while True:
        print(MENU)
        choice = input("Choose an option: ")
        if choice == "1":
            whois_lookup(input("Enter domain: "))
        elif choice == "2":
            dns_lookup(input("Enter domain: "))
        elif choice == "3":
            ip_geo(input("Enter IP address: "))
        elif choice == "4":
            phone_osint(input("Phone number (e.g. +6281xxx): "))
        elif choice == "5":
            subdomain_enum(input("Enter domain: "))
        elif choice == "6":
            port_scan(input("Enter host: "))
        elif choice == "7":
            vuln_scan(input("Enter domain: "))
        elif choice == "8":
            sqli_xss_scanner(input("Enter target URL: "))
        elif choice == "9":
            malware_check(input("Enter SHA256 hash: "))
        elif choice == "0":
            break
        else:
            print("Invalid option, try again!")

if __name__ == "__main__":
    main()