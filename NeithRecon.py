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
[4] Phone OSINT
[5] Subdomain Enumeration
[6] Port Scanner
[7] Vulnerability Scanner
[8] SQL Injection & XSS Scanner
[9] Malware Identification (Hash)
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
    print("Lokasi:", geocoder.description_for_number(p, "en"))

def subdomain_enum(domain):
    print("[*] Subdomain scan (passive)...")
    try:
        res = requests.get(f"https://api.hackertarget.com/hostsearch/?q={domain}")
        print(res.text)
    except:
        print("Gagal ambil subdomain")

def port_scan(host):
    print("[*] Scanning port (1-1024)...")
    for port in range(1, 1025):
        try:
            s = socket.socket()
            s.settimeout(0.3)
            s.connect((host, port))
            print(f"[+] Port terbuka: {port}")
            s.close()
        except:
            pass

def vuln_scan(domain):
    print("[*] Scanning known vulns (passive)...")
    res = requests.get(f"https://api.hackertarget.com/page-link-extractor/?q={domain}")
    links = res.text.splitlines()
    for link in links:
        if any(x in link.lower() for x in ['id=', 'page=', 'php?']):
            print(f"[!] Potensi input param: {link}")

def sqli_xss_scanner(url):
    print("[*] Testing SQLi & XSS injection...")
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
    print("[*] Checking hash on VirusTotal (public API)")
    api = "https://www.virustotal.com/api/v3/files/"
    headers = {
        "x-apikey": "YOUR_API_KEY"  # replace with your API key
    }
    r = requests.get(api + hash_val, headers=headers)
    if r.status_code == 200:
        data = r.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        print("Malware Stats:", stats)
    else:
        print("Hash not found or API error")

def main():
    os.system("clear")
    print(BANNER)
    while True:
        print(MENU)
        choice = input("Pilih menu: ")
        if choice == "1":
            whois_lookup(input("Domain: "))
        elif choice == "2":
            dns_lookup(input("Domain: "))
        elif choice == "3":
            ip_geo(input("IP: "))
        elif choice == "4":
            phone_osint(input("Nomor (e.g. +6281xxx): "))
        elif choice == "5":
            subdomain_enum(input("Domain: "))
        elif choice == "6":
            port_scan(input("Host: "))
        elif choice == "7":
            vuln_scan(input("Domain: "))
        elif choice == "8":
            sqli_xss_scanner(input("URL: "))
        elif choice == "9":
            malware_check(input("File SHA256: "))
        elif choice == "0":
            break
        else:
            print("Pilih yang bener, bre!")

if __name__ == "__main__":
    main()