import requests
import whois
import dns.resolver
import phonenumbers
import sys

BANNER = """
███████╗███╗   ██╗███████╗██╗████████╗██╗  ██╗
██╔════╝████╗  ██║██╔════╝██║╚══██╔══╝██║  ██║
█████╗  ██╔██╗ ██║█████╗  ██║   ██║   ███████║
██╔══╝  ██║╚██╗██║██╔══╝  ██║   ██║   ██╔══██║
███████╗██║ ╚████║███████╗██║   ██║   ██║  ██║
╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝   ╚═╝   ╚═╝  ╚═╝
        OSINT & VULN Toolkit - By Nolan
"""

def banner():
    print(BANNER)

def whois_lookup(domain):
    print("[*] WHOIS Lookup:")
    try:
        w = whois.whois(domain)
        print(w)
    except Exception as e:
        print("Error:", e)

def dns_lookup(domain):
    print("[*] DNS Records:")
    try:
        for qtype in ['A', 'MX', 'NS']:
            answers = dns.resolver.resolve(domain, qtype)
            print(f"{qtype} Records:")
            for r in answers:
                print(f"  {r}")
    except Exception as e:
        print("Error:", e)

def ip_geolocation(ip):
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}")
        data = r.json()
        for key, value in data.items():
            print(f"{key.title()}: {value}")
    except:
        print("Gagal ambil data lokasi")

def phone_lookup(number):
    try:
        parsed = phonenumbers.parse(number)
        print(f"Region: {phonenumbers.region_code_for_number(parsed)}")
        print(f"Carrier: {phonenumbers.carrier.name_for_number(parsed, 'en')}")
        print(f"Valid: {phonenumbers.is_valid_number(parsed)}")
    except:
        print("Nomor tidak valid")

def subdomain_enum(domain):
    print("[*] Subdomain Enumeration:")
    subdomains = ['www', 'mail', 'ftp', 'test', 'dev']
    for sub in subdomains:
        url = f"http://{sub}.{domain}"
        try:
            r = requests.get(url, timeout=3)
            if r.status_code < 400:
                print(f"[+] Found: {url}")
        except:
            pass

def port_scanner(ip):
    import socket
    print("[*] Port Scanner (Top 100 ports):")
    common_ports = [21, 22, 23, 25, 53, 80, 110, 443, 445, 3306]
    for port in common_ports:
        try:
            sock = socket.socket()
            sock.settimeout(0.5)
            result = sock.connect_ex((ip, port))
            if result == 0:
                print(f"[+] Port {port} terbuka")
            sock.close()
        except:
            pass

def vuln_scanner(url):
    print("[*] Basic Vulnerability Scanner")
    try:
        r = requests.get(url)
        if "wp-content" in r.text:
            print("[!] WordPress terdeteksi!")
        elif "joomla" in r.text.lower():
            print("[!] Joomla terdeteksi!")
        else:
            print("[-] CMS tidak terdeteksi.")

        headers = r.headers
        print("\n[*] HTTP Header Check:")
        for h in ['Server', 'X-Powered-By']:
            if h in headers:
                print(f"{h}: {headers[h]}")
    except:
        print("Gagal cek target")

def menu():
    banner()
    print("""
[1] WHOIS Lookup
[2] DNS Lookup
[3] IP Geolocation
[4] Phone OSINT
[5] Subdomain Enumeration
[6] Port Scanner
[7] Vulnerability Scanner
[0] Keluar
""")
    ch = input("Pilih menu: ")
    if ch == "1":
        whois_lookup(input("Domain: "))
    elif ch == "2":
        dns_lookup(input("Domain: "))
    elif ch == "3":
        ip_geolocation(input("IP: "))
    elif ch == "4":
        phone_lookup(input("Nomor (+62...): "))
    elif ch == "5":
        subdomain_enum(input("Domain: "))
    elif ch == "6":
        port_scanner(input("IP Target: "))
    elif ch == "7":
        vuln_scanner(input("URL: "))
    elif ch == "0":
        exit()
    else:
        print("Pilihan salah.")
    input("\nTekan Enter untuk kembali...")
    menu()

menu()
