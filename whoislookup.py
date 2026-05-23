#!/usr/bin/env python3
"""
WhoisLookup - WHOIS & Domain Intelligence Tool
For authorized security research only.
"""

import argparse
import sys
import socket
import json
import csv
import ssl
import datetime

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError:
    class Fore:
        RED = GREEN = YELLOW = CYAN = WHITE = RESET = ""
    class Style:
        RESET_ALL = ""

VERSION = "1.0.0"


def whois_query(domain, server="whois.iana.org", port=43):
    """Query WHOIS server."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((server, port))
        sock.send(f"{domain}\r\n".encode())
        response = b""
        while True:
            data = sock.recv(4096)
            if not data:
                break
            response += data
        sock.close()
        return response.decode('utf-8', errors='ignore')
    except Exception as e:
        return f"Error: {e}"


def get_whois_server(domain):
    """Get the appropriate WHOIS server for a TLD."""
    tld = domain.split('.')[-1].lower()
    servers = {
        "com": "whois.verisign-grs.com",
        "net": "whois.verisign-grs.com",
        "org": "whois.pir.org",
        "info": "whois.afilias.net",
        "io": "whois.nic.io",
        "co": "whois.nic.co",
        "me": "whois.nic.me",
        "dev": "whois.nic.google",
        "app": "whois.nic.google",
        "uk": "whois.nic.uk",
        "de": "whois.denic.de",
        "fr": "whois.nic.fr",
        "au": "whois.auda.org.au",
        "ca": "whois.cira.ca",
        "in": "whois.inregistry.net",
        "ru": "whois.tcinet.ru",
        "cn": "whois.cnnic.cn",
        "br": "whois.registro.br",
        "nl": "whois.sidn.nl",
        "eu": "whois.eu",
        "xyz": "whois.nic.xyz",
        "online": "whois.nic.online",
        "site": "whois.nic.site",
    }
    return servers.get(tld, f"whois.nic.{tld}")


def parse_whois(raw):
    """Parse WHOIS response into structured data."""
    data = {}
    fields = {
        "Domain Name": ["domain_name", "domain"],
        "Registry Domain ID": ["registry_domain_id"],
        "Registrar WHOIS Server": ["registrar_whois_server"],
        "Registrar URL": ["registrar_url"],
        "Updated Date": ["updated_date"],
        "Creation Date": ["creation_date", "created"],
        "Registrar Registration Expiration Date": ["expiry_date", "expiration_date"],
        "Registrar": ["registrar"],
        "Registrar IANA ID": ["registrar_iana_id"],
        "Registrant Organization": ["registrant_org", "org"],
        "Registrant Country": ["registrant_country", "country"],
        "Name Server": ["name_servers"],
        "DNSSEC": ["dnssec"],
        "Status": ["status"],
    }

    for line in raw.split('\n'):
        line = line.strip()
        if ':' in line and not line.startswith('%') and not line.startswith('#'):
            key, _, value = line.partition(':')
            key = key.strip()
            value = value.strip()

            if key in fields:
                for field_name in fields[key]:
                    if field_name in data:
                        if isinstance(data[field_name], list):
                            data[field_name].append(value)
                        else:
                            data[field_name] = [data[field_name], value]
                    else:
                        data[field_name] = value

    return data


def domain_lookup(domain):
    """Full domain WHOIS lookup."""
    print(f"\n{Fore.CYAN}[*] WHOIS Lookup: {domain}{Style.RESET_ALL}")

    # First query IANA to find the right server
    raw = whois_query(domain, "whois.iana.org")

    # Check for registrar WHOIS server referral
    server = None
    for line in raw.split('\n'):
        if 'whois:' in line.lower():
            server = line.split(':')[-1].strip()
            break

    if not server:
        server = get_whois_server(domain)

    # Query the specific server
    raw = whois_query(domain, server)
    data = parse_whois(raw)

    # Print results
    print(f"\n  {Fore.WHITE}Domain:{Style.RESET_ALL} {domain}")
    if "registrar" in data:
        print(f"  {Fore.WHITE}Registrar:{Style.RESET_ALL} {data['registrar']}")
    if "creation_date" in data:
        print(f"  {Fore.WHITE}Created:{Style.RESET_ALL} {data['creation_date']}")
    if "expiry_date" in data:
        print(f"  {Fore.WHITE}Expires:{Style.RESET_ALL} {data['expiry_date']}")
    if "updated_date" in data:
        print(f"  {Fore.WHITE}Updated:{Style.RESET_ALL} {data['updated_date']}")
    if "registrant_org" in data:
        print(f"  {Fore.WHITE}Organization:{Style.RESET_ALL} {data['registrant_org']}")
    if "registrant_country" in data:
        print(f"  {Fore.WHITE}Country:{Style.RESET_ALL} {data['registrant_country']}")
    if "dnssec" in data:
        print(f"  {Fore.WHITE}DNSSEC:{Style.RESET_ALL} {data['dnssec']}")

    if "name_servers" in data:
        ns = data["name_servers"]
        if isinstance(ns, list):
            print(f"\n  {Fore.WHITE}Name Servers:{Style.RESET_ALL}")
            for n in ns:
                print(f"    {n}")
        else:
            print(f"  {Fore.WHITE}Name Server:{Style.RESET_ALL} {ns}")

    if "status" in data:
        status = data["status"]
        if isinstance(status, list):
            print(f"\n  {Fore.WHITE}Status:{Style.RESET_ALL}")
            for s in status:
                print(f"    {s}")
        else:
            print(f"  {Fore.WHITE}Status:{Style.RESET_ALL} {status}")

    return {"domain": domain, "raw": raw[:2000], "parsed": data}


def ip_lookup(ip):
    """IP address WHOIS lookup."""
    print(f"\n{Fore.CYAN}[*] IP WHOIS: {ip}{Style.RESET_ALL}")

    # Resolve hostname
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        print(f"  {Fore.WHITE}Hostname:{Style.RESET_ALL} {hostname}")
    except:
        hostname = None

    raw = whois_query(ip, "whois.arin.net")
    data = parse_whois(raw)

    # Print key info
    for line in raw.split('\n'):
        line = line.strip()
        if any(key in line.lower() for key in ['orgname', 'org-name', 'netrange', 'cidr',
                                                 'country', 'city', 'stateprov', 'address']):
            if ':' in line:
                key, _, val = line.partition(':')
                print(f"  {Fore.WHITE}{key.strip()}:{Style.RESET_ALL} {val.strip()}")

    return {"ip": ip, "hostname": hostname, "raw": raw[:2000]}


def dns_lookup(domain, record_types=None):
    """DNS record lookup."""
    if not HAS_REQUESTS:
        print(f"  {Fore.RED}[!] requests library required{Style.RESET_ALL}")
        return {}

    if record_types is None:
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA"]

    print(f"\n{Fore.CYAN}[*] DNS Records: {domain}{Style.RESET_ALL}\n")
    records = {}

    for rtype in record_types:
        try:
            url = f"https://dns.google/resolve?name={domain}&type={rtype}"
            resp = requests.get(url, timeout=10)
            data = resp.json()
            answers = data.get("Answer", [])
            if answers:
                records[rtype] = []
                print(f"  {Fore.WHITE}{rtype} Records:{Style.RESET_ALL}")
                for a in answers:
                    value = a.get("data", "")
                    ttl = a.get("TTL", "")
                    records[rtype].append({"data": value, "ttl": ttl})
                    print(f"    {value} (TTL: {ttl}s)")
        except Exception as e:
            print(f"  {Fore.RED}[!] {rtype} lookup error: {e}{Style.RESET_ALL}")

    return records


def ssl_lookup(domain, port=443):
    """SSL/TLS certificate inspection."""
    print(f"\n{Fore.CYAN}[*] SSL Certificate: {domain}:{port}{Style.RESET_ALL}\n")

    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()

                print(f"  {Fore.WHITE}TLS Version:{Style.RESET_ALL} {version}")
                print(f"  {Fore.WHITE}Cipher:{Style.RESET_ALL} {cipher[0]} ({cipher[1]} bits)")

                subject = dict(x[0] for x in cert.get('subject', []))
                issuer = dict(x[0] for x in cert.get('issuer', []))

                print(f"\n  {Fore.WHITE}Subject:{Style.RESET_ALL}")
                print(f"    Common Name: {subject.get('commonName', 'N/A')}")
                org = subject.get('organizationName', 'N/A')
                if isinstance(org, tuple):
                    org = org[0]
                print(f"    Organization: {org}")

                print(f"\n  {Fore.WHITE}Issuer:{Style.RESET_ALL}")
                print(f"    Common Name: {issuer.get('commonName', 'N/A')}")
                org = issuer.get('organizationName', 'N/A')
                if isinstance(org, tuple):
                    org = org[0]
                print(f"    Organization: {org}")

                print(f"\n  {Fore.WHITE}Validity:{Style.RESET_ALL}")
                print(f"    Not Before: {cert.get('notBefore', 'N/A')}")
                print(f"    Not After:  {cert.get('notAfter', 'N/A')}")

                san = cert.get('subjectAltName', [])
                if san:
                    print(f"\n  {Fore.WHITE}Subject Alt Names:{Style.RESET_ALL}")
                    for name_type, name in san[:20]:
                        print(f"    {name}")

                return cert
    except Exception as e:
        print(f"  {Fore.RED}[!] SSL Error: {e}{Style.RESET_ALL}")
        return None


def geo_lookup(ip):
    """IP geolocation lookup."""
    if not HAS_REQUESTS:
        print(f"  {Fore.RED}[!] requests library required{Style.RESET_ALL}")
        return None

    print(f"\n{Fore.CYAN}[*] Geolocation: {ip}{Style.RESET_ALL}\n")

    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=10)
        data = resp.json()

        if data.get("status") == "success":
            fields = [
                ("IP", "query"), ("Country", "country"), ("Region", "regionName"),
                ("City", "city"), ("ZIP", "zip"), ("Latitude", "lat"),
                ("Longitude", "lon"), ("Timezone", "timezone"),
                ("ISP", "isp"), ("Organization", "org"), ("AS", "as"),
            ]
            for label, key in fields:
                print(f"  {Fore.WHITE}{label}:{Style.RESET_ALL} {data.get(key, 'N/A')}")
            return data
        else:
            print(f"  {Fore.RED}[!] Lookup failed{Style.RESET_ALL}")
            return None
    except Exception as e:
        print(f"  {Fore.RED}[!] Error: {e}{Style.RESET_ALL}")
        return None


def rdns_lookup(ip):
    """Reverse DNS lookup."""
    print(f"\n{Fore.CYAN}[*] Reverse DNS: {ip}{Style.RESET_ALL}\n")

    try:
        hostname = socket.gethostbyaddr(ip)
        print(f"  {Fore.WHITE}Hostname:{Style.RESET_ALL} {hostname[0]}")
        if hostname[1]:
            print(f"  {Fore.WHITE}Aliases:{Style.RESET_ALL}")
            for alias in hostname[1]:
                print(f"    {alias}")
        if hostname[2]:
            print(f"  {Fore.WHITE}Addresses:{Style.RESET_ALL}")
            for addr in hostname[2]:
                print(f"    {addr}")
        return hostname
    except socket.herror:
        print(f"  {Fore.RED}[!] No reverse DNS record found{Style.RESET_ALL}")
        return None


def main():
    parser = argparse.ArgumentParser(
        description="WhoisLookup - WHOIS & Domain Intelligence Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s domain example.com
  %(prog)s ip 8.8.8.8
  %(prog)s dns example.com --records A,MX,NS
  %(prog)s ssl example.com
  %(prog)s geo 8.8.8.8
  %(prog)s rdns 8.8.8.8
        """
    )

    sub = parser.add_subparsers(dest="command")

    # domain
    d = sub.add_parser("domain", help="Domain WHOIS lookup")
    d.add_argument("target", help="Domain name")
    d.add_argument("-f", "--file", help="File with domains")
    d.add_argument("--output", choices=["json", "csv"], help="Export format")
    d.add_argument("--output-file", help="Output filename")

    # ip
    i = sub.add_parser("ip", help="IP WHOIS lookup")
    i.add_argument("target", help="IP address")

    # dns
    dn = sub.add_parser("dns", help="DNS record lookup")
    dn.add_argument("target", help="Domain name")
    dn.add_argument("--records", default="A,AAAA,MX,NS,TXT,CNAME,SOA,CAA",
                    help="Record types (comma-separated)")

    # ssl
    s = sub.add_parser("ssl", help="SSL certificate inspection")
    s.add_argument("target", help="Domain name")
    s.add_argument("--port", type=int, default=443, help="Port number")

    # geo
    g = sub.add_parser("geo", help="IP geolocation")
    g.add_argument("target", help="IP address")

    # rdns
    r = sub.add_parser("rdns", help="Reverse DNS lookup")
    r.add_argument("target", help="IP address")

    args = parser.parse_args()

    print(f"\n{Fore.CYAN}╔══════════════════════════════════╗")
    print(f"║    WhoisLookup v{VERSION}           ║")
    print(f"╚══════════════════════════════════╝{Style.RESET_ALL}")

    if not args.command:
        parser.print_help()
        sys.exit(1)

    commands = {
        "domain": domain_lookup,
        "ip": ip_lookup,
        "dns": dns_lookup,
        "ssl": ssl_lookup,
        "geo": geo_lookup,
        "rdns": rdns_lookup,
    }

    if args.command == "dns":
        records = args.records.split(",")
        dns_lookup(args.target, records)
    elif args.command == "ssl":
        ssl_lookup(args.target, args.port)
    elif args.command == "domain" and args.file:
        with open(args.file) as f:
            domains = [l.strip() for l in f if l.strip()]
        results = [domain_lookup(d) for d in domains]
        if args.output == "json":
            with open(args.output_file or "whois_results.json", 'w') as f:
                json.dump(results, f, indent=2, default=str)
            print(f"\n{Fore.GREEN}[+] Exported to {args.output_file or 'whois_results.json'}{Style.RESET_ALL}")
    else:
        commands[args.command](args.target)


if __name__ == "__main__":
    main()
