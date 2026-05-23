# WhoisLookup - WHOIS & Domain Intelligence Tool

Comprehensive domain intelligence gathering tool with WHOIS lookups, DNS analysis, IP geolocation, and SSL certificate inspection.

## Features

- WHOIS record parsing (registrar, creation/expiry dates, name servers)
- DNS record enumeration
- IP geolocation
- SSL/TLS certificate inspection
- Reverse DNS lookups
- Bulk domain lookup
- JSON/CSV export

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/whois-lookup.git
cd whois-lookup
pip3 install -r requirements.txt
chmod +x whoislookup.py
```

## Usage

### Domain WHOIS
```bash
python3 whoislookup.py domain example.com
```

### IP WHOIS
```bash
python3 whoislookup.py ip 8.8.8.8
```

### DNS Records
```bash
python3 whoislookup.py dns example.com
python3 whoislookup.py dns example.com --records A,MX,NS,TXT
```

### SSL Certificate
```bash
python3 whoislookup.py ssl example.com
python3 whoislookup.py ssl example.com --port 443
```

### IP Geolocation
```bash
python3 whoislookup.py geo 8.8.8.8
```

### Reverse DNS
```bash
python3 whoislookup.py rdns 8.8.8.8
```

### Bulk Lookup
```bash
python3 whoislookup.py domain -f domains.txt --output json --file results.json
```

## Legal Disclaimer

This tool queries publicly available information. Use responsibly and respect rate limits.

## License

MIT License
