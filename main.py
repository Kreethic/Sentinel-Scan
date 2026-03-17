"""
Sentinel Scan - Online Version
--------------------------------
A vulnerability scanner using built-in Kali Linux tools over network.
Requires internet/network connection to scan targets.
Run: sudo python3 main.py
"""

import os
import re
import sys
import subprocess
import shutil
import socket
import hashlib
import time
from datetime import datetime
import requests

# ──────────────────────────────────────────────
# Styling / UI Helpers
# ──────────────────────────────────────────────

class Color:
    RED     = "\033[91m"
    ORANGE  = "\033[33m"
    YELLOW  = "\033[93m"
    GREEN   = "\033[92m"
    CYAN    = "\033[96m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    BOLD    = "\033[1m"
    RESET   = "\033[0m"

def banner():
    print(f"""
{Color.CYAN}{Color.BOLD}
  /$$$$$$                        /$$     /$$                       /$$
 /$$__  $$                      | $$    |__/                      | $$
| $$  \__/ | $$$$$$  /$$$$$$$  /$$$$$$  | $$ /$$$$$$$   /$$$$$$   | $$
|  $$$$$$  /$$__  $$| $$__  $$|_  $$_/  | $$| $$__  $$ /$$__  $$  | $$
 \____  $$| $$$$$$$$| $$  \ $$  | $$    | $$| $$  \ $$| $$$$$$$$  | $$
 /$$  \ $$| $$_____/| $$  | $$  | $$ /$$| $$| $$  | $$| $$_____/  | $$ /$$
|  $$$$$$/|  $$$$$$$| $$  | $$  |  $$$$/| $$| $$  | $$|  $$$$$$$  |  $$$$/
 \______/  \_______/|__/  |__/   \___/  |__/|__/  |__/ \_______/   \___/

  /$$$$$$                               
 /$$__  $$                              
| $$  \__/  /$$$$$$$  /$$$$$$  /$$$$$$$ 
|  $$$$$$  /$$_____/ |____  $$| $$__  $$
 \____  $$| $$        /$$$$$$$| $$  \ $$
 /$$  \ $$| $$       /$$__  $$| $$  | $$
|  $$$$$$/|  $$$$$$$|  $$$$$$$| $$  | $$
 \______/  \_______/ \_______/|__/  |__/
{Color.RESET}
{Color.MAGENTA}         Sentinel Scan  | Powered by Kreethic  |  Sentry Squad  |  Online Edition{Color.RESET}


The Scanning is take some time "Slower scans often produce more accurate results"

""")

def divider(char="─", length=70, color=Color.CYAN):
    print(f"{color}{char * length}{Color.RESET}")

def log_info(msg):    print(f"{Color.CYAN}[*]{Color.RESET} {msg}")
def log_success(msg): print(f"{Color.GREEN}[+]{Color.RESET} {msg}")
def log_warn(msg):    print(f"{Color.YELLOW}[!]{Color.RESET} {msg}")
def log_error(msg):   print(f"{Color.RED}[x]{Color.RESET} {msg}")


# ──────────────────────────────────────────────
# Tool Availability Checker
# ──────────────────────────────────────────────

REQUIRED_TOOLS = {
    "nmap"     : "sudo apt install nmap -y",
    "nikto"    : "sudo apt install nikto -y",
    "gobuster" : "sudo apt install gobuster -y",
    "whois"    : "sudo apt install whois -y",
    "sslscan"  : "sudo apt install sslscan -y",
    "whatweb"  : "sudo apt install whatweb -y",
    "dig"      : "sudo apt install dnsutils -y",
}

def check_tools():
    """Check which tools are installed."""
    print(f"\n{Color.BOLD}  Checking installed tools...{Color.RESET}\n")
    missing = []
    for tool, install_cmd in REQUIRED_TOOLS.items():
        if shutil.which(tool):
            print(f"  {Color.GREEN}[✔]{Color.RESET} {tool:12} installed")
        else:
            print(f"  {Color.RED}[✘]{Color.RESET} {tool:12} NOT found  →  {install_cmd}")
            missing.append(tool)
    if missing:
        print(f"\n{Color.YELLOW}[!] {len(missing)} tool(s) missing. Install them with the commands above.{Color.RESET}")
    else:
        print(f"\n{Color.GREEN}[+] All tools are installed and ready!{Color.RESET}")
    print()
    return missing


def run_command(cmd: list, timeout: int = 120) -> str:
    """Run a shell command and return output."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout
        )
        output = result.stdout + result.stderr
        return output.strip()
    except subprocess.TimeoutExpired:
        return f"[!] Command timed out after {timeout}s"
    except FileNotFoundError:
        return f"[x] Tool not found: {cmd[0]} — install with: {REQUIRED_TOOLS.get(cmd[0], 'apt install ' + cmd[0])}"
    except Exception as e:
        return f"[x] Error: {e}"



# ──────────────────────────────────────────────
# Online Threat Intelligence (No API Key)
# ──────────────────────────────────────────────

def check_internet() -> bool:
    """Check if internet is available."""
    try:
        socket.setdefaulttimeout(3)
        socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect(("8.8.8.8", 53))
        return True
    except Exception:
        return False

def urlhaus_check_url(url: str) -> dict:
    """Check a URL against URLhaus malware database."""
    try:
        lookup = url if url.startswith("http") else f"http://{url}"
        r = requests.post("https://urlhaus-api.abuse.ch/v1/url/",
                          data={"url": lookup}, timeout=8)
        data = r.json()
        status = data.get("query_status", "")
        if status == "ok":
            return {
                "malicious"  : True,
                "url_status" : data.get("url_status", "N/A"),
                "threat"     : data.get("threat", "N/A"),
                "tags"       : ", ".join(data.get("tags") or []),
            }
    except Exception:
        pass
    return {"malicious": False}

def urlhaus_check_host(host: str) -> dict:
    """Check a host/domain/IP against URLhaus."""
    try:
        r = requests.post("https://urlhaus-api.abuse.ch/v1/host/",
                          data={"host": host}, timeout=8)
        data = r.json()
        if data.get("query_status") == "is_host":
            urls    = data.get("urls", [])
            online  = [u for u in urls if u.get("url_status") == "online"]
            tags    = set()
            for u in urls:
                tags.update(u.get("tags") or [])
            return {
                "malicious"     : True,
                "total_urls"    : len(urls),
                "active_urls"   : len(online),
                "tags"          : ", ".join(tags),
            }
    except Exception:
        pass
    return {"malicious": False}

def ipwhois_check(ip: str) -> dict:
    """Get IP geolocation and reputation info."""
    try:
        r = requests.get(f"https://ipwho.is/{ip}", timeout=8)
        data = r.json()
        if data.get("success"):
            isp = data.get("connection", {}).get("isp", "")
            org = data.get("connection", {}).get("org", "")
            suspicious_keywords = ["tor", "vpn", "proxy", "hosting",
                                    "datacenter", "bulletproof", "anonymous"]
            is_suspicious = any(k in (isp + org).lower() for k in suspicious_keywords)
            return {
                "country"      : data.get("country", "N/A"),
                "city"         : data.get("city", "N/A"),
                "isp"          : isp,
                "org"          : org,
                "is_suspicious": is_suspicious,
            }
    except Exception:
        pass
    return {}

def malwarebazaar_check(file_hash: str) -> dict:
    """Check a file hash against MalwareBazaar."""
    try:
        r = requests.post("https://mb-api.abuse.ch/api/v1/",
                          data={"query": "get_info", "hash": file_hash}, timeout=10)
        data = r.json()
        if data.get("query_status") == "ok":
            details = data.get("data", [{}])[0]
            return {
                "malicious"  : True,
                "signature"  : details.get("signature", "N/A"),
                "file_type"  : details.get("file_type", "N/A"),
                "first_seen" : details.get("first_seen", "N/A"),
                "tags"       : ", ".join(details.get("tags") or []),
            }
    except Exception:
        pass
    return {"malicious": False}

def enrich_with_online(result: dict, target: str, online: bool):
    """Add online threat intel to any scan result."""
    if not online:
        return result
    log_info("Enriching with online threat intelligence...")
    host = re.sub(r"https?://", "", target).split("/")[0]

    # URLhaus host check
    host_data = urlhaus_check_host(host)
    if host_data.get("malicious"):
        active = host_data.get("active_urls", 0)
        total  = host_data.get("total_urls", 0)
        tags   = host_data.get("tags", "")
        if active > 0:
            result["flags"].append(f"[ONLINE] URLhaus: {active} ACTIVE malicious URLs on this host!")
        elif total > 0:
            result["flags"].append(f"[ONLINE] URLhaus: {total} historical malicious URL(s) on this host")
        if tags:
            result["info"]["Threat Tags"] = tags

    # IPwho.is check if target looks like an IP
    try:
        socket.inet_aton(host)
        ip_data = ipwhois_check(host)
        if ip_data:
            result["info"]["Country"] = ip_data.get("country", "N/A")
            result["info"]["ISP"]     = ip_data.get("isp", "N/A")
            result["info"]["Org"]     = ip_data.get("org", "N/A")
            if ip_data.get("is_suspicious"):
                result["flags"].append(f"[ONLINE] Suspicious ISP/Org detected: {ip_data.get('isp')}")
    except Exception:
        pass

    result["risk"] = assess_risk(result["flags"])
    return result


# ──────────────────────────────────────────────
# 1. Nmap — Port Scanner
# ──────────────────────────────────────────────

def scan_ports_nmap(target: str) -> dict:
    log_info(f"Running Nmap port scan on: {target}")
    result = {"target": target, "type": "Port Scan (Nmap)", "flags": [], "info": {}, "output": ""}

    cmd = ["nmap", "-sV", "-sC", "--open", "-T4", target]
    log_info(f"Command: {' '.join(cmd)}")
    output = run_command(cmd, timeout=180)
    result["output"] = output

    # Parse open ports
    ports = re.findall(r"(\d+)/tcp\s+open\s+(\S+)", output)
    if ports:
        result["info"]["Open Ports"] = len(ports)
        port_list = ", ".join([f"{p[0]}/{p[1]}" for p in ports])
        result["info"]["Services"]   = port_list
        log_success(f"Found {len(ports)} open port(s)")

        # Flag risky services
        risky = {"21": "FTP", "23": "Telnet", "445": "SMB",
                 "3389": "RDP", "5900": "VNC", "6379": "Redis",
                 "27017": "MongoDB", "2375": "Docker (exposed)"}
        for port, service in ports:
            if port in risky:
                result["flags"].append(f"Risky service open: {port}/{risky[port]}")
    else:
        result["info"]["Open Ports"] = "None found"

    # Check for vulnerabilities in output
    if "VULNERABLE" in output.upper():
        result["flags"].append("Nmap NSE detected potential vulnerability!")
    if "CVE-" in output:
        cves = re.findall(r"CVE-\d{4}-\d+", output)
        for cve in set(cves):
            result["flags"].append(f"CVE detected: {cve}")

    result["risk"] = assess_risk(result["flags"])
    return result


# ──────────────────────────────────────────────
# 2. Nmap — Vulnerability Scan (NSE Scripts)
# ──────────────────────────────────────────────

def scan_vuln_nmap(target: str) -> dict:
    log_info(f"Running Nmap vulnerability scan on: {target}")
    result = {"target": target, "type": "Vulnerability Scan (Nmap NSE)", "flags": [], "info": {}, "output": ""}

    cmd = ["nmap", "--script", "vuln", "-T4", target]
    log_info(f"Command: {' '.join(cmd)}")
    log_warn("This scan may take 2-5 minutes...")
    output = run_command(cmd, timeout=300)
    result["output"] = output

    # Parse vulnerabilities
    vulns = re.findall(r"(CVE-\d{4}-\d+)", output)
    if vulns:
        result["info"]["CVEs Found"] = len(set(vulns))
        for cve in set(vulns):
            result["flags"].append(f"Vulnerability found: {cve}")

    if "VULNERABLE" in output.upper():
        vuln_lines = [l.strip() for l in output.split("\n") if "VULNERABLE" in l.upper()]
        for line in vuln_lines:
            result["flags"].append(f"NSE: {line[:80]}")

    if not result["flags"]:
        result["info"]["Result"] = "No vulnerabilities detected by NSE scripts"

    result["risk"] = assess_risk(result["flags"])
    log_success("Vulnerability scan complete!")
    return result


# ──────────────────────────────────────────────
# 3. Nmap — OS Detection
# ──────────────────────────────────────────────

def scan_os_nmap(target: str) -> dict:
    log_info(f"Running Nmap OS detection on: {target}")
    result = {"target": target, "type": "OS Detection (Nmap)", "flags": [], "info": {}, "output": ""}

    cmd = ["nmap", "-O", "--osscan-guess", "-T4", target]
    log_info(f"Command: {' '.join(cmd)}")
    output = run_command(cmd, timeout=120)
    result["output"] = output

    # Parse OS detection
    os_match = re.search(r"OS details:\s*(.+)", output)
    if os_match:
        result["info"]["OS Detected"] = os_match.group(1).strip()
        log_success(f"OS detected: {os_match.group(1).strip()}")
    else:
        guess = re.search(r"Aggressive OS guesses:\s*(.+)", output)
        if guess:
            result["info"]["OS Guess"] = guess.group(1).strip()[:80]
        else:
            result["info"]["OS Detection"] = "Could not determine OS"

    # TTL based OS hint
    ttl_match = re.search(r"ttl=(\d+)", output.lower())
    if ttl_match:
        ttl = int(ttl_match.group(1))
        if ttl <= 64:
            result["info"]["TTL Hint"] = f"TTL={ttl} → likely Linux/Unix"
        elif ttl <= 128:
            result["info"]["TTL Hint"] = f"TTL={ttl} → likely Windows"

    result["risk"] = assess_risk(result["flags"])
    return result


# ──────────────────────────────────────────────
# 4. Nikto — Web Vulnerability Scanner
# ──────────────────────────────────────────────

def scan_web_nikto(target: str) -> dict:
    log_info(f"Running Nikto web scan on: {target}")
    result = {"target": target, "type": "Web Scan (Nikto)", "flags": [], "info": {}, "output": ""}

    # Ensure target has http/https
    if not target.startswith("http"):
        target_url = "http://" + target
    else:
        target_url = target

    cmd = ["nikto", "-h", target_url, "-nointeractive"]
    log_info(f"Command: {' '.join(cmd)}")
    log_warn("Nikto scan may take 3-10 minutes...")
    output = run_command(cmd, timeout=600)
    result["output"] = output

    # Parse Nikto findings
    findings = re.findall(r"\+ (.+)", output)
    vuln_count = 0
    for finding in findings:
        finding = finding.strip()
        if any(kw in finding.lower() for kw in
               ["vulnerable", "outdated", "exploit", "xss", "sql",
                "inject", "traversal", "disclosure", "misconfigur",
                "osvdb", "cve-"]):
            result["flags"].append(f"Nikto: {finding[:100]}")
            vuln_count += 1

    # Server info
    server = re.search(r"Server:\s*(.+)", output)
    if server:
        result["info"]["Web Server"] = server.group(1).strip()

    # Headers info
    if "X-Frame-Options" not in output:
        result["flags"].append("Missing X-Frame-Options header (clickjacking risk)")
    if "X-XSS-Protection" not in output:
        result["flags"].append("Missing X-XSS-Protection header")
    if "Strict-Transport-Security" not in output:
        result["flags"].append("Missing HSTS header")

    result["info"]["Findings"] = f"{vuln_count} vulnerability findings"
    result["risk"] = assess_risk(result["flags"])
    log_success("Nikto scan complete!")
    return result


# ──────────────────────────────────────────────
# 5. Gobuster — Directory Scanner
# ──────────────────────────────────────────────

def scan_dirs_gobuster(target: str) -> dict:
    log_info(f"Running Gobuster directory scan on: {target}")
    result = {"target": target, "type": "Directory Scan (Gobuster)", "flags": [], "info": {}, "output": ""}

    if not target.startswith("http"):
        target_url = "http://" + target
    else:
        target_url = target

    # Use built-in Kali wordlist
    wordlist = "/usr/share/wordlists/dirb/common.txt"
    if not os.path.exists(wordlist):
        wordlist = "/usr/share/dirb/wordlists/common.txt"
    if not os.path.exists(wordlist):
        result["info"]["Error"] = "Wordlist not found. Install: sudo apt install dirb"
        result["risk"] = "UNKNOWN"
        return result

    cmd = ["gobuster", "dir", "-u", target_url, "-w", wordlist,
           "-t", "50", "--no-error", "-q"]
    log_info(f"Command: {' '.join(cmd)}")
    log_warn("Gobuster scan may take 2-5 minutes...")
    output = run_command(cmd, timeout=300)
    result["output"] = output

    # Parse found directories
    found = re.findall(r"(/\S+)\s+\(Status:\s*(\d+)\)", output)
    if found:
        result["info"]["Dirs Found"] = len(found)
        sensitive = ["/admin", "/login", "/backup", "/config", "/db",
                     "/.git", "/wp-admin", "/phpmyadmin", "/shell",
                     "/upload", "/uploads", "/password", "/.env",
                     "/secret", "/private", "/api", "/console"]
        for path, status in found:
            for s in sensitive:
                if s.lower() in path.lower():
                    result["flags"].append(f"Sensitive path found: {path} (HTTP {status})")
    else:
        result["info"]["Result"] = "No directories found"

    result["risk"] = assess_risk(result["flags"])
    log_success("Gobuster scan complete!")
    return result


# ──────────────────────────────────────────────
# 6. Whois — Domain Info
# ──────────────────────────────────────────────

def scan_whois(target: str) -> dict:
    log_info(f"Running Whois lookup on: {target}")
    result = {"target": target, "type": "Whois Lookup", "flags": [], "info": {}, "output": ""}

    # Strip http/https if present
    domain = re.sub(r"https?://", "", target).split("/")[0]

    cmd = ["whois", domain]
    log_info(f"Command: {' '.join(cmd)}")
    output = run_command(cmd, timeout=30)
    result["output"] = output

    # Parse key fields
    fields = {
        "Registrar"         : r"Registrar:\s*(.+)",
        "Creation Date"     : r"Creation Date:\s*(.+)",
        "Expiry Date"       : r"Registry Expiry Date:\s*(.+)",
        "Registrant Country": r"Registrant Country:\s*(.+)",
        "Name Servers"      : r"Name Server:\s*(.+)",
        "DNSSEC"            : r"DNSSEC:\s*(.+)",
    }
    for label, pattern in fields.items():
        match = re.search(pattern, output, re.IGNORECASE)
        if match:
            result["info"][label] = match.group(1).strip()[:80]

    # Suspicious checks
    if "REDACTED FOR PRIVACY" in output.upper():
        result["info"]["Privacy"] = "Registrant info hidden (privacy protection)"
    if "abuse" in output.lower():
        result["flags"].append("Abuse contact found in whois record")

    # Check expiry
    expiry = result["info"].get("Expiry Date", "")
    if expiry:
        try:
            exp_date = datetime.strptime(expiry[:10], "%Y-%m-%d")
            days_left = (exp_date - datetime.now()).days
            result["info"]["Days Until Expiry"] = str(days_left)
            if days_left < 30:
                result["flags"].append(f"Domain expires in {days_left} days!")
        except Exception:
            pass

    result["risk"] = assess_risk(result["flags"])
    log_success("Whois lookup complete!")
    return result


# ──────────────────────────────────────────────
# 7. SSLScan — SSL/TLS Certificate Analysis
# ──────────────────────────────────────────────

def scan_ssl(target: str) -> dict:
    log_info(f"Running SSLScan on: {target}")
    result = {"target": target, "type": "SSL/TLS Scan (SSLScan)", "flags": [], "info": {}, "output": ""}

    domain = re.sub(r"https?://", "", target).split("/")[0]

    cmd = ["sslscan", "--no-colour", domain]
    log_info(f"Command: {' '.join(cmd)}")
    output = run_command(cmd, timeout=60)
    result["output"] = output

    # Parse SSL info
    cert_match = re.search(r"Subject:\s*(.+)", output)
    if cert_match:
        result["info"]["Certificate"] = cert_match.group(1).strip()

    expiry = re.search(r"Not valid after:\s*(.+)", output)
    if expiry:
        result["info"]["Cert Expiry"] = expiry.group(1).strip()

    issuer = re.search(r"Issuer:\s*(.+)", output)
    if issuer:
        result["info"]["Issuer"] = issuer.group(1).strip()

    # Flag weak protocols
    weak_protocols = ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"]
    for proto in weak_protocols:
        if f"{proto} enabled" in output or f"Enabled  {proto}" in output:
            result["flags"].append(f"Weak protocol enabled: {proto}")

    # Flag weak ciphers
    weak_ciphers = ["RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon"]
    for cipher in weak_ciphers:
        if cipher in output:
            result["flags"].append(f"Weak cipher detected: {cipher}")

    # Self-signed check
    if "self-signed" in output.lower() or "self signed" in output.lower():
        result["flags"].append("Self-signed certificate detected!")

    # Heartbleed check
    if "heartbleed" in output.lower():
        if "vulnerable" in output.lower():
            result["flags"].append("CRITICAL: Heartbleed vulnerability detected!")

    if not result["flags"]:
        result["info"]["SSL Status"] = "No major SSL issues found"

    result["risk"] = assess_risk(result["flags"])
    log_success("SSLScan complete!")
    return result


# ──────────────────────────────────────────────
# 8. WhatWeb — Web Technology Fingerprinting
# ──────────────────────────────────────────────

def scan_whatweb(target: str) -> dict:
    log_info(f"Running WhatWeb fingerprint on: {target}")
    result = {"target": target, "type": "Web Fingerprint (WhatWeb)", "flags": [], "info": {}, "output": ""}

    if not target.startswith("http"):
        target_url = "http://" + target
    else:
        target_url = target

    cmd = ["whatweb", "-a", "3", "--no-errors", target_url]
    log_info(f"Command: {' '.join(cmd)}")
    output = run_command(cmd, timeout=60)
    result["output"] = output

    # Parse technologies
    tech_patterns = {
        "CMS"        : r"(WordPress|Joomla|Drupal|Magento|Shopify)[^\]]*",
        "Web Server" : r"(Apache|Nginx|IIS|LiteSpeed)[^\]]*",
        "Framework"  : r"(Laravel|Django|Rails|ASP\.NET|PHP)[^\]]*",
        "JavaScript" : r"(jQuery|React|Angular|Vue)[^\]]*",
        "IP Address" : r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
        "Country"    : r"Country\[([^\]]+)\]",
    }
    for label, pattern in tech_patterns.items():
        match = re.search(pattern, output, re.IGNORECASE)
        if match:
            result["info"][label] = match.group(0).strip()[:60]

    # Flag outdated or risky tech
    risky_tech = {
        "WordPress" : "WordPress detected — check for outdated plugins",
        "Joomla"    : "Joomla detected — commonly targeted CMS",
        "phpMyAdmin": "phpMyAdmin detected — database admin panel exposed!",
        "X-Powered-By": "Server technology exposed in headers",
    }
    for tech, msg in risky_tech.items():
        if tech.lower() in output.lower():
            result["flags"].append(msg)

    if not result["info"]:
        result["info"]["Result"] = "No technology fingerprint detected"

    result["risk"] = assess_risk(result["flags"])
    log_success("WhatWeb fingerprint complete!")
    return result


# ──────────────────────────────────────────────
# 9. Dig — DNS Analysis
# ──────────────────────────────────────────────

def scan_dns_dig(target: str) -> dict:
    log_info(f"Running DNS analysis on: {target}")
    result = {"target": target, "type": "DNS Analysis (Dig)", "flags": [], "info": {}, "output": ""}

    domain = re.sub(r"https?://", "", target).split("/")[0]

    all_output = ""

    # Query multiple record types
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
    for rtype in record_types:
        cmd = ["dig", domain, rtype, "+short"]
        out = run_command(cmd, timeout=15)
        if out and "error" not in out.lower() and out.strip():
            result["info"][f"{rtype} Record"] = out.strip()[:100]
            all_output += f"\n{rtype}:\n{out}\n"

    # Check SPF record
    txt = result["info"].get("TXT Record", "")
    if "v=spf1" in txt:
        result["info"]["SPF"] = "SPF record found ✔"
    else:
        result["flags"].append("No SPF record found (email spoofing risk)")

    # Check DMARC
    cmd_dmarc = ["dig", f"_dmarc.{domain}", "TXT", "+short"]
    dmarc_out = run_command(cmd_dmarc, timeout=15)
    if "v=DMARC1" in dmarc_out:
        result["info"]["DMARC"] = "DMARC record found ✔"
    else:
        result["flags"].append("No DMARC record found (email spoofing risk)")

    # Check DNSSEC
    cmd_dnssec = ["dig", domain, "DNSKEY", "+short"]
    dnssec_out = run_command(cmd_dnssec, timeout=15)
    if dnssec_out.strip():
        result["info"]["DNSSEC"] = "DNSSEC enabled ✔"
    else:
        result["flags"].append("DNSSEC not enabled")

    result["output"] = all_output
    result["risk"] = assess_risk(result["flags"])
    log_success("DNS analysis complete!")
    return result


# ──────────────────────────────────────────────
# 10. Full Scan — Run ALL tools
# ──────────────────────────────────────────────

def full_scan(target: str) -> dict:
    log_info(f"Starting FULL scan on: {target}")
    log_warn("Full scan runs ALL tools — this may take 10-20 minutes!")
    print()

    all_results = []
    all_flags   = []

    scans = [
        ("Port Scan",        scan_ports_nmap),
        ("Vulnerability",    scan_vuln_nmap),
        ("OS Detection",     scan_os_nmap),
        ("Web Scan",         scan_web_nikto),
        ("Directory Scan",   scan_dirs_gobuster),
        ("Whois",            scan_whois),
        ("SSL Scan",         scan_ssl),
        ("Web Fingerprint",  scan_whatweb),
        ("DNS Analysis",     scan_dns_dig),
    ]

    for name, scan_fn in scans:
        divider("-", 60, Color.YELLOW)
        print(f"{Color.BOLD}  Running: {name}{Color.RESET}")
        divider("-", 60, Color.YELLOW)
        try:
            r = scan_fn(target)
            all_results.append(r)
            all_flags.extend(r.get("flags", []))
            badge = risk_badge(r.get("risk", "CLEAN"))
            print(f"  {name} → {badge} | {len(r.get('flags', []))} flag(s)")
        except Exception as e:
            log_error(f"{name} failed: {e}")
        print()

    # Combined result
    combined = {
        "target"      : target,
        "type"        : "Full Scan",
        "flags"       : all_flags,
        "info"        : {"Total Scans": len(scans),
                         "Total Flags": len(all_flags)},
        "output"      : "",
        "sub_results" : all_results,
        "risk"        : assess_risk(all_flags),
    }
    return combined


# ──────────────────────────────────────────────
# Risk Assessment
# ──────────────────────────────────────────────

def assess_risk(flags: list) -> str:
    count = len(flags)
    if count >= 6:  return "CRITICAL"
    if count >= 4:  return "HIGH"
    if count >= 2:  return "MEDIUM"
    if count >= 1:  return "LOW"
    return "CLEAN"

def risk_badge(level: str) -> str:
    badges = {
        "CRITICAL": f"{Color.RED}{Color.BOLD}[CRITICAL]{Color.RESET}",
        "HIGH"    : f"{Color.ORANGE}{Color.BOLD}[HIGH]{Color.RESET}",
        "MEDIUM"  : f"{Color.YELLOW}{Color.BOLD}[MEDIUM]{Color.RESET}",
        "LOW"     : f"{Color.YELLOW}[LOW]{Color.RESET}",
        "CLEAN"   : f"{Color.GREEN}{Color.BOLD}[CLEAN]{Color.RESET}",
        "UNKNOWN" : f"{Color.BLUE}[UNKNOWN]{Color.RESET}",
    }
    return badges.get(level, f"{Color.GREEN}[CLEAN]{Color.RESET}")


# ──────────────────────────────────────────────
# Report Printer
# ──────────────────────────────────────────────

def print_report(result: dict):
    print()
    divider("=")
    print(f"{Color.BOLD}  404 SCANNER - SCAN REPORT  |  Team 404{Color.RESET}")
    print(f"  Type   : {Color.CYAN}{result['type']}{Color.RESET}")
    print(f"  Target : {Color.MAGENTA}{result['target']}{Color.RESET}")
    print(f"  Time   : {Color.GRAY if hasattr(Color, 'GRAY') else ''}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Color.RESET}")
    divider("=")

    print(f"\n  Risk Level : {risk_badge(result.get('risk', 'CLEAN'))}")

    if result.get("flags"):
        print(f"\n  {Color.BOLD}Threat Indicators ({len(result['flags'])}):{Color.RESET}")
        for flag in result["flags"]:
            print(f"    {Color.YELLOW}>>{Color.RESET} {flag}")
    else:
        print(f"\n  {Color.GREEN}[+] No threat indicators found.{Color.RESET}")

    if result.get("info"):
        print(f"\n  {Color.BOLD}Details:{Color.RESET}")
        for k, v in result["info"].items():
            print(f"    {Color.CYAN}{k:22}{Color.RESET}: {v}")

    # Full scan sub-results summary
    if result.get("sub_results"):
        print(f"\n  {Color.BOLD}Individual Scan Summary:{Color.RESET}")
        divider("-", 60)
        for r in result["sub_results"]:
            badge = risk_badge(r.get("risk", "CLEAN"))
            flags = len(r.get("flags", []))
            print(f"    {Color.CYAN}{r['type']:35}{Color.RESET} {badge}  | {flags} flag(s)")

    divider("=")
    print()


# ──────────────────────────────────────────────
# Report Generation (File)
# ──────────────────────────────────────────────

def generate_report(result: dict) -> str:
    now   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = []
    lines.append("=" * 70)
    lines.append("           404 SCANNER - VULNERABILITY REPORT")
    lines.append("                    Team 404  |  Sentry Squad")
    lines.append("                    Offline Edition")
    lines.append("=" * 70)
    lines.append(f"  Date        : {now}")
    lines.append(f"  Scan Type   : {result['type']}")
    lines.append(f"  Target      : {result['target']}")
    lines.append(f"  Risk Level  : {result.get('risk', 'CLEAN')}")
    lines.append("")
    lines.append("-" * 70)

    if result.get("flags"):
        lines.append(f"  THREAT INDICATORS ({len(result['flags'])})")
        lines.append("-" * 70)
        for flag in result["flags"]:
            lines.append(f"  >> {flag}")
        lines.append("")

    if result.get("info"):
        lines.append("-" * 70)
        lines.append("  DETAILS")
        lines.append("-" * 70)
        for k, v in result["info"].items():
            lines.append(f"  {k:22}: {v}")
        lines.append("")

    if result.get("sub_results"):
        lines.append("-" * 70)
        lines.append("  FULL SCAN SUMMARY")
        lines.append("-" * 70)
        for r in result["sub_results"]:
            lines.append(f"  {r['type']:35} Risk: {r.get('risk','CLEAN'):10} Flags: {len(r.get('flags',[]))}")
        lines.append("")

    if result.get("output"):
        lines.append("-" * 70)
        lines.append("  RAW TOOL OUTPUT")
        lines.append("-" * 70)
        lines.append(result["output"][:3000])
        lines.append("")

    lines.append("=" * 70)
    lines.append("  Generated by Sentinel Scan | Team 404 | Sentry Squad | Online Edition")
    lines.append("=" * 70)
    return "\n".join(lines)

def ask_save_report(result: dict):
    ans = input(f"\n{Color.CYAN}Save report to file? (y/n): {Color.RESET}").strip().lower()
    if ans == "y":
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename  = f"404scan_offline_report_{timestamp}.txt"
        content   = generate_report(result)
        with open(filename, "w", encoding="utf-8") as f:
            f.write(content)
        log_success(f"Report saved: {Color.MAGENTA}{filename}{Color.RESET}")
    else:
        log_info("Report not saved.")


# ──────────────────────────────────────────────
# Interactive Menu
# ──────────────────────────────────────────────

MENU_OPTIONS = [
    ("[1]  Port Scan      ", "Nmap     — Scan open ports and detect services"),
    ("[2]  Vuln Scan      ", "Nmap NSE — Scan for known CVE vulnerabilities"),
    ("[3]  OS Detection   ", "Nmap     — Detect operating system of target"),
    ("[4]  Web Scan       ", "Nikto    — Scan web server for vulnerabilities"),
    ("[5]  Dir Scan       ", "Gobuster — Brute force directories and files"),
    ("[6]  Whois Lookup   ", "Whois    — Get domain registration information"),
    ("[7]  SSL Scan       ", "SSLScan  — Analyze SSL/TLS certificate & ciphers"),
    ("[8]  Web Fingerprint", "WhatWeb  — Detect web technologies and CMS"),
    ("[9]  DNS Analysis   ", "Dig      — Full DNS record analysis"),
    ("[10] Full Scan      ", "ALL      — Run every scan on one target"),
    ("[11] Check Tools    ", "Verify   — Check all required tools are installed"),
    ("[12] Exit           ", "Quit     — Exit Sentinel Scan"),
]

def show_menu():
    print()
    divider()
    print(f"{Color.BOLD}  SELECT SCAN TYPE{Color.RESET}\n")
    for i, (icon, desc) in enumerate(MENU_OPTIONS, 1):
        if i == len(MENU_OPTIONS):
            print(f"  {Color.RED}{icon}{Color.RESET}  {desc}")
        else:
            print(f"  {Color.CYAN}{icon}{Color.RESET}  {desc}")
    divider()

def get_choice() -> int:
    while True:
        try:
            choice = int(input(f"\n{Color.BOLD}Enter choice [1-{len(MENU_OPTIONS)}]: {Color.RESET}"))
            if 1 <= choice <= len(MENU_OPTIONS):
                return choice
            log_warn(f"Enter a number between 1 and {len(MENU_OPTIONS)}.")
        except ValueError:
            log_warn("Invalid input. Please enter a number.")

def get_target(prompt="Enter Target (IP/Domain/URL)") -> str:
    return input(f"{Color.CYAN}{prompt:35}: {Color.RESET}").strip()

def run_scan(choice: int, online: bool):
    print()
    result = None
    try:
        if choice == 1:
            target = get_target("Enter Target (IP/Domain)")
            result = scan_ports_nmap(target)
            result = enrich_with_online(result, target, online)

        elif choice == 2:
            target = get_target("Enter Target (IP/Domain)")
            result = scan_vuln_nmap(target)
            result = enrich_with_online(result, target, online)

        elif choice == 3:
            target = get_target("Enter Target (IP/Domain)")
            result = scan_os_nmap(target)
            result = enrich_with_online(result, target, online)

        elif choice == 4:
            target = get_target("Enter Target (URL/Domain)")
            result = scan_web_nikto(target)
            result = enrich_with_online(result, target, online)

        elif choice == 5:
            target = get_target("Enter Target (URL/Domain)")
            result = scan_dirs_gobuster(target)
            result = enrich_with_online(result, target, online)

        elif choice == 6:
            target = get_target("Enter Domain")
            result = scan_whois(target)
            result = enrich_with_online(result, target, online)

        elif choice == 7:
            target = get_target("Enter Domain/URL")
            result = scan_ssl(target)
            result = enrich_with_online(result, target, online)

        elif choice == 8:
            target = get_target("Enter Target (URL/Domain)")
            result = scan_whatweb(target)
            result = enrich_with_online(result, target, online)

        elif choice == 9:
            target = get_target("Enter Domain")
            result = scan_dns_dig(target)
            result = enrich_with_online(result, target, online)

        elif choice == 10:
            target = get_target("Enter Target (IP/Domain/URL)")
            result = full_scan(target)
            result = enrich_with_online(result, target, online)

        elif choice == 11:
            check_tools()
            input(f"\n{Color.CYAN}Press Enter to return to menu...{Color.RESET}")
            return

        if result:
            print_report(result)
            ask_save_report(result)

    except KeyboardInterrupt:
        log_warn("Scan interrupted by user.")
    except Exception as e:
        log_error(f"Unexpected error: {e}")

    input(f"\n{Color.CYAN}Press Enter to return to menu...{Color.RESET}")


# ──────────────────────────────────────────────
# Entry Point
# ──────────────────────────────────────────────

def main():
    # Check for root/sudo — Linux only
    import platform
    if platform.system() == "Windows":
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        if not is_admin:
            print(f"\n{Color.YELLOW}[!] Some scans require Administrator privileges.{Color.RESET}")
            print(f"{Color.YELLOW}[!] Run as Administrator for full scan capabilities.{Color.RESET}\n")
    else:
        if os.geteuid() != 0:
            print(f"\n{Color.YELLOW}[!] Some scans (Nmap OS, Vuln) require root.{Color.RESET}")
            print(f"{Color.YELLOW}[!] Run with: sudo python3 main.py{Color.RESET}\n")

    banner()

    # ── Check internet connectivity ──
    log_info("Checking internet connection...")
    online = check_internet()
    if online:
        log_success("Network connected — Online mode active!")
        print(f"  {Color.CYAN}[*]{Color.RESET} Kali tools + URLhaus + MalwareBazaar + IPwho.is enrichment enabled\n")
    else:
        log_warn("No network connection detected — some scans may not work.")
        print(f"  {Color.YELLOW}[!]{Color.RESET} Please check your internet connection\n")

    while True:
        show_menu()
        # Show current mode in menu
        mode = f"{Color.GREEN}ONLINE (Network Connected){Color.RESET}" if online else f"{Color.RED}NO NETWORK — Check Connection{Color.RESET}"
        print(f"  Mode: {mode}\n")
        choice = get_choice()
        if choice == len(MENU_OPTIONS):
            print(f"\n{Color.CYAN}{'═' * 65}{Color.RESET}")
            print(f"{Color.BOLD}{Color.MAGENTA}  Goodbye! Sentinel Scan signing off. Stay Secure! 🛡️{Color.RESET}")
            print(f"{Color.CYAN}{'═' * 65}{Color.RESET}\n")
            sys.exit(0)
        run_scan(choice, online)

if __name__ == "__main__":
    main()
