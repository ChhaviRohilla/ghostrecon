#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║   GhostRecon v1.0 — Corporate OSINT & Recon Engine          ║
║   Discovers public/leaked data for any company name         ║
║   ⚠  FOR AUTHORIZED / EDUCATIONAL USE ONLY                 ║
╚══════════════════════════════════════════════════════════════╝

Modules:
  1.  DNS & Subdomain Enumeration
  2.  AWS S3 Bucket Discovery
  3.  Google Workspace / G Suite Exposure
  4.  Email Harvesting & Pattern Discovery
  5.  GitHub Code & Secret Leaks
  6.  Shodan / Internet Exposure (via Shodan API or Censys)
  7.  SSL Certificate Transparency (crt.sh)
  8.  WHOIS & Domain Intelligence
  9.  Pastebin / Ghostbin Leaks
 10.  Google Dork Automation
 11.  LinkedIn / Employee Enumeration
 12.  Cloud Storage Enumeration (Azure, GCP, AWS)
 13.  Breach / HaveIBeenPwned Data
 14.  Technology Stack Fingerprinting
 15.  Report Generation (JSON + HTML)
"""

import os
import sys
import json
import time
import socket
import ssl
import re
import argparse
import threading
import queue
import hashlib
import datetime
import ipaddress
from urllib.parse import urljoin, urlparse, quote
from concurrent.futures import ThreadPoolExecutor, as_completed

# ── Colour output ──────────────────────────────────────────────────────────
class C:
    RED    = '\033[91m'
    GREEN  = '\033[92m'
    YELLOW = '\033[93m'
    BLUE   = '\033[94m'
    CYAN   = '\033[96m'
    WHITE  = '\033[97m'
    BOLD   = '\033[1m'
    DIM    = '\033[2m'
    RESET  = '\033[0m'
    MAGENTA= '\033[95m'

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    requests.packages.urllib3.disable_warnings()
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    import dns.resolver
    import dns.zone
    import dns.query
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False

# ── Global results store ───────────────────────────────────────────────────
RESULTS = {
    "meta":          {},
    "domains":       [],
    "subdomains":    [],
    "emails":        [],
    "aws_buckets":   [],
    "gcp_buckets":   [],
    "azure_blobs":   [],
    "github_leaks":  [],
    "google_dorks":  [],
    "employees":     [],
    "dns_records":   {},
    "ssl_certs":     [],
    "whois":         {},
    "shodan":        [],
    "pastes":        [],
    "technologies":  [],
    "open_ports":    [],
    "google_workspace": {},
    "breaches":      [],
    "vulnerabilities": [],
}

LOCK = threading.Lock()

def safe_add(key, item):
    with LOCK:
        if isinstance(RESULTS[key], list):
            if item not in RESULTS[key]:
                RESULTS[key].append(item)
        elif isinstance(RESULTS[key], dict):
            RESULTS[key].update(item)

# ── Print helpers ──────────────────────────────────────────────────────────
def banner():
    print(f"""
{C.GREEN}{C.BOLD}
  ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗
 ██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝
 ██║  ███╗███████║██║   ██║███████╗   ██║   
 ██║   ██║██╔══██║██║   ██║╚════██║   ██║   
 ╚██████╔╝██║  ██║╚██████╔╝███████║   ██║   
  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   
{C.CYAN}  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
{C.RESET}
{C.YELLOW}  Corporate OSINT & Recon Engine v1.0{C.RESET}
{C.RED}  ⚠  FOR AUTHORIZED / EDUCATIONAL USE ONLY{C.RESET}
""")

def info(msg):    print(f"  {C.BLUE}[*]{C.RESET} {msg}")
def good(msg):    print(f"  {C.GREEN}[+]{C.RESET} {C.GREEN}{msg}{C.RESET}")
def warn(msg):    print(f"  {C.YELLOW}[!]{C.RESET} {C.YELLOW}{msg}{C.RESET}")
def bad(msg):     print(f"  {C.RED}[-]{C.RESET} {msg}")
def found(msg):   print(f"  {C.MAGENTA}[★]{C.RESET} {C.BOLD}{msg}{C.RESET}")
def section(msg): print(f"\n{C.CYAN}{C.BOLD}{'═'*60}\n  {msg}\n{'═'*60}{C.RESET}")

# ── HTTP session ───────────────────────────────────────────────────────────
def make_session():
    s = requests.Session()
    retry = Retry(total=2, backoff_factor=0.3,
                  status_forcelist=[429, 500, 502, 503])
    s.mount('http://',  HTTPAdapter(max_retries=retry))
    s.mount('https://', HTTPAdapter(max_retries=retry))
    s.headers.update({
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 '
                      '(KHTML, like Gecko) Chrome/122.0 Safari/537.36'
    })
    return s

SESSION = None  # initialised after import check

# ══════════════════════════════════════════════════════════════════════════
# MODULE 1 — DOMAIN DISCOVERY
# ══════════════════════════════════════════════════════════════════════════
def derive_domains(company):
    """Generate candidate domain names from company name."""
    section("MODULE 1 — DOMAIN DISCOVERY")
    slug = re.sub(r'[^a-z0-9]', '', company.lower())
    slug2 = re.sub(r'\s+', '-', company.lower().strip())
    slug2 = re.sub(r'[^a-z0-9\-]', '', slug2)

    tlds = ['com','io','co','net','org','ai','dev','app','cloud',
            'tech','xyz','co.in','in','us','co.uk','biz','info']

    candidates = set()
    for tld in tlds:
        candidates.add(f"{slug}.{tld}")
        candidates.add(f"{slug2}.{tld}")
        candidates.add(f"get{slug}.{tld}")
        candidates.add(f"try{slug}.{tld}")
        candidates.add(f"{slug}hq.{tld}")
        candidates.add(f"{slug}app.{tld}")

    live = []
    info(f"Testing {len(candidates)} domain candidates...")

    def check_domain(domain):
        try:
            ip = socket.gethostbyname(domain)
            return (domain, ip)
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=30) as ex:
        futures = {ex.submit(check_domain, d): d for d in candidates}
        for f in as_completed(futures):
            result = f.result()
            if result:
                domain, ip = result
                good(f"Domain alive: {domain} → {ip}")
                safe_add("domains", {"domain": domain, "ip": ip})
                live.append(domain)

    if not live:
        warn("No domains resolved — trying manual input")
    return live

# ══════════════════════════════════════════════════════════════════════════
# MODULE 2 — SUBDOMAIN ENUMERATION
# ══════════════════════════════════════════════════════════════════════════
SUBDOMAIN_WORDLIST = [
    'www','mail','remote','blog','webmail','server','ns1','ns2','smtp',
    'secure','vpn','m','shop','ftp','mail2','test','portal','ns','ww1',
    'host','support','dev','staging','api','app','cdn','admin','beta',
    'dashboard','panel','login','auth','sso','id','identity','git','gitlab',
    'github','jira','confluence','jenkins','ci','cd','build','deploy','prod',
    'production','uat','qa','demo','sandbox','internal','intranet','corp',
    'hr','erp','crm','helpdesk','kb','wiki','docs','developer','developers',
    'status','monitor','grafana','kibana','elastic','s3','storage','files',
    'assets','media','img','images','static','download','uploads','backup',
    'db','database','mysql','postgres','redis','mongo','kafka','rabbitmq',
    'ws','websocket','socket','api2','api-v1','api-v2','v1','v2','v3',
    'mobile','android','ios','web','frontend','backend','microservice',
    'gateway','proxy','lb','loadbalancer','k8s','kubernetes','docker',
    'registry','vault','secret','config','consul','etcd','prometheus',
    'old','legacy','archive','new','next','mx','mx1','mx2','relay',
    'exchange','webdav','owa','autodiscover','lyncdiscover','sip',
    'meet','zoom','video','conference','my','account','accounts','billing',
    'pay','payments','checkout','store','shop','ecommerce','cart',
    'tracking','analytics','data','metrics','logs','reporting','report',
    'jobs','careers','press','ir','investor','partners','affiliate',
]

def enumerate_subdomains(domains):
    section("MODULE 2 — SUBDOMAIN ENUMERATION")
    found_subs = []

    for base_domain in domains[:3]:  # top 3 live domains
        info(f"Enumerating subdomains for: {base_domain}")

        # Method A: DNS brute force
        def check_sub(sub):
            fqdn = f"{sub}.{base_domain}"
            try:
                ip = socket.gethostbyname(fqdn)
                return (fqdn, ip)
            except Exception:
                return None

        with ThreadPoolExecutor(max_workers=50) as ex:
            futures = {ex.submit(check_sub, s): s for s in SUBDOMAIN_WORDLIST}
            for f in as_completed(futures):
                r = f.result()
                if r:
                    fqdn, ip = r
                    found(f"Subdomain: {fqdn} → {ip}")
                    rec = {"subdomain": fqdn, "ip": ip, "base": base_domain}
                    safe_add("subdomains", rec)
                    found_subs.append(fqdn)

        # Method B: crt.sh Certificate Transparency
        _crtsh_enum(base_domain)

        # Method C: DNS zone records
        _dns_records(base_domain)

    return found_subs

def _crtsh_enum(domain):
    """Query crt.sh for SSL certificate subdomains."""
    info(f"crt.sh certificate transparency lookup for {domain}")
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        r = SESSION.get(url, timeout=15)
        if r.status_code == 200:
            data = r.json()
            seen = set()
            for entry in data:
                names = entry.get('name_value','').split('\n')
                for name in names:
                    name = name.strip().lstrip('*.')
                    if domain in name and name not in seen:
                        seen.add(name)
                        try:
                            ip = socket.gethostbyname(name)
                            found(f"crt.sh: {name} → {ip}")
                            safe_add("subdomains", {"subdomain": name, "ip": ip, "source": "crt.sh"})
                            safe_add("ssl_certs", {
                                "domain": name,
                                "issuer": entry.get('issuer_name',''),
                                "logged": entry.get('entry_timestamp',''),
                            })
                        except Exception:
                            safe_add("subdomains", {"subdomain": name, "ip": None, "source": "crt.sh"})
            good(f"crt.sh found {len(seen)} certificate entries")
    except Exception as e:
        bad(f"crt.sh error: {e}")

def _dns_records(domain):
    """Pull all DNS record types."""
    info(f"DNS record enumeration for {domain}")
    record_types = ['A','AAAA','MX','NS','TXT','CNAME','SOA','SRV','CAA']
    dns_data = {}

    if HAS_DNSPYTHON:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 5
        for rtype in record_types:
            try:
                answers = resolver.resolve(domain, rtype)
                records = [str(r) for r in answers]
                dns_data[rtype] = records
                for rec in records:
                    good(f"DNS {rtype}: {rec}")
                    # Check for interesting TXT records
                    if rtype == 'TXT':
                        _analyse_txt_record(rec, domain)
            except Exception:
                pass
    else:
        # Fallback via socket
        try:
            ip = socket.gethostbyname(domain)
            dns_data['A'] = [ip]
            good(f"DNS A: {ip}")
        except Exception:
            pass

    safe_add("dns_records", {domain: dns_data})

def _analyse_txt_record(txt, domain):
    """Extract intelligence from TXT records."""
    txt_lower = txt.lower()
    # Google Workspace / G Suite verification
    if 'google-site-verification' in txt_lower:
        good(f"Google Workspace verified for {domain}")
        safe_add("google_workspace", {
            "domain": domain,
            "verified": True,
            "token": txt,
            "note": "Organisation uses Google Workspace (Gmail/Drive/Docs)"
        })
    if 'v=spf1' in txt_lower:
        good(f"SPF record: {txt}")
        # Check for cloud mail providers
        for provider in ['google','amazonses','sendgrid','mailchimp',
                         'mailgun','sparkpost','postmark','office365',
                         'protection.outlook']:
            if provider in txt_lower:
                good(f"Mail provider detected: {provider.upper()}")
                safe_add("technologies", {"type":"mail","provider":provider,"domain":domain})
        if 'include:_spf.google.com' in txt_lower:
            safe_add("google_workspace", {"domain": domain, "spf_google": True,
                "note": "Email flows through Google — likely Google Workspace"})
    if 'v=dmarc1' in txt_lower:
        good(f"DMARC record found — {txt}")
    if 'atlassian-domain-verification' in txt_lower:
        good(f"Atlassian (Jira/Confluence) account linked to {domain}")
        safe_add("technologies", {"type":"project","provider":"Atlassian","domain":domain})
    if 'docusign' in txt_lower:
        safe_add("technologies", {"type":"esign","provider":"DocuSign","domain":domain})
    if 'stripe' in txt_lower:
        safe_add("technologies", {"type":"payment","provider":"Stripe","domain":domain})
    if 'have-i-been-pwned' in txt_lower or 'hibp' in txt_lower:
        warn(f"HIBP verification token found — someone checked breaches for {domain}")
    if 'ms=' in txt_lower or 'microsoft' in txt_lower:
        good(f"Microsoft/O365 tenant linked to {domain}")
        safe_add("technologies", {"type":"mail","provider":"Microsoft365","domain":domain})
    if 'amazonses' in txt_lower or 'aws' in txt_lower:
        good(f"AWS SES email sending for {domain}")
        safe_add("technologies", {"type":"mail","provider":"AWS SES","domain":domain})
    if 'zoom' in txt_lower:
        safe_add("technologies", {"type":"video","provider":"Zoom","domain":domain})

# ══════════════════════════════════════════════════════════════════════════
# MODULE 3 — AWS S3 BUCKET DISCOVERY
# ══════════════════════════════════════════════════════════════════════════
def enumerate_aws_buckets(company, domains):
    section("MODULE 3 — AWS S3 BUCKET DISCOVERY")
    slug  = re.sub(r'[^a-z0-9\-]', '-', company.lower().strip()).strip('-')
    slug2 = re.sub(r'[^a-z0-9]', '', company.lower())

    # Generate bucket name candidates
    prefixes  = ['','backup','backups','dev','prod','staging','test','data',
                 'logs','assets','media','files','uploads','static','public',
                 'private','internal','archive','export','import','dump',
                 'database','db','config','configs','secret','secrets',
                 'credentials','creds','keys','tokens','terraform','infra',
                 'infrastructure','build','builds','releases','artifacts',
                 'docs','documents','reports','invoices','hr','finance',
                 'marketing','sales','engineering','security']
    suffixes  = ['','backup','backups','dev','prod','staging','test','data',
                 'bucket','store','storage','files','assets','-public',
                 '-private','-internal','2024','2023','2025','old','new']

    candidates = set()
    for pfx in prefixes:
        for sfx in suffixes:
            for base in [slug, slug2]:
                name = f"{pfx}-{base}{sfx}".strip('-')
                candidates.add(name)
                name2 = f"{base}-{pfx}{sfx}".strip('-')
                candidates.add(name2)
                name3 = f"{pfx}{base}{sfx}".strip('-')
                candidates.add(name3)

    # Also add domain-based names
    for d in domains[:3]:
        base = d.split('.')[0]
        candidates.update([base, f"{base}-backup", f"{base}-data",
                           f"{base}-assets", f"{base}-uploads"])

    candidates = {c for c in candidates if 3 <= len(c) <= 63
                  and re.match(r'^[a-z0-9][a-z0-9\-]*[a-z0-9]$', c)}

    info(f"Testing {len(candidates)} S3 bucket name candidates...")

    def check_bucket(name):
        results = []
        # Method 1: HTTP request to bucket URL
        urls = [
            f"https://{name}.s3.amazonaws.com",
            f"https://s3.amazonaws.com/{name}",
        ]
        for url in urls:
            try:
                r = SESSION.get(url, timeout=6, allow_redirects=True)
                status = r.status_code
                if status == 200:
                    results.append({
                        "bucket": name, "url": url,
                        "status": "PUBLIC ⚠ OPEN",
                        "severity": "CRITICAL",
                        "note": "Bucket is publicly listable!",
                        "size_hint": len(r.content)
                    })
                elif status == 403:
                    results.append({
                        "bucket": name, "url": url,
                        "status": "EXISTS (private)",
                        "severity": "INFO",
                        "note": "Bucket exists but access denied"
                    })
                elif status == 301:
                    results.append({
                        "bucket": name, "url": url,
                        "status": "EXISTS (redirect)",
                        "severity": "LOW",
                        "note": f"Redirects to: {r.headers.get('Location','?')}"
                    })
            except Exception:
                pass
        return results

    with ThreadPoolExecutor(max_workers=40) as ex:
        futures = {ex.submit(check_bucket, n): n for n in candidates}
        for f in as_completed(futures):
            items = f.result()
            for item in items:
                sev = item.get('severity','INFO')
                if sev == 'CRITICAL':
                    found(f"S3 OPEN: {item['bucket']} — {item['url']}")
                elif sev == 'INFO':
                    good(f"S3 exists: {item['bucket']}")
                safe_add("aws_buckets", item)

    open_count = len([b for b in RESULTS['aws_buckets'] if b.get('severity') == 'CRITICAL'])
    info(f"S3 scan complete — {len(RESULTS['aws_buckets'])} found, {open_count} OPEN")

# ══════════════════════════════════════════════════════════════════════════
# MODULE 4 — GCP & AZURE CLOUD STORAGE
# ══════════════════════════════════════════════════════════════════════════
def enumerate_cloud_storage(company):
    section("MODULE 4 — GCP & AZURE CLOUD STORAGE")
    slug  = re.sub(r'[^a-z0-9\-]', '-', company.lower().strip()).strip('-')
    slug2 = re.sub(r'[^a-z0-9]', '', company.lower())

    suffixes = ['','-backup','-data','-assets','-files','-public','-dev',
                '-prod','-staging','-static','-uploads','-media','-storage']

    # GCP buckets
    info("Checking Google Cloud Storage buckets...")
    for base in [slug, slug2]:
        for sfx in suffixes:
            name = f"{base}{sfx}".strip('-')
            if len(name) < 3: continue
            gcp_url = f"https://storage.googleapis.com/{name}"
            try:
                r = SESSION.get(gcp_url, timeout=5)
                if r.status_code == 200:
                    found(f"GCP OPEN BUCKET: {name}")
                    safe_add("gcp_buckets", {"bucket": name, "url": gcp_url,
                        "status": "PUBLIC ⚠ OPEN", "severity": "CRITICAL"})
                elif r.status_code == 403:
                    good(f"GCP bucket exists (private): {name}")
                    safe_add("gcp_buckets", {"bucket": name, "url": gcp_url,
                        "status": "EXISTS (private)", "severity": "INFO"})
            except Exception:
                pass

    # Azure Blob Storage
    info("Checking Azure Blob Storage containers...")
    for base in [slug, slug2]:
        for sfx in suffixes:
            name = re.sub(r'[^a-z0-9]','', f"{base}{sfx}")
            if len(name) < 3 or len(name) > 24: continue
            az_url = f"https://{name}.blob.core.windows.net"
            try:
                r = SESSION.get(az_url, timeout=5)
                if r.status_code in [200, 400, 409]:
                    good(f"Azure storage account exists: {name}")
                    safe_add("azure_blobs", {"account": name, "url": az_url,
                        "status": "EXISTS", "severity": "MEDIUM"})
                    # Try to list containers
                    list_url = f"{az_url}?comp=list"
                    r2 = SESSION.get(list_url, timeout=5)
                    if r2.status_code == 200 and '<Container>' in r2.text:
                        found(f"Azure OPEN containers at: {az_url}")
                        safe_add("azure_blobs", {"account": name, "url": list_url,
                            "status": "PUBLIC ⚠ OPEN", "severity": "CRITICAL",
                            "raw": r2.text[:500]})
            except Exception:
                pass

# ══════════════════════════════════════════════════════════════════════════
# MODULE 5 — GOOGLE WORKSPACE INTELLIGENCE
# ══════════════════════════════════════════════════════════════════════════
def enumerate_google_workspace(company, domains):
    section("MODULE 5 — GOOGLE WORKSPACE INTELLIGENCE")
    for domain in domains[:3]:
        info(f"Probing Google Workspace exposure for {domain}")

        # Check Google Workspace MX records
        mx_check_url = f"https://dns.google/resolve?name={domain}&type=MX"
        try:
            r = SESSION.get(mx_check_url, timeout=8)
            data = r.json()
            mx_records = [a.get('data','') for a in data.get('Answer',[])]
            for mx in mx_records:
                if 'google' in mx.lower() or 'googlemail' in mx.lower():
                    found(f"Google Workspace MX confirmed: {mx}")
                    safe_add("google_workspace", {
                        "domain": domain, "mx": mx,
                        "type": "Google Workspace (Gmail)",
                        "note": "All company email runs through Google"
                    })
                if 'outlook' in mx.lower() or 'protection.outlook' in mx.lower():
                    good(f"Microsoft 365 MX confirmed: {mx}")
                    safe_add("technologies", {"type":"mail","provider":"M365","domain":domain})
        except Exception:
            pass

        # Google Workspace login page probe
        try:
            r = SESSION.get(
                f"https://accounts.google.com/samlredirect?domain={domain}",
                timeout=8, allow_redirects=False)
            if r.status_code in [302, 200]:
                loc = r.headers.get('Location','')
                if 'google' in loc or 'gsuite' in loc or 'workspace' in loc:
                    good(f"Google SSO/SAML redirect active for {domain}")
                    safe_add("google_workspace", {"domain": domain,
                        "saml": True, "redirect": loc})
        except Exception:
            pass

        # Check for exposed Google Drive / Docs
        google_dorks_gws = [
            f'site:drive.google.com "{company}"',
            f'site:docs.google.com "{company}"',
            f'site:sheets.google.com "{company}"',
            f'site:slides.google.com "{company}"',
            f'site:forms.google.com "{company}"',
        ]
        for dork in google_dorks_gws:
            safe_add("google_dorks", {
                "dork": dork,
                "url": f"https://www.google.com/search?q={quote(dork)}",
                "type": "Google Workspace exposure",
                "note": "Manually check for publicly shared docs/sheets"
            })
            info(f"Google Dork queued: {dork}")

        # Check Google Workspace admin panel
        admin_urls = [
            f"https://admin.{domain}",
            f"https://mail.{domain}",
            f"https://calendar.{domain}",
        ]
        for url in admin_urls:
            try:
                r = SESSION.get(url, timeout=5, allow_redirects=True)
                final = r.url
                if 'accounts.google.com' in final or 'workspace.google' in final:
                    good(f"GWS admin/mail portal: {url} → {final}")
                    safe_add("google_workspace", {"url": url, "redirects_to": final})
            except Exception:
                pass

# ══════════════════════════════════════════════════════════════════════════
# MODULE 6 — GITHUB LEAK DETECTION
# ══════════════════════════════════════════════════════════════════════════
GITHUB_SECRET_PATTERNS = [
    (r'aws_access_key_id\s*[=:]\s*["\']?([A-Z0-9]{20})',       'AWS Access Key ID'),
    (r'aws_secret_access_key\s*[=:]\s*["\']?([A-Za-z0-9/+]{40})','AWS Secret Key'),
    (r'AKIA[0-9A-Z]{16}',                                        'AWS Key (raw)'),
    (r'["\']?api[_\-]?key["\']?\s*[=:]\s*["\']([A-Za-z0-9_\-]{20,})', 'API Key'),
    (r'["\']?secret["\']?\s*[=:]\s*["\']([A-Za-z0-9_\-]{16,})', 'Secret'),
    (r'["\']?password["\']?\s*[=:]\s*["\']([^"\']{8,})',         'Password'),
    (r'["\']?token["\']?\s*[=:]\s*["\']([A-Za-z0-9_\-\.]{20,})', 'Token'),
    (r'BEGIN\s+(?:RSA|DSA|EC|OPENSSH)\s+PRIVATE\s+KEY',          'Private Key'),
    (r'mongodb(\+srv)?://[^"\s]+',                                'MongoDB URI'),
    (r'postgres://[^"\s]+',                                       'PostgreSQL URI'),
    (r'mysql://[^"\s]+',                                          'MySQL URI'),
    (r'redis://[^"\s]+',                                          'Redis URI'),
    (r'[A-Za-z0-9_\-]{24}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27}', 'Discord Token'),
    (r'ghp_[A-Za-z0-9]{36}',                                     'GitHub PAT'),
    (r'gho_[A-Za-z0-9]{36}',                                     'GitHub OAuth Token'),
    (r'AIza[0-9A-Za-z\-_]{35}',                                  'Google API Key'),
    (r'ya29\.[0-9A-Za-z\-_]+',                                   'Google OAuth Token'),
    (r'sk-[A-Za-z0-9]{48}',                                      'OpenAI API Key'),
    (r'xox[baprs]-[A-Za-z0-9\-]+',                               'Slack Token'),
    (r'EAACEdEose0cBA[0-9A-Za-z]+',                               'Facebook Token'),
    (r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',   'Google OAuth Client'),
    (r'-----BEGIN\s+CERTIFICATE-----',                            'SSL Certificate'),
    (r'jdbc:[a-z]+://[^\s"\']+',                                  'JDBC Connection String'),
]

def github_recon(company, domains, github_token=None):
    section("MODULE 6 — GITHUB LEAK DETECTION")
    slug = re.sub(r'\s+', '', company.lower())
    headers = {'Accept': 'application/vnd.github.v3+json'}
    if github_token:
        headers['Authorization'] = f"token {github_token}"
        good("Using GitHub token — higher rate limits")
    else:
        warn("No GitHub token — limited to 10 req/min. Use --github-token")

    base = "https://api.github.com"

    # Search for org/user accounts
    info(f"Searching GitHub for org: {company}")
    try:
        r = SESSION.get(f"{base}/search/users?q={quote(company)}+type:org",
                        headers=headers, timeout=10)
        if r.status_code == 200:
            for item in r.json().get('items', [])[:5]:
                login = item['login']
                good(f"GitHub org found: {login} — {item.get('html_url')}")
                safe_add("github_leaks", {
                    "type": "org", "login": login,
                    "url": item.get('html_url'),
                    "note": "Check all public repos for secrets"
                })
                # List repos
                _github_scan_org(login, headers)
        if r.status_code == 403:
            warn("GitHub rate limit hit — add --github-token for more requests")
    except Exception as e:
        bad(f"GitHub org search error: {e}")

    # Code search for secrets
    search_queries = [
        f'"{company}" password',
        f'"{company}" api_key',
        f'"{company}" secret',
        f'"{company}" aws_access_key',
        f'"{company}" db_password',
        f'"{company}" private_key',
    ]
    for domain in domains[:2]:
        search_queries += [
            f'"{domain}" password',
            f'"{domain}" api_key',
            f'"{domain}" secret',
        ]

    for query in search_queries[:8]:
        try:
            r = SESSION.get(
                f"{base}/search/code?q={quote(query)}&per_page=5",
                headers=headers, timeout=10)
            if r.status_code == 200:
                items = r.json().get('items', [])
                for item in items:
                    repo = item.get('repository', {})
                    file_url = item.get('html_url','')
                    found(f"GitHub code leak: {repo.get('full_name')} → {item.get('name')}")
                    safe_add("github_leaks", {
                        "type": "code_search",
                        "query": query,
                        "repo": repo.get('full_name'),
                        "file": item.get('name'),
                        "url": file_url,
                        "severity": "HIGH",
                        "note": f"Manually review for exposed secrets"
                    })
            time.sleep(1.2)  # Rate limit
        except Exception as e:
            bad(f"GitHub code search error: {e}")

def _github_scan_org(org_login, headers):
    """Scan org repos for secrets in file names."""
    base = "https://api.github.com"
    interesting_files = [
        '.env', '.env.prod', '.env.production', '.env.local',
        'config.json', 'config.yml', 'secrets.yml', 'credentials.json',
        'terraform.tfvars', 'terraform.tfstate', '.aws/credentials',
        'docker-compose.yml', 'kubeconfig', '.kube/config',
        'private.key', 'id_rsa', 'server.key', 'cert.pem',
        'database.yml', 'settings.py', 'application.properties',
    ]
    try:
        r = SESSION.get(f"{base}/orgs/{org_login}/repos?per_page=30&sort=updated",
                        headers=headers, timeout=10)
        if r.status_code == 200:
            repos = r.json()
            info(f"Found {len(repos)} public repos for {org_login}")
            for repo in repos[:10]:
                repo_name = repo.get('name','')
                # Check for interesting file names
                for fname in interesting_files[:5]:
                    try:
                        check_url = (f"{base}/repos/{org_login}/{repo_name}"
                                     f"/contents/{fname}")
                        r2 = SESSION.get(check_url, headers=headers, timeout=5)
                        if r2.status_code == 200:
                            found(f"Sensitive file in repo: {org_login}/{repo_name}/{fname}")
                            safe_add("github_leaks", {
                                "type": "sensitive_file",
                                "org": org_login,
                                "repo": repo_name,
                                "file": fname,
                                "url": f"https://github.com/{org_login}/{repo_name}/blob/main/{fname}",
                                "severity": "CRITICAL",
                                "note": f"Sensitive config file publicly accessible!"
                            })
                        time.sleep(0.3)
                    except Exception:
                        pass
    except Exception as e:
        bad(f"Org repo scan error: {e}")

# ══════════════════════════════════════════════════════════════════════════
# MODULE 7 — EMAIL HARVESTING
# ══════════════════════════════════════════════════════════════════════════
EMAIL_PATTERN = re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')

EMAIL_FORMATS = [
    "{first}.{last}",
    "{first}{last}",
    "{f}{last}",
    "{first}",
    "{last}",
    "{first}_{last}",
    "{first}-{last}",
    "{f}.{last}",
    "{last}.{first}",
    "{last}{f}",
]

def harvest_emails(company, domains):
    section("MODULE 7 — EMAIL HARVESTING")
    found_emails = set()

    for domain in domains[:3]:
        # Hunter.io style (free endpoint)
        info(f"Hunting emails for {domain}")

        # Method: scrape from search results (Bing - less rate limited)
        search_queries = [
            f'site:{domain} email OR contact',
            f'"{domain}" filetype:pdf OR filetype:xlsx contact',
            f'intext:"@{domain}" -site:{domain}',
        ]
        for q in search_queries:
            safe_add("google_dorks", {
                "dork": q,
                "url": f"https://www.google.com/search?q={quote(q)}",
                "type": "Email harvesting",
                "note": f"May reveal @{domain} email addresses"
            })

        # Method: check common email-revealing pages
        email_pages = [
            f"https://{domain}/contact",
            f"https://{domain}/team",
            f"https://{domain}/about",
            f"https://{domain}/about-us",
            f"https://{domain}/people",
            f"https://www.{domain}/contact",
        ]
        for page_url in email_pages:
            try:
                r = SESSION.get(page_url, timeout=8)
                emails = EMAIL_PATTERN.findall(r.text)
                for email in emails:
                    if domain in email:
                        found_emails.add(email)
                        found(f"Email found: {email}")
                        safe_add("emails", {"email": email, "source": page_url, "domain": domain})
            except Exception:
                pass

        # Derive email pattern from found examples
        if found_emails:
            info("Detected email pattern — generating employee list format")
            sample = list(found_emails)[0]
            user_part = sample.split('@')[0]
            if '.' in user_part:
                pattern = "{first}.{last}@" + domain
            elif len(user_part) <= 6:
                pattern = "{f}{last}@" + domain
            else:
                pattern = "{first}{last}@" + domain
            good(f"Likely email format: {pattern}")
            safe_add("emails", {"type": "pattern", "pattern": pattern, "domain": domain})

    return list(found_emails)

# ══════════════════════════════════════════════════════════════════════════
# MODULE 8 — GOOGLE DORKS
# ══════════════════════════════════════════════════════════════════════════
def generate_google_dorks(company, domains):
    section("MODULE 8 — GOOGLE DORKS GENERATION")
    slug = company.replace(' ', '+')
    domain = domains[0] if domains else f"{company.lower().replace(' ','')}.com"

    dork_categories = {
        "🔐 Credentials & Secrets": [
            f'site:{domain} ext:env OR ext:cfg OR ext:conf password',
            f'site:{domain} intext:"DB_PASSWORD" OR intext:"DB_USER"',
            f'site:{domain} intext:"api_key" OR intext:"secret_key"',
            f'site:github.com "{company}" password OR secret OR api_key',
            f'site:gitlab.com "{company}" password OR secret',
            f'site:pastebin.com "{company}" password OR secret',
            f'site:trello.com "{company}" password',
            f'"{domain}" filetype:env',
            f'"{domain}" filetype:config',
        ],
        "📄 Exposed Documents": [
            f'site:{domain} filetype:pdf OR filetype:docx OR filetype:xlsx',
            f'site:{domain} filetype:xlsx "confidential" OR "internal"',
            f'site:{domain} filetype:pdf "invoice" OR "contract" OR "agreement"',
            f'"{company}" filetype:pptx site:slideshare.net',
            f'site:{domain} intitle:"index of" OR intitle:"Directory listing"',
            f'site:{domain} "not for public release" OR "internal use only"',
        ],
        "☁ Cloud & Infrastructure": [
            f'site:s3.amazonaws.com "{company}"',
            f'site:blob.core.windows.net "{company}"',
            f'site:storage.googleapis.com "{company}"',
            f'"{company}" site:s3.amazonaws.com',
            f'site:{domain} inurl:admin OR inurl:dashboard OR inurl:panel',
            f'site:{domain} inurl:jenkins OR inurl:gitlab OR inurl:jira',
        ],
        "👤 Employee & PII": [
            f'site:linkedin.com/in "{company}"',
            f'"{domain}" site:hunter.io',
            f'"{company}" site:rocketreach.co',
            f'"{domain}" "email" site:pastebin.com',
            f'intext:"@{domain}" site:github.com',
            f'"{company}" employees site:linkedin.com',
        ],
        "🔓 Login Pages & Admin": [
            f'site:{domain} inurl:login OR inurl:signin OR inurl:admin',
            f'site:{domain} inurl:wp-admin OR inurl:phpmyadmin',
            f'site:{domain} intext:"Powered by" inurl:admin',
            f'site:{domain} intitle:"Dashboard" OR intitle:"Control Panel"',
        ],
        "📊 Leaked Data": [
            f'"{company}" site:pastebin.com',
            f'"{company}" site:ghostbin.com',
            f'"{company}" site:hastebin.com',
            f'"{domain}" dump OR leak OR breach',
            f'"{company}" confidential filetype:pdf -site:{domain}',
        ],
        "🔧 Tech Stack": [
            f'site:{domain} intext:"Powered by" OR intext:"Built with"',
            f'site:{domain} intext:"Laravel" OR intext:"Django" OR intext:"Rails"',
            f'site:{domain} inurl:graphql OR inurl:swagger OR inurl:api-docs',
            f'site:{domain} "X-Powered-By"',
        ],
    }

    total = 0
    for category, dorks in dork_categories.items():
        good(f"{category}: {len(dorks)} dorks")
        for dork in dorks:
            total += 1
            safe_add("google_dorks", {
                "dork": dork,
                "url": f"https://www.google.com/search?q={quote(dork)}",
                "category": category,
            })
    info(f"Generated {total} Google dorks across {len(dork_categories)} categories")

# ══════════════════════════════════════════════════════════════════════════
# MODULE 9 — TECHNOLOGY FINGERPRINTING
# ══════════════════════════════════════════════════════════════════════════
TECH_SIGNATURES = {
    "WordPress":      [('header','X-Powered-By','wordpress'), ('body','wp-content'), ('body','wp-includes')],
    "Shopify":        [('body','cdn.shopify.com'), ('header','X-ShopId','')],
    "Cloudflare":     [('header','CF-Ray',''), ('header','Server','cloudflare')],
    "AWS CloudFront": [('header','X-Amz-Cf-Id',''), ('header','Via','CloudFront')],
    "Nginx":          [('header','Server','nginx')],
    "Apache":         [('header','Server','apache')],
    "React":          [('body','__REACT_'), ('body','react-root'), ('body','data-reactroot')],
    "Next.js":        [('body','__NEXT_DATA__'), ('body','_next/static')],
    "Vue.js":         [('body','__vue__'), ('body','data-v-')],
    "Angular":        [('body','ng-version'), ('body','angular.min.js')],
    "jQuery":         [('body','jquery.min.js'), ('body','jQuery')],
    "Bootstrap":      [('body','bootstrap.min.css'), ('body','bootstrap.min.js')],
    "Google Analytics":[('body','google-analytics.com/analytics.js'), ('body','gtag(')],
    "Google Tag Mgr": [('body','googletagmanager.com/gtm.js')],
    "HubSpot":        [('body','js.hs-scripts.com'), ('body','hubspot')],
    "Salesforce":     [('body','salesforce.com'), ('body','force.com')],
    "Zendesk":        [('body','zendesk.com'), ('body','zopim')],
    "Intercom":       [('body','intercom.io'), ('body','intercomSettings')],
    "Stripe":         [('body','js.stripe.com'), ('body','Stripe(')],
    "Sentry":         [('body','browser.sentry-cdn.com'), ('body','Sentry.init')],
    "Datadog":        [('body','datadoghq.com')],
    "New Relic":      [('body','newrelic.com'), ('body','NREUM')],
    "Laravel":        [('header','Set-Cookie','laravel_session')],
    "Django":         [('header','Set-Cookie','csrftoken'), ('body','csrfmiddlewaretoken')],
    "Ruby on Rails":  [('header','X-Powered-By','Phusion Passenger')],
    "ASP.NET":        [('header','X-Powered-By','ASP.NET'), ('header','X-AspNet-Version','')],
    "PHP":            [('header','X-Powered-By','PHP')],
}

def fingerprint_tech(domains):
    section("MODULE 9 — TECHNOLOGY STACK FINGERPRINTING")
    for domain in domains[:3]:
        url = f"https://{domain}"
        info(f"Fingerprinting: {url}")
        try:
            r = SESSION.get(url, timeout=10)
            headers = {k.lower(): v.lower() for k,v in r.headers.items()}
            body = r.text.lower()

            detected = []
            for tech, sigs in TECH_SIGNATURES.items():
                for sig_type, sig_key, sig_val in sigs:
                    if sig_type == 'header':
                        hval = headers.get(sig_key.lower(), '')
                        if sig_val.lower() in hval or (sig_val == '' and sig_key.lower() in headers):
                            detected.append(tech)
                            break
                    elif sig_type == 'body':
                        if sig_key.lower() in body:
                            detected.append(tech)
                            break

            for tech in set(detected):
                good(f"Tech detected: {tech} on {domain}")
                safe_add("technologies", {"domain": domain, "technology": tech})

            # Check security headers
            security_headers = [
                'strict-transport-security', 'content-security-policy',
                'x-frame-options', 'x-content-type-options',
                'referrer-policy', 'permissions-policy'
            ]
            missing = [h for h in security_headers if h not in headers]
            if missing:
                warn(f"Missing security headers on {domain}: {', '.join(missing)}")
                safe_add("vulnerabilities", {
                    "domain": domain,
                    "type": "Missing Security Headers",
                    "missing": missing,
                    "severity": "LOW"
                })

            # Check for interesting response headers
            interesting = ['server','x-powered-by','x-generator','x-drupal-cache',
                           'x-wp-total','x-magento-version']
            for h in interesting:
                if h in headers:
                    good(f"Header leak: {h}: {headers[h]}")
                    safe_add("technologies", {"header": h, "value": headers[h], "domain": domain})

        except Exception as e:
            bad(f"Fingerprint error for {domain}: {e}")

# ══════════════════════════════════════════════════════════════════════════
# MODULE 10 — WHOIS & DOMAIN INTEL
# ══════════════════════════════════════════════════════════════════════════
def whois_lookup(domains):
    section("MODULE 10 — WHOIS & DOMAIN INTELLIGENCE")
    for domain in domains[:5]:
        info(f"WHOIS lookup: {domain}")
        # Use RDAP (modern WHOIS replacement)
        try:
            tld = domain.split('.')[-1]
            rdap_urls = [
                f"https://rdap.org/domain/{domain}",
                f"https://rdap.verisign.com/com/v1/domain/{domain}",
                f"https://rdap.iana.org/domain/{domain}",
            ]
            for rdap_url in rdap_urls:
                try:
                    r = SESSION.get(rdap_url, timeout=10)
                    if r.status_code == 200:
                        data = r.json()
                        registrar = ''
                        registrant = ''
                        created = ''
                        expires = ''

                        for entity in data.get('entities', []):
                            roles = entity.get('roles', [])
                            vcard = entity.get('vcardArray', [None, []])[1]
                            name = next((v[3] for v in vcard if v[0]=='fn'), '') if vcard else ''
                            if 'registrar' in roles:
                                registrar = name
                            if 'registrant' in roles:
                                registrant = name

                        for event in data.get('events', []):
                            if event.get('eventAction') == 'registration':
                                created = event.get('eventDate','')
                            if event.get('eventAction') == 'expiration':
                                expires = event.get('eventDate','')

                        good(f"WHOIS {domain}: Registrar={registrar}, Created={created[:10]}, Expires={expires[:10]}")
                        safe_add("whois", {
                            domain: {
                                "registrar": registrar,
                                "registrant": registrant,
                                "created": created,
                                "expires": expires,
                                "nameservers": [ns.get('ldhName','') for ns in data.get('nameservers',[])],
                                "status": data.get('status',[]),
                            }
                        })

                        # Check nameservers for cloud DNS
                        ns_list = [ns.get('ldhName','').lower() for ns in data.get('nameservers',[])]
                        for ns in ns_list:
                            if 'aws' in ns or 'amazon' in ns or 'route53' in ns:
                                good(f"Route53 DNS detected for {domain}")
                                safe_add("technologies", {"domain":domain,"dns":"AWS Route53"})
                            if 'cloudflare' in ns:
                                good(f"Cloudflare DNS detected for {domain}")
                                safe_add("technologies", {"domain":domain,"dns":"Cloudflare"})
                            if 'google' in ns:
                                good(f"Google Cloud DNS for {domain}")
                                safe_add("technologies", {"domain":domain,"dns":"Google Cloud DNS"})
                        break
                except Exception:
                    continue
        except Exception as e:
            bad(f"WHOIS error for {domain}: {e}")

# ══════════════════════════════════════════════════════════════════════════
# MODULE 11 — PASTEBIN / LEAK SITES
# ══════════════════════════════════════════════════════════════════════════
def check_paste_leaks(company, domains):
    section("MODULE 11 — PASTE & LEAK SITE DETECTION")
    slug = company.replace(' ', '+')

    paste_dorks = []
    for domain in domains[:2]:
        paste_dorks += [
            f'site:pastebin.com "{domain}"',
            f'site:pastebin.com "{company}" password',
            f'site:ghostbin.com "{domain}"',
            f'site:hastebin.com "{domain}"',
            f'site:controlc.com "{domain}"',
            f'site:paste.ee "{domain}"',
            f'site:dpaste.com "{domain}"',
            f'site:gist.github.com "{domain}"',
            f'site:gist.github.com "{company}" secret OR password OR key',
        ]

    for dork in paste_dorks:
        safe_add("google_dorks", {
            "dork": dork,
            "url": f"https://www.google.com/search?q={quote(dork)}",
            "category": "📊 Leaked Data / Pastes",
            "note": "Check manually for credentials, dumps, breach data"
        })
    good(f"Generated {len(paste_dorks)} paste-site dorks")

    # Try direct search on psbdmp (pastebin search)
    try:
        for domain in domains[:1]:
            r = SESSION.get(f"https://psbdmp.ws/api/search/{domain}", timeout=8)
            if r.status_code == 200:
                data = r.json()
                pastes = data.get('data', [])
                if pastes:
                    found(f"psbdmp found {len(pastes)} pastes mentioning {domain}!")
                    for paste in pastes[:10]:
                        safe_add("pastes", {
                            "site": "pastebin",
                            "id": paste.get('id'),
                            "url": f"https://pastebin.com/{paste.get('id')}",
                            "date": paste.get('time'),
                            "note": "Manually review for leaked credentials"
                        })
    except Exception:
        pass

# ══════════════════════════════════════════════════════════════════════════
# MODULE 12 — SHODAN / INTERNET EXPOSURE
# ══════════════════════════════════════════════════════════════════════════
def shodan_recon(company, domains, shodan_key=None):
    section("MODULE 12 — INTERNET EXPOSURE (Shodan/Censys)")

    if not shodan_key:
        warn("No Shodan API key — generating dorks only. Use --shodan-key")
        safe_add("google_dorks", {
            "dork": f'org:"{company}"',
            "url": f"https://www.shodan.io/search?query=org%3A%22{quote(company)}%22",
            "category": "🌐 Shodan Search",
            "note": "Find all internet-exposed assets for this org"
        })
        for domain in domains[:3]:
            safe_add("google_dorks", {
                "dork": f"hostname:{domain}",
                "url": f"https://www.shodan.io/search?query=hostname%3A{domain}",
                "category": "🌐 Shodan Search",
                "note": f"All exposed services on {domain}"
            })
            # Censys (also needs key but has free tier)
            safe_add("google_dorks", {
                "dork": f"parsed.names: {domain}",
                "url": f"https://search.censys.io/certificates?q=parsed.names%3A+{domain}",
                "category": "🌐 Censys SSL Search",
                "note": "SSL cert transparency for all IPs"
            })
        return

    # If Shodan key provided
    info("Querying Shodan API...")
    try:
        for domain in domains[:3]:
            r = SESSION.get(
                f"https://api.shodan.io/shodan/host/search"
                f"?key={shodan_key}&query=hostname:{domain}",
                timeout=12)
            if r.status_code == 200:
                data = r.json()
                for match in data.get('matches', []):
                    ip   = match.get('ip_str')
                    port = match.get('port')
                    prod = match.get('product','')
                    vulns= match.get('vulns', {})
                    found(f"Shodan: {ip}:{port} {prod}")
                    safe_add("shodan", {
                        "ip": ip, "port": port,
                        "product": prod,
                        "org": match.get('org',''),
                        "os": match.get('os',''),
                        "vulns": list(vulns.keys()),
                    })
                    for cve in vulns:
                        found(f"CVE via Shodan: {cve} on {ip}:{port}")
                        safe_add("vulnerabilities", {
                            "cve": cve, "ip": ip, "port": port,
                            "severity": "HIGH",
                            "source": "Shodan"
                        })
    except Exception as e:
        bad(f"Shodan error: {e}")

# ══════════════════════════════════════════════════════════════════════════
# MODULE 13 — BREACH CHECK
# ══════════════════════════════════════════════════════════════════════════
def check_breaches(domains, hibp_key=None):
    section("MODULE 13 — BREACH INTELLIGENCE")
    if not hibp_key:
        warn("No HIBP API key — generating manual check links. Use --hibp-key")
        for domain in domains[:3]:
            safe_add("breaches", {
                "domain": domain,
                "check_url": f"https://haveibeenpwned.com/DomainSearch/{domain}",
                "note": "Requires HIBP API key or manual check",
                "dehashed_url": f"https://dehashed.com/search?query={domain}",
            })
            safe_add("google_dorks", {
                "dork": f'"{domain}" site:haveibeenpwned.com',
                "url": f"https://haveibeenpwned.com/DomainSearch/{domain}",
                "category": "🔓 Breach Data",
                "note": "Check if domain appears in known data breaches"
            })
        return

    headers = {'hibp-api-key': hibp_key, 'user-agent': 'GhostRecon-OSINT'}
    for domain in domains[:3]:
        try:
            r = SESSION.get(
                f"https://haveibeenpwned.com/api/v3/breacheddomain/{domain}",
                headers=headers, timeout=10)
            if r.status_code == 200:
                breaches = r.json()
                found(f"HIBP: {domain} found in {len(breaches)} breaches!")
                for name, details in breaches.items():
                    safe_add("breaches", {
                        "domain": domain,
                        "breach": name,
                        "compromised": details,
                        "severity": "CRITICAL" if 'Passwords' in details else "HIGH",
                    })
            elif r.status_code == 404:
                good(f"HIBP: No breaches for {domain}")
        except Exception as e:
            bad(f"HIBP error: {e}")
        time.sleep(1.5)

# ══════════════════════════════════════════════════════════════════════════
# MODULE 14 — LINKEDIN / EMPLOYEE ENUM
# ══════════════════════════════════════════════════════════════════════════
def enumerate_employees(company, domains):
    section("MODULE 14 — EMPLOYEE & LINKEDIN ENUMERATION")
    domain = domains[0] if domains else ""

    dorks = [
        f'site:linkedin.com/in "{company}"',
        f'site:linkedin.com/in "{company}" engineer',
        f'site:linkedin.com/in "{company}" developer',
        f'site:linkedin.com/in "{company}" security',
        f'site:linkedin.com/in "{company}" devops',
        f'site:linkedin.com/in "{company}" "cloud"',
        f'site:linkedin.com/in "{company}" CTO OR CEO OR CISO',
        f'site:linkedin.com/company "{company}"',
        f'"{company}" site:xing.com',
    ]

    for dork in dorks:
        safe_add("google_dorks", {
            "dork": dork,
            "url": f"https://www.google.com/search?q={quote(dork)}",
            "category": "👤 Employee Enumeration",
            "note": "Reveals employee names → generate email list"
        })

    # Try to scrape LinkedIn company page employee count
    try:
        slug = company.lower().replace(' ','-')
        r = SESSION.get(f"https://www.linkedin.com/company/{slug}",
                        timeout=8, allow_redirects=True)
        if r.status_code == 200 and HAS_BS4:
            soup = BeautifulSoup(r.text, 'html.parser')
            emp_tag = soup.find(string=re.compile(r'\d+\s+employees'))
            if emp_tag:
                found(f"LinkedIn employee count: {emp_tag.strip()}")
                safe_add("employees", {"source":"linkedin","count":emp_tag.strip()})
    except Exception:
        pass

    good(f"Generated {len(dorks)} LinkedIn/employee dorks")
    info("TIP: Use linkedin2username tool to generate email lists from LinkedIn results")

# ══════════════════════════════════════════════════════════════════════════
# REPORT GENERATOR
# ══════════════════════════════════════════════════════════════════════════
def generate_report(company, output_dir='.'):
    section("GENERATING REPORTS")
    ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    safe_name = re.sub(r'[^a-z0-9]','_', company.lower())
    base = os.path.join(output_dir, f"ghostrecon_{safe_name}_{ts}")

    # ── JSON report ──
    json_path = base + '.json'
    RESULTS['meta'] = {
        "company": company,
        "generated": datetime.datetime.now().isoformat(),
        "tool": "GhostRecon v1.0",
        "summary": {
            "domains":      len(RESULTS['domains']),
            "subdomains":   len(RESULTS['subdomains']),
            "emails":       len(RESULTS['emails']),
            "aws_buckets":  len(RESULTS['aws_buckets']),
            "gcp_buckets":  len(RESULTS['gcp_buckets']),
            "azure_blobs":  len(RESULTS['azure_blobs']),
            "github_leaks": len(RESULTS['github_leaks']),
            "google_dorks": len(RESULTS['google_dorks']),
            "technologies": len(RESULTS['technologies']),
            "breaches":     len(RESULTS['breaches']),
            "pastes":       len(RESULTS['pastes']),
            "vulnerabilities": len(RESULTS['vulnerabilities']),
        }
    }
    with open(json_path, 'w') as f:
        json.dump(RESULTS, f, indent=2, default=str)
    good(f"JSON report: {json_path}")

    # ── HTML report ──
    html_path = base + '.html'
    _write_html_report(html_path, company)
    good(f"HTML report: {html_path}")

    # ── Text summary ──
    txt_path = base + '_summary.txt'
    _write_text_report(txt_path, company)
    good(f"Text summary: {txt_path}")

    return json_path, html_path

def _write_text_report(path, company):
    lines = [
        "═"*65,
        f" GhostRecon OSINT Report — {company}",
        f" Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}",
        "═"*65, "",
        "SUMMARY",
        "─"*40,
    ]
    s = RESULTS['meta'].get('summary', {})
    for k,v in s.items():
        lines.append(f"  {k:<22}: {v}")
    lines += ["", "DOMAINS", "─"*40]
    for d in RESULTS['domains']:
        lines.append(f"  {d.get('domain')} → {d.get('ip')}")
    lines += ["", "SUBDOMAINS", "─"*40]
    for s in RESULTS['subdomains'][:30]:
        lines.append(f"  {s.get('subdomain')} → {s.get('ip','?')}")
    lines += ["", "EMAILS", "─"*40]
    for e in RESULTS['emails']:
        if isinstance(e, dict):
            lines.append(f"  {e.get('email') or e.get('pattern')}")
        else:
            lines.append(f"  {e}")
    lines += ["", "AWS S3 BUCKETS", "─"*40]
    for b in RESULTS['aws_buckets']:
        lines.append(f"  [{b.get('severity','?')}] {b.get('bucket')} — {b.get('status')}")
    lines += ["", "GITHUB LEAKS", "─"*40]
    for g in RESULTS['github_leaks']:
        lines.append(f"  [{g.get('severity','INFO')}] {g.get('type')} — {g.get('url')}")
    lines += ["", "GOOGLE WORKSPACE", "─"*40]
    for k,v in RESULTS['google_workspace'].items():
        lines.append(f"  {k}: {v}")
    lines += ["", "TECHNOLOGIES DETECTED", "─"*40]
    for t in RESULTS['technologies']:
        lines.append(f"  {t}")
    lines += ["", "VULNERABILITIES", "─"*40]
    for v in RESULTS['vulnerabilities']:
        lines.append(f"  [{v.get('severity','?')}] {v.get('type') or v.get('cve')} — {v.get('domain') or v.get('ip')}")
    lines += ["", "GOOGLE DORKS (top 20)", "─"*40]
    for d in RESULTS['google_dorks'][:20]:
        lines.append(f"  [{d.get('category','?')}]")
        lines.append(f"  {d.get('dork')}")
        lines.append(f"  {d.get('url')}")
        lines.append("")
    lines += ["═"*65, " END OF REPORT", "═"*65]
    with open(path, 'w') as f:
        f.write('\n'.join(lines))

def _write_html_report(path, company):
    """Generate a rich HTML report."""
    s = RESULTS['meta'].get('summary', {})
    critical = len([b for b in RESULTS['aws_buckets'] if b.get('severity')=='CRITICAL'])
    critical += len([g for g in RESULTS['github_leaks'] if g.get('severity')=='CRITICAL'])

    def section_html(title, items, fields):
        if not items: return ''
        rows = ''
        for item in items:
            if isinstance(item, dict):
                cells = ''.join(f"<td>{str(item.get(f,''))[:200]}</td>" for f in fields)
            else:
                cells = f"<td colspan='{len(fields)}'>{str(item)[:200]}</td>"
            rows += f"<tr>{cells}</tr>"
        headers = ''.join(f"<th>{f.upper()}</th>" for f in fields)
        return f"""
        <div class="section">
          <h2>{title} <span class="badge">{len(items)}</span></h2>
          <table><thead><tr>{headers}</tr></thead><tbody>{rows}</tbody></table>
        </div>"""

    # Build dorks table
    dorks_html = ''
    by_cat = {}
    for d in RESULTS['google_dorks']:
        cat = d.get('category','Other')
        by_cat.setdefault(cat, []).append(d)
    for cat, dorks in by_cat.items():
        dorks_html += f"<h3>{cat}</h3>"
        for d in dorks:
            url = d.get('url','')
            dork = d.get('dork','')
            note = d.get('note','')
            dorks_html += f"""<div class="dork">
              <a href="{url}" target="_blank">{dork}</a>
              {f'<span class="note">{note}</span>' if note else ''}
            </div>"""

    html = f"""<!DOCTYPE html>
<html><head>
<meta charset="UTF-8">
<title>GhostRecon — {company}</title>
<style>
  body{{font-family:'Courier New',monospace;background:#0a0c0f;color:#c8d8e8;margin:0;padding:20px;}}
  h1{{color:#00ff88;font-size:28px;border-bottom:1px solid #1e2a38;padding-bottom:12px;}}
  h2{{color:#38bdf8;font-size:16px;margin-top:28px;}}
  h3{{color:#ffd060;font-size:13px;margin:14px 0 6px;}}
  .meta{{color:#4a6070;font-size:13px;margin-bottom:24px;}}
  .stats{{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:12px;margin:20px 0;}}
  .stat{{background:#0f1318;border:1px solid #1e2a38;border-radius:4px;padding:14px;text-align:center;}}
  .stat .num{{font-size:32px;font-weight:bold;color:#00ff88;}}
  .stat .num.red{{color:#ff4560;}}
  .stat .lbl{{font-size:10px;color:#4a6070;letter-spacing:2px;margin-top:4px;}}
  .section{{background:#0f1318;border:1px solid #1e2a38;border-radius:4px;padding:16px;margin:16px 0;}}
  table{{width:100%;border-collapse:collapse;font-size:12px;}}
  th{{background:#151b24;color:#38bdf8;padding:8px;text-align:left;border-bottom:1px solid #1e2a38;}}
  td{{padding:6px 8px;border-bottom:1px solid #0f1318;word-break:break-all;}}
  tr:hover td{{background:#151b24;}}
  .badge{{background:#151b24;color:#4a6070;font-size:11px;padding:2px 8px;border-radius:12px;margin-left:8px;}}
  .critical{{color:#ff0055;font-weight:bold;}}
  .high{{color:#ff4560;}}
  .medium{{color:#ffd060;}}
  .low{{color:#38bdf8;}}
  .dork{{background:#0a0c0f;border:1px solid #1e2a38;border-radius:3px;padding:8px 12px;margin:4px 0;font-size:12px;}}
  .dork a{{color:#00ff88;text-decoration:none;}}
  .dork a:hover{{text-decoration:underline;}}
  .note{{display:block;color:#4a6070;font-size:11px;margin-top:3px;}}
  .warn{{background:rgba(255,208,96,.08);border:1px solid rgba(255,208,96,.3);border-radius:4px;padding:10px 14px;color:#ffd060;margin:12px 0;font-size:13px;}}
</style>
</head><body>
<h1>👻 GhostRecon OSINT Report</h1>
<div class="meta">
  Company: <b style="color:#fff">{company}</b> |
  Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')} |
  Tool: GhostRecon v1.0
</div>
<div class="warn">⚠ FOR AUTHORIZED / EDUCATIONAL USE ONLY. Unauthorized use is illegal.</div>
<div class="stats">
  <div class="stat"><div class="num">{s.get('domains',0)}</div><div class="lbl">DOMAINS</div></div>
  <div class="stat"><div class="num">{s.get('subdomains',0)}</div><div class="lbl">SUBDOMAINS</div></div>
  <div class="stat"><div class="num">{s.get('emails',0)}</div><div class="lbl">EMAILS</div></div>
  <div class="stat"><div class="num {'red' if s.get('aws_buckets',0) else ''}">{s.get('aws_buckets',0)}</div><div class="lbl">S3 BUCKETS</div></div>
  <div class="stat"><div class="num {'red' if s.get('github_leaks',0) else ''}">{s.get('github_leaks',0)}</div><div class="lbl">GITHUB LEAKS</div></div>
  <div class="stat"><div class="num">{s.get('technologies',0)}</div><div class="lbl">TECHNOLOGIES</div></div>
  <div class="stat"><div class="num {'red' if critical else ''}">{critical}</div><div class="lbl">CRITICAL</div></div>
  <div class="stat"><div class="num">{s.get('google_dorks',0)}</div><div class="lbl">DORKS</div></div>
</div>

{section_html('🌐 Domains', RESULTS['domains'], ['domain','ip'])}
{section_html('🔍 Subdomains', RESULTS['subdomains'][:50], ['subdomain','ip','source'])}
{section_html('📧 Emails', RESULTS['emails'], ['email','pattern','source','domain'])}
{section_html('☁ AWS S3 Buckets', RESULTS['aws_buckets'], ['bucket','status','severity','url','note'])}
{section_html('🌩 GCP Buckets', RESULTS['gcp_buckets'], ['bucket','status','severity','url'])}
{section_html('🔷 Azure Blobs', RESULTS['azure_blobs'], ['account','status','severity','url'])}
{section_html('🐙 GitHub Leaks', RESULTS['github_leaks'], ['type','severity','repo','file','url','note'])}
{section_html('🔑 SSL Certificates', RESULTS['ssl_certs'][:30], ['domain','issuer','logged'])}
{section_html('🛡 Vulnerabilities', RESULTS['vulnerabilities'], ['type','severity','domain','missing','cve'])}
{section_html('💻 Technologies', RESULTS['technologies'], ['domain','technology','type','provider','header','value'])}
{section_html('📋 Pastes / Leaks', RESULTS['pastes'], ['site','url','date','note'])}
{section_html('📊 Breaches', RESULTS['breaches'], ['domain','breach','severity','compromised'])}

<div class="section">
  <h2>🎯 Google Dorks <span class="badge">{len(RESULTS['google_dorks'])}</span></h2>
  {dorks_html}
</div>

</body></html>"""
    with open(path,'w') as f:
        f.write(html)

# ══════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════
def check_dependencies():
    missing = []
    if not HAS_REQUESTS:   missing.append('requests')
    if not HAS_DNSPYTHON:  missing.append('dnspython')
    if not HAS_BS4:        missing.append('beautifulsoup4')
    if missing:
        warn(f"Optional packages missing (some features limited): {', '.join(missing)}")
        warn(f"Install with: pip install {' '.join(missing)}")
    return not bool(missing)

def main():
    global SESSION

    parser = argparse.ArgumentParser(
        description='GhostRecon — Corporate OSINT & Recon Engine',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:
  python ghostrecon.py -c "Acme Corp"
  python ghostrecon.py -c "Acme Corp" --github-token ghp_xxx --shodan-key xxx
  python ghostrecon.py -c "Acme Corp" --modules dns,aws,github,dorks
  python ghostrecon.py -c "Acme Corp" --domain acmecorp.com --deep
  python ghostrecon.py -c "Acme Corp" --output /tmp/reports --threads 50

LEGAL:
  Only use on organisations you are authorised to assess.
  Unauthorised use is illegal under various computer crime laws.
        """
    )
    parser.add_argument('-c','--company',     required=True, help='Company/organisation name')
    parser.add_argument('-d','--domain',      help='Known domain (skips domain discovery)')
    parser.add_argument('-o','--output',      default='.', help='Output directory for reports')
    parser.add_argument('--github-token',     help='GitHub Personal Access Token (higher rate limits)')
    parser.add_argument('--shodan-key',       help='Shodan API key')
    parser.add_argument('--hibp-key',         help='HaveIBeenPwned API key')
    parser.add_argument('--threads',          type=int, default=30, help='Thread count (default: 30)')
    parser.add_argument('--deep',             action='store_true', help='Deep scan (more wordlist entries, slower)')
    parser.add_argument('--modules',          default='all',
        help='Comma-separated modules: dns,subdomains,aws,gcp,gws,github,emails,dorks,tech,whois,pastes,shodan,breaches,linkedin (default: all)')
    parser.add_argument('--no-report',        action='store_true', help='Skip report generation')
    parser.add_argument('--timeout',          type=int, default=8, help='HTTP timeout seconds')

    args = parser.parse_args()

    banner()
    check_dependencies()

    if not HAS_REQUESTS:
        bad("requests library required: pip install requests")
        sys.exit(1)

    SESSION = make_session()
    SESSION.verify = False

    company = args.company
    modules = args.modules.lower().split(',') if args.modules != 'all' else ['all']
    run_all = 'all' in modules

    info(f"Target: {C.BOLD}{company}{C.RESET}")
    info(f"Modules: {args.modules}")
    info(f"Threads: {args.threads}")
    info(f"Output:  {args.output}")
    print()

    os.makedirs(args.output, exist_ok=True)

    start_time = time.time()

    # ── Run modules ──────────────────────────────────────────────────────
    # Domains
    if run_all or 'dns' in modules:
        if args.domain:
            domains = [args.domain]
            try:
                ip = socket.gethostbyname(args.domain)
                safe_add("domains", {"domain": args.domain, "ip": ip})
                good(f"Using provided domain: {args.domain} → {ip}")
            except Exception:
                warn(f"Could not resolve {args.domain}")
        else:
            domains = derive_domains(company)
    else:
        domains = [args.domain] if args.domain else []

    if not domains:
        warn("No live domains found. Continuing with best-guess domain.")
        slug = re.sub(r'[^a-z0-9]','',company.lower())
        domains = [f"{slug}.com"]

    # Subdomains
    if run_all or 'subdomains' in modules:
        enumerate_subdomains(domains)

    # DNS records & TXT intel
    if run_all or 'dns' in modules:
        for d in domains[:3]:
            _dns_records(d)

    # WHOIS
    if run_all or 'whois' in modules:
        whois_lookup(domains)

    # Tech fingerprint
    if run_all or 'tech' in modules:
        fingerprint_tech(domains)

    # AWS S3
    if run_all or 'aws' in modules:
        enumerate_aws_buckets(company, domains)

    # GCP + Azure
    if run_all or 'gcp' in modules:
        enumerate_cloud_storage(company)

    # Google Workspace
    if run_all or 'gws' in modules:
        enumerate_google_workspace(company, domains)

    # GitHub
    if run_all or 'github' in modules:
        github_recon(company, domains, github_token=args.github_token)

    # Emails
    if run_all or 'emails' in modules:
        harvest_emails(company, domains)

    # Employees / LinkedIn
    if run_all or 'linkedin' in modules:
        enumerate_employees(company, domains)

    # Google Dorks
    if run_all or 'dorks' in modules:
        generate_google_dorks(company, domains)

    # Paste leaks
    if run_all or 'pastes' in modules:
        check_paste_leaks(company, domains)

    # Shodan
    if run_all or 'shodan' in modules:
        shodan_recon(company, domains, shodan_key=args.shodan_key)

    # Breach check
    if run_all or 'breaches' in modules:
        check_breaches(domains, hibp_key=args.hibp_key)

    # ── Summary ──────────────────────────────────────────────────────────
    elapsed = time.time() - start_time
    section(f"SCAN COMPLETE in {elapsed:.1f}s")

    s = RESULTS['meta'].get('summary', {})
    print(f"""
  {C.GREEN}Domains found    : {len(RESULTS['domains'])}{C.RESET}
  {C.GREEN}Subdomains       : {len(RESULTS['subdomains'])}{C.RESET}
  {C.GREEN}Emails harvested : {len(RESULTS['emails'])}{C.RESET}
  {C.YELLOW}S3 buckets       : {len(RESULTS['aws_buckets'])} ({len([b for b in RESULTS['aws_buckets'] if b.get('severity')=='CRITICAL'])} OPEN){C.RESET}
  {C.YELLOW}GCP buckets      : {len(RESULTS['gcp_buckets'])}{C.RESET}
  {C.YELLOW}Azure blobs      : {len(RESULTS['azure_blobs'])}{C.RESET}
  {C.RED}GitHub leaks     : {len(RESULTS['github_leaks'])}{C.RESET}
  {C.CYAN}Technologies     : {len(RESULTS['technologies'])}{C.RESET}
  {C.CYAN}Google dorks     : {len(RESULTS['google_dorks'])}{C.RESET}
  {C.RED}Vulnerabilities  : {len(RESULTS['vulnerabilities'])}{C.RESET}
  {C.RED}Breaches         : {len(RESULTS['breaches'])}{C.RESET}
    """)

    # Report
    if not args.no_report:
        # Update summary before report
        RESULTS['meta']['summary'] = {
            "domains":      len(RESULTS['domains']),
            "subdomains":   len(RESULTS['subdomains']),
            "emails":       len(RESULTS['emails']),
            "aws_buckets":  len(RESULTS['aws_buckets']),
            "gcp_buckets":  len(RESULTS['gcp_buckets']),
            "azure_blobs":  len(RESULTS['azure_blobs']),
            "github_leaks": len(RESULTS['github_leaks']),
            "google_dorks": len(RESULTS['google_dorks']),
            "technologies": len(RESULTS['technologies']),
            "breaches":     len(RESULTS['breaches']),
            "pastes":       len(RESULTS['pastes']),
            "vulnerabilities": len(RESULTS['vulnerabilities']),
        }
        json_path, html_path = generate_report(company, args.output)
        print(f"\n  {C.BOLD}Reports saved:{C.RESET}")
        print(f"  {C.GREEN}→ {html_path}{C.RESET}")
        print(f"  {C.GREEN}→ {json_path}{C.RESET}")
        print(f"\n  Open the HTML report in your browser for full results.\n")

if __name__ == '__main__':
    main()
