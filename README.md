# 👻 GhostRecon v1.0 — Corporate OSINT & Recon Engine

> ⚠ FOR AUTHORIZED / EDUCATIONAL USE ONLY.
> Unauthorized scanning is illegal. Only use on organisations you own or have written permission to assess.

---

## What it discovers

| Module | What It Finds |
|--------|--------------|
| 🌐 Domain Discovery | Live domains from company name across 16 TLDs |
| 🔍 Subdomain Enum | 200+ wordlist + crt.sh certificate transparency |
| ☁ AWS S3 Buckets | Open/private buckets via 500+ name permutations |
| 🌩 GCP Storage | Google Cloud Storage open buckets |
| 🔷 Azure Blobs | Azure Blob Storage accounts and open containers |
| 📧 Email Harvesting | Real emails + pattern detection |
| 🐙 GitHub Leaks | Org repos, secret files, credential leaks in code |
| 🏢 Google Workspace | MX confirm, SAML/SSO, shared Drive/Docs/Sheets |
| 🎯 Google Dorks | 70+ automated dorks across 7 categories |
| 💻 Tech Stack | 30+ technologies detected from HTTP headers/body |
| 📋 DNS Records | A/AAAA/MX/TXT/SPF/DMARC/NS/SOA analysis |
| 🌍 WHOIS/RDAP | Registrar, registrant, nameservers, expiry |
| 📊 Paste Leaks | Pastebin/Ghostbin/Gist dorks + psbdmp search |
| 🔓 Breach Intel | HIBP domain search (needs API key) |
| 👤 Employee Enum | LinkedIn dorks → email list generation |
| 🔧 Shodan | Internet exposure (needs API key) |

---

## Install

```bash
pip install -r requirements.txt
```

## Usage

### Basic scan
```bash
python ghostrecon.py -c "Target Company"
```

### With known domain
```bash
python ghostrecon.py -c "Target Company" --domain targetcompany.com
```

### Full scan with API keys (best results)
```bash
python ghostrecon.py -c "Target Company" \
  --domain targetcompany.com \
  --github-token ghp_YOUR_TOKEN \
  --shodan-key YOUR_SHODAN_KEY \
  --hibp-key YOUR_HIBP_KEY \
  --output ./reports
```

### Run specific modules only
```bash
python ghostrecon.py -c "Target Company" --modules dns,aws,github,dorks
```

### Available modules
`dns` `subdomains` `aws` `gcp` `gws` `github` `emails` `dorks` `tech` `whois` `pastes` `shodan` `breaches` `linkedin`

---

## API Keys (optional but recommended)

| Key | Where to get | What it unlocks |
|-----|-------------|-----------------|
| GitHub Token | github.com → Settings → Developer Settings → PAT | 5000 req/hr vs 60/hr. Required for code search |
| Shodan Key | shodan.io (free tier available) | Internet-exposed services, open ports, CVEs |
| HIBP Key | haveibeenpwned.com/API/Key | Domain breach check — which employees were pwned |

---

## Output

Three files are generated per scan:
- `ghostrecon_COMPANY_TIMESTAMP.html` — Rich HTML report (open in browser)
- `ghostrecon_COMPANY_TIMESTAMP.json` — Full machine-readable results
- `ghostrecon_COMPANY_TIMESTAMP_summary.txt` — Plain text summary

---

## Legal targets to practice on

- Your own company/infrastructure
- Bug bounty programs: HackerOne, Bugcrowd, Intigriti
- CTF/practice: `buggy.website`, `hack.me`, OWASP WebGoat
- Your own test AWS/GCP accounts

---

## What each finding means

### Open S3 Bucket [CRITICAL]
The bucket is publicly listable. Anyone on the internet can download all files. Common findings: employee data, source code, database backups, credentials.

### GitHub Leaks [HIGH/CRITICAL]
`.env` files, credentials, AWS keys committed to public repos. Often includes database passwords, API tokens, private keys.

### Google Workspace Confirmed
The company uses Google for email/docs. Useful for: phishing simulation, identifying shared public Drive docs, SAML SSO attacks.

### SPF/DMARC Records
SPF tells you which servers can send email for the domain. Weak SPF (`+all`) = anyone can spoof email from this domain.

### crt.sh Subdomains
SSL certificate transparency logs reveal every subdomain that ever had an SSL cert — even internal/staging ones.
