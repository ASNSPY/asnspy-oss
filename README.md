# ASNSPY - Open Source Edition

<div align="center">

![ASNSPY Logo](https://img.shields.io/badge/ASNSPY-v3.0.0--oss-blue?style=for-the-badge)
![License](https://img.shields.io/badge/license-MIT-green?style=for-the-badge)
![POSIX](https://img.shields.io/badge/POSIX-compliant-orange?style=for-the-badge)
![Shell](https://img.shields.io/badge/shell-sh-lightgrey?style=for-the-badge)

**Advanced ASN Reconnaissance for Security Researchers**

[Features](#-features) • [Installation](#-installation) • [Quick Start](#-quick-start) • [Examples](#-examples) • [Documentation](#-documentation)

</div>

---

## 🎯 What is ASNSPY?

ASNSPY is a comprehensive reconnaissance tool that maps entire Autonomous Systems (ASNs) to discover infrastructure, identify security vulnerabilities, and analyze network architecture. Unlike traditional domain-focused scanners, ASNSPY approaches security assessment from the network level, giving you complete visibility into an organization's external attack surface.

**Think of it as:**
- 🔍 **nmap** for ASN-level reconnaissance
- 🌐 **Subfinder + Amass** with built-in vulnerability detection
- 🔒 **Nessus-lite** focused on network infrastructure
- 📊 **Shodan** but you run it yourself against specific networks

### Why ASN-Focused Scanning Matters

Most security tools start with domains. ASNSPY starts with network ownership:

```
Traditional Approach:           ASNSPY Approach:
domain.com                      AS15169 (Google)
  ├── subdomain enum              ├── 8,000+ IP prefixes
  ├── port scan                   ├── 600,000+ IP addresses
  └── vuln scan                   ├── Complete DNS mapping
                                  ├── All domains discovered
                                  ├── TLS certificate analysis
                                  ├── CVE vulnerability detection
                                  └── Infrastructure topology
```

You discover infrastructure the organization might not even know exists.

---

## 🚀 Features

ASNSPY combines multiple reconnaissance phases into a single, powerful workflow:

### 🔎 ASN Intelligence Gathering
- **WHOIS Lookup** - Organization info, country, contact details
- **Prefix Enumeration** - All IPv4/IPv6 network blocks owned by the ASN
- **RIPE/ARIN Integration** - Authoritative data from regional registries

Know exactly what infrastructure belongs to your target before you scan a single IP.

### 🌐 Network Discovery & Mapping
- **PTR Record Enumeration** - Reverse DNS for every IP in the ASN
- **Domain Extraction** - Automatically discover all domains
- **Smart Filtering** - Skip dead space, focus on real infrastructure
- **Resume Capability** - Pick up where you left off on large scans

Traditional recon finds `www.company.com`. ASNSPY finds `old-admin-panel.company.com`, `staging-api.company.com`, `vpn-legacy.company.com` - the forgotten assets attackers love.

### 🛣️ Network Path Analysis
- **Traceroute with ASN Attribution** - See routing paths and ownership
- **Hop-by-hop Analysis** - Identify transit providers, peering points
- **Network Topology Mapping** - Understand infrastructure architecture

Discover network segmentation, find backup routes, identify single points of failure.

### 🔐 TLS Certificate Intelligence
- **Complete Certificate Analysis** - CN, SANs, issuer, validity
- **Expiry Tracking** - Find certificates expiring soon
- **Self-Signed Detection** - Identify internal/dev systems
- **Weak Crypto Detection** - Flag outdated algorithms
- **Certificate Transparency** - Subdomain enumeration via CT logs

Certificates leak infrastructure details. A cert for `internal-api.company.com` tells you it exists - even if DNS doesn't resolve publicly.

### 🔓 Port Scanning & Service Detection
- **Comprehensive Port Discovery** - Full TCP connect scans
- **Top Ports Mode** - Nmap-style top N ports (fast mode)
- **Service Fingerprinting** - HTTP server version detection
- **Banner Grabbing** - Identify running services

You can't hack what you can't see. Find the forgotten FTP server, the old MySQL instance, the development Redis exposed to the internet.

### 🚨 CVE Vulnerability Detection
- **Automated CVE Lookup** - Query NVD database for known vulnerabilities
- **Version Correlation** - Match detected software to CVE database
- **Severity Filtering** - Focus on CRITICAL/HIGH findings
- **Real-time Updates** - Uses latest NVD API data

Bridge the gap between reconnaissance and exploitation. Find the Apache 2.4.49 server vulnerable to path traversal, the outdated WordPress, the unpatched IIS.

### 💣 Security Leak Detection
- **Exposed Configuration Files** - `.env`, `config.yml`, `.git/config`
- **Credential Scanning** - Pattern matching for API keys, passwords
- **Backup File Discovery** - `backup.sql`, `database.dump`
- **Debug Endpoints** - `phpinfo.php`, `server-status`

The #1 source of critical vulnerabilities. One exposed `.env` file = game over.

### 🔒 HTTP Security Analysis
- **Security Headers** - HSTS, CSP, X-Frame-Options analysis
- **Missing Protections** - Identify unprotected endpoints
- **A-F Grading System** - OWASP standards compliance
- **100-Point Scoring** - Detailed security posture assessment

Missing security headers = easy wins for attackers. Clickjacking, XSS, and protocol downgrade attacks become trivial.

### ☁️ Cloud Provider Detection
- **AWS/Azure/GCP Identification** - Automatic cloud infrastructure mapping
- **Multi-Cloud Discovery** - DigitalOcean, Cloudflare, Linode, OVH
- **Infrastructure Analysis** - Understand hosting strategy

Cloud misconfigurations are the #1 breach vector. Know what's in AWS so you can check for open S3 buckets, exposed RDS instances, misconfigured security groups.

### 📊 Professional Output Formats
- **CSV Export** - Easy analysis in spreadsheets
- **JSON Export** - Integration with other tools
- **Structured Reports** - Human-readable summaries
- **Raw Data** - Complete output for deep analysis

Your recon data is only useful if you can analyze it. Export to Splunk, import to Elasticsearch, analyze in Jupyter notebooks.

---

## 📥 Installation

### Quick Install

```bash
git clone https://github.com/ASNSPY/asnspy-oss.git
cd asnspy-oss
chmod +x asnspy.sh
./asnspy.sh AS15169
```

ASNSPY runs on any POSIX-compliant system with no compilation required.

### Supported Systems

- ✅ Linux (Ubuntu, Debian, RHEL, CentOS, Arch, Alpine, Fedora, etc.)
- ✅ macOS (Homebrew or MacPorts)
- ✅ BSD (FreeBSD, OpenBSD, NetBSD)
- ✅ Solaris / illumos
- ✅ Windows (WSL2, Git Bash, MSYS2)
- ✅ Android (Termux)
- ✅ Docker (any platform)

### Dependencies

**Required:**
- `curl` - HTTP client
- `jq` - JSON processor
- `dig` or `drill` - DNS lookups

**Optional:**
- `openssl` - TLS scanning
- `traceroute` - Path analysis
- `whois` - ASN metadata
- `nc` - Banner grabbing

**Complete installation guide:** [INSTALL.md](https://github.com/ASNSPY/asnspy-oss/blob/main/INSTALL.md)

---

## 🎬 Quick Start

### Your First Scan

```bash
./asnspy.sh AS13335
```

This command fetches all IP prefixes owned by AS13335 from RIPE, enumerates PTR records for discovered IPs, extracts unique domains from hostnames, and generates a comprehensive report.

**Output structure:**
```
scans/AS13335_a7f3d9e2/
├── prefixes.txt
├── ptr_results.txt
├── domains.txt
└── json/
    └── summary.json
```

**Scan duration:** 5-10 minutes for typical ASN

### Security Assessment Scan

```bash
./asnspy.sh AS13335 --profile security
```

Adds TLS certificate analysis, server version detection, CVE vulnerability lookup, HTTP security headers check, cloud provider identification, and exposed credential scanning.

**Scan duration:** 20-40 minutes depending on ASN size

### Deep Reconnaissance

```bash
./asnspy.sh AS13335 --profile deep
```

Comprehensive scan including network path tracing, Certificate Transparency enumeration, port scanning, version detection across all services, CVE detection for all severities, complete TLS analysis, leak detection, and full JSON export.

**Scan duration:** 1-3 hours for large ASN

---

## 💡 Use Cases & Examples

### 🎯 Bug Bounty Hunting

**Scenario:** You're targeting `company.com` on HackerOne.

```bash
whois company.com | grep -i "origin"

./asnspy.sh AS64496 --profile security --cve-min-severity HIGH
```

**Discoveries:**
- staging-api.company.com (not documented in scope)
- old-admin.company.com (running vulnerable WordPress)
- legacy-vpn.company.com (exposed to internet)
- dev-db.company.com (MySQL 5.5 with CVE-2019-2434)

You found 4 subdomains not listed in the scope, including a critical SQLi vulnerability.

**Typical bounty payout:** $500-5000 depending on severity

---

### 🔍 Attack Surface Discovery

**Scenario:** Your company hired you to find everything exposed on the internet.

```bash
./asnspy.sh AS12345 --profile deep --json

cat scans/AS12345_*/json/summary.json | jq '.statistics'
```

**Management visibility:**
```json
{
  "prefixes": 42,
  "ptr_records": 8934,
  "domains": 234,
  "tls_certificates": 156,
  "vulnerabilities": 23,
  "leak_exposures": 7
}
```

**Critical discoveries:**
- Forgotten dev servers still running
- Shadow IT infrastructure
- Acquired companies' infrastructure never integrated
- Leaked credentials in configuration files
- Expired TLS certificates on payment systems

**Business impact:** Prevent breach, ensure compliance, reduce attack surface

---

### 🏢 Vendor Security Assessment

**Scenario:** Evaluating a SaaS vendor before signing $500k contract.

```bash
whois vendor.com | grep origin

./asnspy.sh AS54113 \
  --profile security \
  --tls \
  --http-security \
  --leak-scan \
  --cve-min-severity MEDIUM

cat scans/AS54113_*/vulnerabilities.csv
cat scans/AS54113_*/leak_exposures.csv
cat scans/AS54113_*/http_security.csv
```

**Red flags discovered:**
- Database backups accessible without authentication
- Admin panels with default credentials
- Certificates expired 6 months ago
- Missing security headers on payment pages
- 12 CRITICAL CVEs in production systems

**Decision:** Negotiate security remediation clauses or walk away from contract

---

### 🌐 Competitor Intelligence

**Scenario:** Understanding competitor infrastructure for business intelligence.

```bash
./asnspy.sh AS99999 --cloud-detect --trace

cat scans/AS99999_*/domains.txt
```

**Infrastructure analysis:**
- 100% AWS infrastructure (enables cost estimation)
- Using Cloudflare CDN for public-facing services
- Infrastructure in 3 regions: US, EU, APAC
- Running 50% more servers than last quarter (scaling indicators)

**Domain analysis reveals:**
- new-product.competitor.com (unreleased product)
- enterprise-api.competitor.com (B2B pivot)
- jobs-internal.competitor.com (hiring infrastructure)

**Business value:** Strategic intelligence, market positioning, competitive analysis

This reconnaissance uses public data and is legal in most jurisdictions.

---

### 📡 Network Architecture Analysis

**Scenario:** Understanding network design before a penetration test.

```bash
./asnspy.sh AS20940 --trace --trace-mode all

cat scans/AS20940_*/traceroute_topology.txt
```

**Traceroute reveals:**
- Primary transit: Level3 (AS3356)
- Backup transit: Cogent (AS174)
- Peering points: 4 major IXPs
- Internal segmentation visible via routing patterns

**Penetration test value:**
- Understand network design and architecture
- Identify single points of failure
- Find alternate routes for resilience testing
- Map trust boundaries and segmentation

---

### 🔐 Certificate Hygiene Audit

**Scenario:** Security team needs to track certificate expiry across all infrastructure.

```bash
./asnspy.sh AS30000 --tls --tls-mode all

cat scans/AS30000_*/tls_issues.txt
```

**Typical findings:**

```
EXPIRED CERTIFICATES: 12
  10.20.30.40 - vpn.company.com (expired 45 days ago)
  10.20.30.41 - mail.company.com (expired 12 days ago)

EXPIRING SOON (<30 days): 8
  10.20.30.50 - api.company.com (23 days remaining)
  10.20.30.51 - admin.company.com (15 days remaining)

SELF-SIGNED CERTIFICATES: 34
  Internal dev servers that should not be publicly accessible

WEAK KEY SIZES: 3
  10.20.30.60 - RSA 1024 bits (should be 2048+)
```

**Remediation actions:**
- Renew expired certificates immediately
- Automate renewal for expiring certificates
- Remove self-signed certificates from production
- Upgrade weak cryptography

---

### 🕵️ OSINT for Investigations

**Scenario:** Investigating a malicious domain's infrastructure.

```bash
whois malicious-site.com | grep -i origin

./asnspy.sh AS12876 --profile deep

cat scans/AS12876_*/domains.txt | grep -E "phishing|scam|fake"
```

**Investigation findings:**
- 200+ suspicious domains on same ASN
- Same TLS certificate across 50 domains (infrastructure reuse)
- All domains registered in last 30 days
- Hosting pattern matches known threat actor

**Investigation value:**
- Link multiple campaigns to same threat actor
- Find additional IOCs (indicators of compromise)
- Report entire ASN to hosting provider
- Implement network-level blocking

---

## 🎓 Advanced Usage

### Parallel Processing for Performance

ASNSPY supports parallel processing across all scan phases for dramatic speed improvements:

```bash
# Default: Serial scanning (safest, slowest)
./asnspy.sh AS15169

# Global parallel - applies to all phases
./asnspy.sh AS15169 --parallel 50

# Phase-specific parallel (fine-grained control)
./asnspy.sh AS15169 \
  --parallel 100 \
  --trace-parallel 10 \
  --tls-parallel 20 \
  --version-parallel 20 \
  --port-scan-parallel 100

# Speed-optimized scan
./asnspy.sh AS15169 --profile quick --parallel 100
```

**Performance Guidelines:**

| Concurrency | Use Case | Scan Speed | Network Impact |
|------------|----------|------------|----------------|
| `--parallel 1` | Default, safest | ~10 IPs/min | Minimal |
| `--parallel 10` | Small networks | ~50 IPs/min | Low |
| `--parallel 50` | Medium networks | ~200 IPs/min | Moderate |
| `--parallel 100` | Large networks | ~400 IPs/min | High |
| `--parallel 200+` | High-performance | ~800 IPs/min | Very High |

**When to use parallel:**
- ✅ **Bug bounty hunting** - Speed matters for first discovery
- ✅ **Large ASNs** - 10,000+ IPs take hours without parallel
- ✅ **Quick reconnaissance** - Initial survey of attack surface
- ✅ **Your own infrastructure** - No stealth concerns

**When NOT to use high parallel:**
- ❌ **Stealth operations** - Use `--profile stealth` (parallel=1)
- ❌ **Rate-limited targets** - Risk triggering WAF/IPS
- ❌ **Shared infrastructure** - Respect server resources
- ❌ **Unstable networks** - Packet loss increases with concurrency

**Example timing:**

```bash
# AS15169 (Google) has ~8,000 prefixes

# Serial scan (parallel=1)
# Time: 4-6 hours
./asnspy.sh AS15169 --profile security

# Moderate parallel (parallel=50)
# Time: 30-45 minutes
./asnspy.sh AS15169 --profile security --parallel 50

# High parallel (parallel=100)
# Time: 15-25 minutes
./asnspy.sh AS15169 --profile security --parallel 100
```

**Best practice:**
```bash
# Start conservative, increase if needed
./asnspy.sh AS15169 --profile security --parallel 20

# Monitor network impact, adjust accordingly
# If no issues, increase to 50 or 100
```

### Custom Scans

```bash
./asnspy.sh AS15169 --parallel 100 --profile quick

./asnspy.sh AS15169 --profile stealth

./asnspy.sh AS15169 --gateway-only --port-scan

./asnspy.sh AS15169 --host-range 1-50 --prefix-range 8-8

./asnspy.sh AS15169 --port-scan --port-scan-ports "22,80,443,3389"

./asnspy.sh AS15169 --port-scan --port-scan-top 100
```

### Combining Features

```bash
./asnspy.sh AS15169 \
  --tls --tls-mode ptr \
  --version-detect \
  --cve --cve-min-severity HIGH

./asnspy.sh AS15169 \
  --port-scan --port-scan-top 1000 \
  --tls \
  --version-detect \
  --cve --cve-min-severity MEDIUM \
  --http-security \
  --leak-scan \
  --cloud-detect \
  --json

./asnspy.sh AS15169 \
  --trace --trace-mode all \
  --ct \
  --cloud-detect
```

### Filtering & Optimization

```bash
./asnspy.sh AS15169 --skip-dead

./asnspy.sh AS15169 --internet-only

./asnspy.sh AS15169 --strict-valid

./asnspy.sh AS15169 --ipv4

./asnspy.sh AS15169 --ipv6
```

---

## 📊 Output & Analysis

### Understanding Results

Every scan creates a timestamped directory:
```
scans/AS15169_a7f3d9e2/
├── prefixes.txt
├── ptr_results.txt
├── domains.txt
├── ct_results.txt
├── traceroute_results.txt
├── tls_certificates.csv
├── server_versions.csv
├── port_scan_results.csv
├── vulnerabilities.csv
├── leak_exposures.csv
├── http_security.csv
├── cloud_providers.csv
└── json/
    ├── summary.json
    ├── prefixes.json
    ├── vulnerabilities.json
    ├── tls_certificates.json
    └── ...
```

### Analysis Examples

```bash
awk -F, '$6=="CRITICAL"' scans/AS*/vulnerabilities.csv

awk -F, '$13=="expired"' scans/AS*/tls_certificates.csv

grep -i "password\|apikey\|secret" scans/AS*/leak_exposures.csv

wc -l scans/AS*/domains.txt

cat scans/AS*/json/vulnerabilities.json | \
  curl -X POST http://splunk:8088/services/collector \
    -H "Authorization: Splunk YOUR_TOKEN" \
    -d @-

csvtool readable scans/AS*/vulnerabilities.csv > report.txt

awk -F, '$21=="yes"' scans/AS*/tls_certificates.csv

sort scans/AS*/cloud_providers.csv | uniq -c
```

---

## 🔧 Configuration

### Config File

Create `~/.asnspyrc` to save preferences:

```bash
./asnspy.sh --generate-config

nano ~/.asnspyrc
```

**Example configuration:**

```bash
PARALLEL=50
TRACE_PARALLEL=10
TLS_PARALLEL=20

DO_TRACE=1
DO_TLS=1
DO_CVE=1
DO_JSON=1

MODE_INTERNET_ONLY=1
CVE_MIN_SEVERITY=MEDIUM

SCAN_PROFILE=security
```

**Config locations (priority order):**
1. `./.asnspyrc` (current directory)
2. `~/.asnspyrc` (home directory)
3. `/etc/asnspy.conf` (system-wide)

---

## 🛡️ Legal & Ethical Use

### Authorization Required

You must have explicit authorization before scanning:

- Your own infrastructure
- Client infrastructure with written permission
- Bug bounty programs within defined scope
- Penetration test engagements with signed contracts

Unauthorized scanning may violate:
- Computer Fraud and Abuse Act (CFAA) in the United States
- Computer Misuse Act in the United Kingdom
- Similar laws in other jurisdictions

Penalties include fines and imprisonment.

### Responsible Use Guidelines

**Best practices:**
- Read bug bounty scope documentation carefully
- Obtain written authorization for penetration tests
- Respect rate limits and system resources
- Follow responsible disclosure practices
- Stop scanning if requested by the target

**Prohibited activities:**
- Scanning without authorization
- Exploiting discovered vulnerabilities without permission
- Sharing credentials discovered during scans
- Causing damage or service disruption
- Exceeding authorized bug bounty scope

### Bug Bounty Best Practices

**Verify scope:**
- Confirm ASN belongs to target organization
- Check for out-of-scope subsidiaries and acquisitions
- Validate IP ranges against program documentation

**Start passive:**
- Begin with `--profile quick` for initial reconnaissance
- Validate findings manually before active scanning
- Escalate to deeper scans only when appropriate

**Report responsibly:**
- Include ASNSPY output as evidence
- Provide clear reproduction steps
- Do not exfiltrate sensitive data
- Follow program disclosure timeline
- Report through official channels only

---

## 🆚 Open Source vs Enterprise

### What's Included in Open Source

ASNSPY Open Source is a complete, professional reconnaissance tool - not a crippled demo:

**Core Scanning (100% Unrestricted)**
- ✅ ASN Intelligence Gathering (WHOIS, prefixes)
- ✅ PTR Record Enumeration (all IPs)
- ✅ Domain Extraction (unlimited)
- ✅ Certificate Transparency (CT log queries)
- ✅ Network Path Tracing (traceroute with ASN lookup)
- ✅ TLS Certificate Analysis (expiry, weak crypto, self-signed)
- ✅ Port Scanning (TCP connect, all ports)
- ✅ HTTP Server Version Detection (fingerprinting)
- ✅ CVE Vulnerability Detection (NVD integration)
- ✅ HTTP Security Headers (A-F grading)
- ✅ Cloud Provider Detection (AWS, Azure, GCP, etc.)
- ✅ Security Leak Detection (configs, credentials, banners)

**Features & Capabilities**
- ✅ Parallel Processing (unlimited concurrency)
- ✅ All Scan Profiles (quick, standard, deep, stealth, security)
- ✅ Resume Capability (large scan support)
- ✅ Filtering Options (dead hosts, gateway-only, IP ranges)
- ✅ JSON Export (structured data for all findings)
- ✅ Configuration Files (.asnspyrc support)
- ✅ IPv4 and IPv6 Support
- ✅ Multiple Scan Modes (ptr, all, gateway)

**No Artificial Limitations**
- No scan count limits
- No IP address limits
- No time restrictions
- No feature paywalls
- No "premium" tiers for core functionality

### Enterprise-Only Features

Enterprise ASNSPY adds **operational automation** and **enterprise integration** - it doesn't just "unlock" existing features:

**ASN Range Scanning**
```bash
./asnspy.sh --asn-range AS13335-AS13340 --fetch-prefixes
```
Scan multiple ASNs in batch operations. Useful for:
- Industry-wide reconnaissance (scan all ISPs)
- Subsidiary mapping (parent company + acquisitions)
- Competitive analysis (scan multiple competitors)
- Managed service providers (multi-tenant monitoring)

**SIEM Integration (Real-time Event Streaming)**
```bash
./asnspy.sh AS15169 --profile security \
  --siem splunk --siem-host splunk.company.com:8088 \
  --siem-token YOUR_HEC_TOKEN --siem-index security
```
Send findings directly to your SIEM platform as they're discovered:
- **Supported platforms:** Splunk (HEC), Elasticsearch, QRadar, ArcSight, Graylog, Sumo Logic, Syslog
- **Real-time streaming:** Events sent as discovered (not batch)
- **Structured formats:** HEC, GELF, CEF, ECS
- **Use case:** Security operations centers, compliance monitoring, threat hunting

**Webhook Notifications**
```bash
./asnspy.sh AS15169 --profile security \
  --webhook https://hooks.slack.com/YOUR/WEBHOOK \
  --webhook-type slack \
  --webhook-events scan_complete,critical_finding
```
Get instant alerts for scan completion and critical findings:
- **Supported services:** Slack, Discord, Microsoft Teams, PagerDuty, generic webhooks
- **Event types:** scan_start, scan_complete, critical_finding, error
- **Severity filtering:** Only alert on CRITICAL/HIGH findings
- **Use case:** Team notifications, incident response, change management

**Database Backend (Scan History & Trending)**
```bash
./asnspy.sh AS15169 --profile security \
  --database --db-type postgresql \
  --db-host db.company.com --db-user scanner --db-pass secret
```
Store all scan results in a database for historical analysis:
- **Supported databases:** SQLite (single-user), PostgreSQL (enterprise), MySQL
- **Capabilities:** 
  - Scan history tracking (every scan stored)
  - Vulnerability trending over time
  - Asset inventory (centralized IP/hostname database)
  - Certificate expiry monitoring
  - Finding lifecycle management (discovery → remediation)
- **Use case:** Compliance reporting, SLA tracking, executive dashboards

**Diff Mode (Change Detection)**
```bash
./asnspy.sh AS15169 --profile security \
  --database --diff LATEST \
  --webhook https://hooks.slack.com/YOUR/WEBHOOK
```
Automatically detect changes between scans:
- **Detects:** New/removed assets, new/resolved vulnerabilities, port changes, certificate expiry
- **Requires:** Database backend enabled
- **Baselines:** Compare against LATEST scan or specific scan ID
- **Alerts:** Automatic notifications for new CRITICAL findings
- **Use case:** Continuous monitoring, change detection, compliance drift

**Why These Are Enterprise-Only**

These features require **infrastructure** and **integration** beyond a single shell script:

1. **ASN Range Scanning** - Batch orchestration, parallel ASN lookups, multi-WHOIS parsing
2. **SIEM Integration** - 8 different platform APIs, authentication handling, retry logic
3. **Webhooks** - 5 different message formats, event routing, notification management
4. **Database** - Schema management, migrations, query optimization, multi-user support
5. **Diff Mode** - Change detection algorithms, baseline management, alert rules

Building these yourself = 6-12 months dev time = $300,000-$600,000

### Why Upgrade to Enterprise?

**The Challenge with Open Source**

Running ASNSPY OSS in production requires manual work:

**Weekly security scan routine:**
- Run scan: 2 hours
- Parse CSV files: 2 hours
- Compare with last week (spreadsheets): 3 hours
- Generate reports for management: 4 hours
- Track remediation in tickets: 3 hours
- Alert teams on critical findings: 2 hours
- Update asset inventory: 2 hours

**Total: 18 hours/week = $117,000/year** (at $125/hour)

**With Enterprise:**
- Automated scheduled scans: 0 hours
- SIEM integration (auto-parsed): 0 hours
- Automated change detection: 0 hours
- Auto-generated reports: 0 hours
- Webhook alerts: 0 hours
- Database asset inventory: 0 hours

**Total: 0 hours/week = $10,000/year license**

**Annual savings: $107,000**

### Real-World Example

**Mid-sized security team scenario:**

Company with 5 ASNs, weekly security scans:

**Open Source approach:**
```bash
./asnspy.sh AS12345 --profile security --json
./asnspy.sh AS12346 --profile security --json
./asnspy.sh AS12347 --profile security --json
./asnspy.sh AS12348 --profile security --json
./asnspy.sh AS12349 --profile security --json
```
Then manually:
- Import 5 JSON files into spreadsheet
- Compare with previous week's data
- Identify new vulnerabilities
- Email teams about critical findings
- Update Jira tickets
- Copy data to Splunk
- Generate weekly report for CISO

**Enterprise approach:**
```bash
./asnspy.sh --asn-range AS12345-AS12349 --profile security \
  --database --diff LATEST \
  --siem splunk --siem-host splunk.company.com:8088 \
  --webhook https://hooks.slack.com/YOUR/WEBHOOK \
  --webhook-events critical_finding
```
Then:
- Nothing. It's automated.
- Slack alerts on new CRITICAL findings
- Splunk ingests all data automatically
- Database tracks changes week-over-week
- Query database for CISO report

**Learn more:** [https://asnspy.com/enterprise](https://asnspy.com/enterprise)

---

## 🤝 Contributing

We welcome contributions from the security community.

### Areas We Need Help
- Bug reports and issue identification
- Documentation improvements and examples
- Additional CVE data sources
- Cloud provider detection expansion
- Testing on additional platforms
- Internationalization and translations

### How to Contribute

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

### Code Standards
- ✅ POSIX-compliant (no bashisms)
- ✅ Comprehensive error handling
- ✅ Inline documentation
- ✅ Test on multiple platforms
- ✅ Follow existing code style

---

## 📚 Documentation

- [Installation Guide](https://github.com/ASNSPY/asnspy-oss/blob/main/INSTALL.md) - Detailed setup for every platform
- [Enterprise Comparison](https://github.com/ASNSPY/asnspy-oss/blob/main/ENTERPRISE_COMPARISON.md) - Feature comparison & ROI
- [Removed Modules](https://github.com/ASNSPY/asnspy-oss/blob/main/REMOVED_MODULES.md) - Technical details on OSS vs Enterprise
- [Changelog](https://github.com/ASNSPY/asnspy-oss/blob/main/CHANGELOG.md) - Version history
- [Contributing](https://github.com/ASNSPY/asnspy-oss/blob/main/CONTRIBUTING.md) - How to contribute

---

## 🗺️ Roadmap

### Near Term (Q1 2025)
- Additional CVE data sources (Vulners, CVE.org)
- IPv6 scanning improvements
- Performance optimizations
- Additional cloud provider detection

### Medium Term (Q2-Q3 2025)
- HTML report generation
- GraphQL API scanning
- Kubernetes cluster detection
- Container registry scanning

### Long Term (Q4 2025+)
- GUI interface (community contribution welcome)
- Machine learning for anomaly detection
- Threat intelligence integration
- Mobile app (iOS/Android)

**Vote on features:** [GitHub Discussions](https://github.com/ASNSPY/asnspy-oss/discussions)

---

## 📞 Support & Community

### Community Support
- **GitHub Issues:** [Report bugs, request features](https://github.com/ASNSPY/asnspy-oss/issues)
- **GitHub Discussions:** [Ask questions, share tips](https://github.com/ASNSPY/asnspy-oss/discussions)
- **Discord:** [Join the community](https://discord.gg/asnspy)

### Enterprise Support
- **Website:** [https://asnspy.com](https://asnspy.com)
- **Contact:** [contact@asnspy.com](mailto:contact@asnspy.com)
- **Instagram:** [@asn_spy](https://instagram.com/asn_spy)
- **Documentation:** [https://docs.asnspy.com](https://docs.asnspy.com)

---

## 📜 License

**MIT License** - see [LICENSE](LICENSE) file for details

Free for personal and commercial use. No restrictions.

---

## 🙏 Credits & Acknowledgments

ASNSPY is built on the shoulders of giants:

**Data Sources:**
- RIPE NCC - ASN and prefix data
- NVD (NIST) - CVE vulnerability database
- Certificate Transparency - Google's CT log infrastructure
- Team Cymru - IP-to-ASN mapping

**Built With:**
- `curl` - HTTP client
- `jq` - JSON processor
- `openssl` - TLS/crypto operations
- `traceroute` - Network path analysis

**Inspired By:**
- **nmap** - Port scanning methodology
- **Amass** - Subdomain enumeration approach
- **Shodan** - Internet-wide scanning concepts
- **Nessus** - Vulnerability assessment workflow

---

## ⚡ Quick Reference

```bash
./asnspy.sh AS15169

./asnspy.sh AS15169 --profile security

./asnspy.sh AS15169 --profile deep

./asnspy.sh AS15169 --profile quick

./asnspy.sh AS15169 \
  --parallel 100 \
  --port-scan --port-scan-top 1000 \
  --tls --version-detect --cve \
  --leak-scan --http-security \
  --json

./asnspy.sh --help

./asnspy.sh --generate-config
```

---

<div align="center">

**Discover your attack surface**

```bash
git clone https://github.com/ASNSPY/asnspy-oss.git
cd asnspy-oss
./asnspy.sh AS15169 --profile deep
```

**Star this repository to support the project** ⭐

[⬆ Back to Top](#asnspy---open-source-edition)

</div>
