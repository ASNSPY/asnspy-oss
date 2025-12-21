# ASNSPY - Open Source Edition

<div align="center">

![ASNSPY Logo](https://img.shields.io/badge/ASNSPY-v3.0.0--oss-blue?style=for-the-badge)
![License](https://img.shields.io/badge/license-MIT-green?style=for-the-badge)
![POSIX](https://img.shields.io/badge/POSIX-compliant-orange?style=for-the-badge)
![Shell](https://img.shields.io/badge/shell-sh-lightgrey?style=for-the-badge)

**Professional ASN Reconnaissance & Network Mapping for Security Researchers**

[Features](#-features) • [Installation](#-installation) • [Quick Start](#-quick-start) • [Examples](#-examples) • [Documentation](#-documentation)

</div>

---

## 🎯 What is ASNSPY?

ASNSPY is a comprehensive reconnaissance tool that maps **entire Autonomous Systems (ASNs)** to discover infrastructure, identify security vulnerabilities, and analyze network architecture. Unlike traditional domain-focused scanners, ASNSPY approaches security assessment from the network level - giving you complete visibility into an organization's external attack surface.

**Think of it as:**
- 🔍 **nmap** for ASN-level reconnaissance
- 🌐 **Subfinder + Amass** with built-in vulnerability detection
- 🔒 **Nessus-lite** focused on network infrastructure
- 📊 **Shodan** but you run it yourself against specific networks

### Why ASN-Focused Scanning Matters

Most security tools start with domains. ASNSPY starts with **network ownership**:

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

**The difference?** You discover infrastructure the organization might not even know exists.

---

## 🚀 Features

ASNSPY combines multiple reconnaissance phases into a single, powerful workflow:

### 🔎 ASN Intelligence Gathering
- **WHOIS Lookup** - Organization info, country, contact details
- **Prefix Enumeration** - All IPv4/IPv6 network blocks owned by the ASN
- **RIPE/ARIN Integration** - Authoritative data from regional registries

**Why this matters:** Know exactly what infrastructure belongs to your target before you scan a single IP.

### 🌐 Network Discovery & Mapping
- **PTR Record Enumeration** - Reverse DNS for every IP in the ASN
- **Domain Extraction** - Automatically discover all domains
- **Smart Filtering** - Skip dead space (.0, .255), focus on real infrastructure
- **Resume Capability** - Pick up where you left off on large scans

**Why this matters:** Traditional recon finds `www.company.com`. ASNSPY finds `old-admin-panel.company.com`, `staging-api.company.com`, `vpn-legacy.company.com` - the forgotten assets attackers love.

### 🛣️ Network Path Analysis
- **Traceroute with ASN Attribution** - See routing paths and ownership
- **Hop-by-hop Analysis** - Identify transit providers, peering points
- **Network Topology Mapping** - Understand infrastructure architecture

**Why this matters:** Discover network segmentation, find backup routes, identify single points of failure.

### 🔐 TLS Certificate Intelligence
- **Complete Certificate Analysis** - CN, SANs, issuer, validity
- **Expiry Tracking** - Find certificates expiring soon
- **Self-Signed Detection** - Identify internal/dev systems
- **Weak Crypto Detection** - Flag outdated algorithms
- **Certificate Transparency** - Subdomain enumeration via CT logs

**Why this matters:** Certificates leak infrastructure details. A cert for `internal-api.company.com` tells you it exists - even if DNS doesn't resolve publicly.

### 🔓 Port Scanning & Service Detection
- **Comprehensive Port Discovery** - Full TCP connect scans
- **Top Ports Mode** - Nmap-style top N ports (fast mode)
- **Service Fingerprinting** - HTTP server version detection
- **Banner Grabbing** - Identify running services

**Why this matters:** You can't hack what you can't see. Find the forgotten FTP server, the old MySQL instance, the development Redis exposed to the internet.

### 🚨 CVE Vulnerability Detection
- **Automated CVE Lookup** - Query NVD database for known vulnerabilities
- **Version Correlation** - Match detected software to CVE database
- **Severity Filtering** - Focus on CRITICAL/HIGH findings
- **Real-time Updates** - Uses latest NVD API data

**Why this matters:** Bridge the gap between reconnaissance and exploitation. Find the Apache 2.4.49 server vulnerable to path traversal, the outdated WordPress, the unpatched IIS.

### 💣 Security Leak Detection
- **Exposed Configuration Files** - `.env`, `config.yml`, `.git/config`
- **Credential Scanning** - Pattern matching for API keys, passwords
- **Backup File Discovery** - `backup.sql`, `database.dump`
- **Debug Endpoints** - `phpinfo.php`, `server-status`

**Why this matters:** The #1 source of critical vulnerabilities. One exposed `.env` file = game over.

### 🔒 HTTP Security Analysis
- **Security Headers** - HSTS, CSP, X-Frame-Options analysis
- **Missing Protections** - Identify unprotected endpoints
- **Best Practice Compliance** - Compare against OWASP standards

**Why this matters:** Missing security headers = easy wins for attackers. Clickjacking, XSS, and protocol downgrade attacks become trivial.

### ☁️ Cloud Provider Detection
- **AWS/Azure/GCP Identification** - Automatic cloud infrastructure mapping
- **Multi-Cloud Discovery** - DigitalOcean, Cloudflare, Linode, OVH
- **Infrastructure Analysis** - Understand hosting strategy

**Why this matters:** Cloud misconfigurations are the #1 breach vector. Know what's in AWS so you can check for open S3 buckets, exposed RDS instances, misconfigured security groups.

### 📊 Professional Output Formats
- **CSV Export** - Easy analysis in spreadsheets
- **JSON Export** - Integration with other tools
- **Structured Reports** - Human-readable summaries
- **Raw Data** - Complete output for deep analysis

**Why this matters:** Your recon data is only useful if you can analyze it. Export to Splunk, import to Elasticsearch, analyze in Jupyter notebooks.

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
# TLS + Version + CVE pipeline
./asnspy.sh AS15169 \
  --tls --tls-mode ptr \
  --version-detect \
  --cve --cve-min-severity HIGH

# Complete security audit
./asnspy.sh AS15169 \
  --port-scan --port-scan-top 1000 \
  --tls \
  --version-detect \
  --cve --cve-min-severity MEDIUM \
  --http-security \
  --leak-scan \
  --cloud-detect \
  --json

# Network analysis focus
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
├── prefixes.txt              # IP ranges (8.8.8.0/24, 8.8.4.0/24, ...)
├── ptr_results.txt           # IP,hostname (8.8.8.8,dns.google)
├── domains.txt               # Unique domains (google.com, dns.google, ...)
├── ct_results.txt            # CT log subdomains
├── traceroute_results.txt    # Network paths (CSV format)
├── tls_certificates.csv      # Certificate details
├── server_versions.csv       # Detected software versions
├── port_scan_results.csv     # Open ports
├── vulnerabilities.csv       # CVE findings
├── leak_exposures.csv        # Exposed configs/credentials
├── http_security.csv         # Security header analysis
├── cloud_providers.csv       # Cloud infrastructure mapping
└── json/
    ├── summary.json          # Complete scan summary
    ├── prefixes.json         # Structured prefix data
    ├── vulnerabilities.json  # CVE details
    ├── tls_certificates.json # Certificate data
    └── ...                   # All data in JSON format
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

### What's Included FREE in Open Source

ASNSPY Open Source is **not a demo** - it's a complete, professional tool:

- ✅ **All Scanning Capabilities** (unrestricted)
- ✅ **CVE Vulnerability Detection** (full NVD integration)
- ✅ **Leak/Credential Detection** (complete pattern matching)
- ✅ **TLS Certificate Analysis** (comprehensive)
- ✅ **Port Scanning** (all ports, all modes)
- ✅ **Version Detection** (HTTP fingerprinting)
- ✅ **Cloud Provider Detection** (AWS, Azure, GCP, etc.)
- ✅ **HTTP Security Analysis** (header checks)
- ✅ **Network Tracing** (with ASN attribution)
- ✅ **Certificate Transparency** (subdomain enumeration)
- ✅ **JSON Export** (structured data)
- ✅ **Parallel Processing** (unlimited concurrency)
- ✅ **Resume Capability** (large scan support)
- ✅ **All Scan Profiles** (quick, deep, security, stealth)

**No artificial limits. No crippled features. No pay walls.**

### Enterprise Features

Enterprise ASNSPY transforms point-in-time scans into continuous security intelligence:

**Scale & Automation**
- ASN Range Scanning: Scan AS13335-AS99999 in one command
- Scheduling: Automated daily/weekly scans with error handling
- API Access: RESTful API for programmatic integration
- Bulk Operations: Campaign management for hundreds of targets

**Enterprise Integration**
- SIEM Connectors: Splunk, Elasticsearch, QRadar, ArcSight, Graylog, Sumo Logic
- Webhook Notifications: Slack, Discord, Teams, PagerDuty, custom endpoints
- Database Backend: PostgreSQL, MySQL with 12+ months historical data
- SSO/RBAC: SAML, OAuth, role-based access control

**Intelligence & Analytics**
- Diff Mode: Automated change detection between scans
- Trending: Historical analysis and pattern recognition
- Asset Inventory: Centralized database of discovered infrastructure
- Vulnerability Tracking: Track findings from discovery through remediation
- Analytics Dashboard: Web-based visualization and reporting

**Compliance & Reporting**
- Compliance Templates: PCI-DSS, SOC2, ISO 27001, NIST
- PDF Reports: Automated executive and technical report generation
- Audit Trails: Complete activity logging for compliance
- SLA Tracking: Measure mean-time-to-remediation

**Support**
- Priority Support: Email and phone with SLA
- Training: Live onboarding sessions
- Custom Integrations: Professional services available
- Dedicated CSM: Customer success manager

### Why Upgrade to Enterprise?

**Manual approach with Open Source:**
- 18 hours per week of manual work
- Annual cost: $117,000 (at $125/hour)

**Automated Enterprise approach:**
- 0 hours per week
- Annual cost: $10,000

**Annual savings: $107,000**

Alternatively, building these capabilities in-house requires:
- 6-12 months of development time
- Engineering cost: $300,000-$600,000
- Ongoing maintenance and updates

**Learn more:** [https://asnspy.com/enterprise](https://asnspy.com/enterprise)

---

## 🤝 Contributing

We welcome contributions! Here's how to help:

### Areas We Need Help
- 🐛 **Bug Reports** - Find issues, report them
- 📖 **Documentation** - Improve guides, add examples
- ✨ **Features** - Additional CVE sources, cloud providers
- 🧪 **Testing** - More platforms, edge cases
- 🌍 **Translations** - Internationalization

### How to Contribute

1. **Fork the repository**
2. **Create feature branch** (`git checkout -b feature/amazing-feature`)
3. **Commit changes** (`git commit -m 'Add amazing feature'`)
4. **Push to branch** (`git push origin feature/amazing-feature`)
5. **Open Pull Request**

### Code Standards
- ✅ POSIX-compliant (no bashisms)
- ✅ Comprehensive error handling
- ✅ Inline documentation
- ✅ Test on multiple platforms
- ✅ Follow existing code style

---

## 📚 Documentation

- **[Installation Guide](https://github.com/ASNSPY/asnspy-oss/blob/main/INSTALL.md)** - Detailed setup for every platform
- **[Enterprise Comparison](https://github.com/ASNSPY/asnspy-oss/blob/main/ENTERPRISE_COMPARISON.md)** - Feature comparison & ROI
- **[Removed Modules](https://github.com/ASNSPY/asnspy-oss/blob/main/REMOVED_MODULES.md)** - Technical details on OSS vs Enterprise
- **[Changelog](https://github.com/ASNSPY/asnspy-oss/blob/main/CHANGELOG.md)** - Version history
- **[Contributing](https://github.com/ASNSPY/asnspy-oss/blob/main/CONTRIBUTING.md)** - How to contribute

---

## 🗺️ Roadmap

### Near Term (Q1 2024)
- [ ] Additional CVE data sources (Vulners, CVE.org)
- [ ] IPv6 scanning improvements
- [ ] Performance optimizations
- [ ] Additional cloud provider detection (DigitalOcean, Linode, Vultr)

### Medium Term (Q2-Q3 2024)
- [ ] HTML report generation
- [ ] GraphQL API scanning
- [ ] Kubernetes cluster detection
- [ ] Container registry scanning

### Long Term (Q4 2024+)
- [ ] GUI interface (community contribution welcome)
- [ ] Machine learning for anomaly detection
- [ ] Threat intelligence integration
- [ ] Mobile app (iOS/Android)

**Vote on features:** [GitHub Discussions](https://github.com/ASNSPY/asnspy-oss/discussions)

---

## 📞 Support & Community

### Community Support
- **GitHub Issues:** [Report bugs, request features](https://github.com/ASNSPY/asnspy-oss/issues)
- **GitHub Discussions:** [Ask questions, share tips](https://github.com/ASNSPY/asnspy-oss/discussions)
- **Discord:** [Join the community](https://discord.gg/asnspy) (coming soon)

### Enterprise Support
- **Website:** [https://asnspy.com](https://asnspy.com)
- **Sales:** [sales@asnspy.com](mailto:sales@asnspy.com)
- **Documentation:** [https://docs.asnspy.com](https://docs.asnspy.com)
- **Twitter:** [@asnspy](https://twitter.com/asnspy)

---

## 📜 License

**MIT License** - see [LICENSE](LICENSE) file for details

Free for personal and commercial use. No restrictions.

---

## 🙏 Credits & Acknowledgments

ASNSPY is built on the shoulders of giants:

- **RIPE NCC** - ASN and prefix data
- **NVD (NIST)** - CVE vulnerability database
- **Certificate Transparency** - Google's CT log infrastructure
- **Team Cymru** - IP-to-ASN mapping
- **IANA** - Internet number resources

### Built With
- `curl` - HTTP client
- `jq` - JSON processor
- `openssl` - TLS/crypto operations
- `traceroute` - Network path analysis

### Inspired By
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

## 📥 Installation

### Quick Install (Any System)
```bash
# Clone and run
git clone https://github.com/ASNSPY/asnspy-oss.git
cd asnspy-oss
chmod +x asnspy.sh
./asnspy.sh AS15169
```

### Ubuntu / Debian / Mint / Pop!_OS
```bash
sudo apt update
sudo apt install -y curl jq dnsutils traceroute openssl util-linux whois netcat-openbsd
git clone https://github.com/ASNSPY/asnspy-oss.git
cd asnspy-oss
chmod +x asnspy.sh
```

### RHEL / CentOS / Rocky Linux / AlmaLinux
```bash
sudo yum install -y curl jq bind-utils traceroute openssl util-linux whois nc
# Or on newer versions:
sudo dnf install -y curl jq bind-utils traceroute openssl util-linux whois nc
git clone https://github.com/ASNSPY/asnspy-oss.git
cd asnspy-oss
chmod +x asnspy.sh
```

### Fedora
```bash
sudo dnf install -y curl jq bind-utils traceroute openssl util-linux whois nc git
git clone https://github.com/ASNSPY/asnspy-oss.git
cd asnspy-oss
chmod +x asnspy.sh
```

### Arch Linux / Manjaro
```bash
sudo pacman -S curl jq bind traceroute openssl util-linux whois gnu-netcat git
git clone https://github.com/ASNSPY/asnspy-oss.git
cd asnspy-oss
chmod +x asnspy.sh
```

### openSUSE / SUSE Linux Enterprise
```bash
sudo zypper install -y curl jq bind-utils traceroute openssl util-linux whois netcat-openbsd git
git clone https://github.com/ASNSPY/asnspy-oss.git
cd asnspy-oss
chmod +x asnspy.sh
```

### Alpine Linux
```bash
sudo apk add curl jq bind-tools traceroute openssl util-linux whois netcat-openbsd git bash
git clone https://github.com/ASNSPY/asnspy-oss.git
cd asnspy-oss
chmod +x asnspy.sh
```

### Gentoo
```bash
sudo emerge -av net-misc/curl app-misc/jq net-dns/bind-tools net-analyzer/traceroute dev-libs/openssl sys-apps/util-linux net-misc/whois net-analyzer/netcat
git clone https://github.com/ASNSPY/asnspy-oss.git
cd asnspy-oss
chmod +x asnspy.sh
```

### Void Linux
```bash
sudo xbps-install -S curl jq bind-utils traceroute openssl util-linux whois openbsd-netcat git
git clone https://github.com/ASNSPY/asnspy-oss.git
cd asnspy-oss
chmod +x asnspy.sh
```

### macOS (Homebrew)
```bash
# Install Homebrew if not already installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install dependencies
brew install curl jq bind openssl coreutils
git clone https://github.com/ASNSPY/asnspy-oss.git
cd asnspy-oss
chmod +x asnspy.sh
```

### macOS (MacPorts)
```bash
sudo port install curl jq bind9 openssl coreutils
git clone https://github.com/ASNSPY/asnspy-oss.git
cd asnspy-oss
chmod +x asnspy.sh
```

### FreeBSD
```bash
sudo pkg install curl jq bind-tools traceroute openssl whois netcat git
git clone https://github.com/ASNSPY/asnspy-oss.git
cd asnspy-oss
chmod +x asnspy.sh
```

### OpenBSD
```bash
# Most tools are in base system, install missing ones
doas pkg_add curl jq git
git clone https://github.com/ASNSPY/asnspy-oss.git
cd asnspy-oss
chmod +x asnspy.sh
```

### NetBSD
```bash
sudo pkgin install curl jq bind-tools traceroute openssl whois netcat git
git clone https://github.com/ASNSPY/asnspy-oss.git
cd asnspy-oss
chmod +x asnspy.sh
```

### Solaris / illumos / OpenIndiana
```bash
sudo pkg install curl jq bind traceroute openssl whois netcat git
git clone https://github.com/ASNSPY/asnspy-oss.git
cd asnspy-oss
chmod +x asnspy.sh
```

### Kali Linux / Parrot OS
```bash
# Most tools pre-installed
sudo apt update
sudo apt install -y curl jq
git clone https://github.com/ASNSPY/asnspy-oss.git
cd asnspy-oss
chmod +x asnspy.sh
```

### Termux (Android)
```bash
pkg update
pkg install -y curl jq bind-tools traceroute openssl whois netcat-openbsd git
git clone https://github.com/ASNSPY/asnspy-oss.git
cd asnspy-oss
chmod +x asnspy.sh
```

### NixOS
```bash
# Add to configuration.nix or use nix-shell
nix-shell -p curl jq bind traceroute openssl whois netcat git

git clone https://github.com/ASNSPY/asnspy-oss.git
cd asnspy-oss
chmod +x asnspy.sh
```

### Docker (Any System)
```bash
# Use pre-built image
docker pull asnspy/asnspy-oss:latest
docker run --rm asnspy/asnspy-oss AS15169

# Or build locally
git clone https://github.com/ASNSPY/asnspy-oss.git
cd asnspy-oss
docker build -t asnspy .
docker run --rm asnspy AS15169
```

### Windows (WSL2)
```bash
# Inside WSL2 Ubuntu/Debian
sudo apt update
sudo apt install -y curl jq dnsutils traceroute openssl util-linux whois netcat-openbsd
git clone https://github.com/ASNSPY/asnspy-oss.git
cd asnspy-oss
chmod +x asnspy.sh
./asnspy.sh AS15169
```

### Windows (Git Bash / MSYS2)
```bash
# In MSYS2 terminal
pacman -S curl jq bind traceroute openssl util-linux whois netcat git
git clone https://github.com/ASNSPY/asnspy-oss.git
cd asnspy-oss
chmod +x asnspy.sh
./asnspy.sh AS15169
```

### Chrome OS (Crostini Linux)
```bash
sudo apt update
sudo apt install -y curl jq dnsutils traceroute openssl util-linux whois netcat-openbsd
git clone https://github.com/ASNSPY/asnspy-oss.git
cd asnspy-oss
chmod +x asnspy.sh
```

### Manual Installation (No Package Manager)
```bash
# Download script directly
curl -O https://raw.githubusercontent.com/ASNSPY/asnspy-oss/main/asnspy.sh
chmod +x asnspy.sh

# Ensure dependencies are available:
# - curl, jq, dig/drill, openssl, traceroute, flock, whois (optional)
# If missing, download from source and compile

./asnspy.sh AS15169
```

### System-wide Installation (Optional)
```bash
# After cloning, install to /usr/local/bin
sudo cp asnspy.sh /usr/local/bin/asnspy
sudo chmod +x /usr/local/bin/asnspy

# Now run from anywhere
asnspy AS15169
```

## 🎯 Quick Examples

### Basic Recon
```bash
# Simple ASN scan
./asnspy.sh AS15169

# Quick scan (first 50 IPs)
./asnspy.sh AS15169 --profile quick

# Full deep scan
./asnspy.sh AS15169 --profile deep
```

### Security Audit
```bash
# Port scan + CVE detection
./asnspy.sh AS15169 --port-scan --cve

# Complete security assessment
./asnspy.sh AS15169 --profile security

# Custom security scan
./asnspy.sh AS15169 \
  --port-scan --port-scan-top 100 \
  --tls --version-detect --cve \
  --http-security --leak-scan
```

### Network Analysis
```bash
# Trace network paths
./asnspy.sh AS15169 --trace

# TLS certificate analysis
./asnspy.sh AS15169 --tls --tls-mode all

# Cloud provider detection
./asnspy.sh AS15169 --cloud-detect
```

### Advanced Usage
```bash
# High performance scan
./asnspy.sh AS15169 --parallel 100 --profile deep

# Targeted gateway scan
./asnspy.sh AS15169 --gateway-only --port-scan --tls

# Custom range with filtering
./asnspy.sh AS15169 \
  --host-range 1-100 \
  --internet-only \
  --parallel 50
```

## 📊 Output Structure

```
scans/AS#####_########/
├── prefixes.txt              # IP prefixes
├── ptr_results.txt           # IP->hostname mappings (CSV)
├── domains.txt               # Unique domains
├── ct_results.txt            # CT log subdomains
├── traceroute_results.txt    # Network paths (CSV)
├── tls_certificates.csv      # Certificate data
├── server_versions.csv       # Detected software
├── port_scan_results.csv     # Open ports
├── vulnerabilities.csv       # CVE findings
├── cloud_providers.csv       # Cloud provider data
├── http_security.csv         # Security headers
├── leak_exposures.csv        # Exposed configs
└── json/                     # JSON exports
    ├── summary.json
    ├── prefixes.json
    ├── vulnerabilities.json
    └── ...
```

## 🔧 Configuration

Create `~/.asnspyrc`:

```bash
# Performance
PARALLEL=50
TRACE_PARALLEL=10
TLS_PARALLEL=20

# Features
DO_TRACE=1
DO_TLS=1
DO_CVE=1
DO_CLOUD_DETECT=1
DO_JSON=1

# Filtering
MODE_INTERNET_ONLY=1
CVE_MIN_SEVERITY=MEDIUM
```

Generate example:
```bash
./asnspy.sh --generate-config
```

## 📖 Scan Profiles

| Profile | Description | Use Case |
|---------|-------------|----------|
| `quick` | Fast scan, first 50 IPs | Quick recon |
| `standard` | Balanced (default) | General purpose |
| `deep` | Everything enabled | Comprehensive audit |
| `stealth` | Slow, careful | Low-profile scanning |
| `security` | Vulnerability focus | Security assessment |

## 🎓 Use Cases

### Bug Bounty Hunting
```bash
# Find subdomains and vulnerabilities
./asnspy.sh AS13335 --profile deep --cve-min-severity HIGH
```

### Network Inventory
```bash
# Map organization's infrastructure
./asnspy.sh AS15169 --trace --cloud-detect
```

### Security Assessment
```bash
# Complete security audit
./asnspy.sh AS15169 --profile security --json
```

### Certificate Monitoring
```bash
# Find expiring certificates
./asnspy.sh AS15169 --tls --tls-mode all
```

## 🔒 Authorization & Legal

⚠️ **IMPORTANT**: Only scan networks you own or have explicit written permission to test.

- Port scanning requires authorization
- Leak detection requires authorization
- Unauthorized scanning may violate:
  - Computer Fraud and Abuse Act (CFAA) - USA
  - Computer Misuse Act - UK
  - Similar laws in other jurisdictions

For bug bounty programs: Ensure ASN is within defined scope.

## 🆚 Open Source vs Enterprise

### What's Included in Open Source
- ✅ All scanning capabilities (unrestricted)
- ✅ CVE vulnerability detection
- ✅ Leak/credential detection
- ✅ JSON export
- ✅ Parallel processing (unlimited)
- ✅ All scan modes and profiles
- ✅ Community support

### Enterprise-Only Features
- ❌ **ASN Range Scanning** - Scan entire industries
- ❌ **SIEM Integration** - Splunk, Elasticsearch, QRadar, etc.
- ❌ **Webhook Notifications** - Slack, Discord, Teams, PagerDuty
- ❌ **Database Tracking** - PostgreSQL, MySQL with history
- ❌ **Diff Mode** - Change detection and trending
- ❌ **Scheduling** - Automated recurring scans
- ❌ **Multi-user Access** - RBAC and team collaboration
- ❌ **Compliance Reporting** - PCI-DSS, SOC2, ISO templates
- ❌ **Priority Support** - SLA-backed assistance
- ❌ **API Access** - Programmatic integration

**Need enterprise features?** Visit [https://asnspy.com/enterprise](https://asnspy.com/enterprise)

## 💡 Why Upgrade to Enterprise?

### The Challenge
Open Source ASNSPY gives you **powerful point-in-time scans**. But running it in production requires:

1. **Scheduling System** - Cron + error handling + retries
2. **Database Schema** - PostgreSQL + migrations
3. **Data Pipeline** - CSV → DB ingestion
4. **Change Detection** - Diff algorithms
5. **SIEM Connectors** - 8 different APIs
6. **Webhook Handlers** - 5 different formats
7. **Alert Routing** - Who gets what when
8. **Web UI** - Dashboards, reports
9. **Authentication** - SSO, RBAC
10. **Compliance** - Audit trails, templates

**Engineering Cost**: 6-12 months = $300k-600k  
**Enterprise License**: $10k/year

### The Solution
Enterprise ASNSPY provides **continuous security intelligence**:

- Scan 1000s of ASNs automatically
- Store 12 months of historical data
- Alert on new vulnerabilities within 15 minutes
- Track remediation SLAs
- Generate compliance reports
- Role-based access for 50+ users
- Integrate with your security stack

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Areas We Need Help
- Additional CVE data sources
- Cloud provider detection improvements
- Performance optimizations
- Documentation improvements
- Bug reports and fixes

## 📜 License

MIT License - see [LICENSE](LICENSE) file for details.

Free for personal and educational use. Commercial use permitted.

## 🙏 Credits

Created with ❤️ by the ASNSPY team.

Built on:
- RIPE NVD API
- NVD CVE Database
- Certificate Transparency Logs
- Team Cymru IP-to-ASN

## 📞 Support

- **Community Support**: [GitHub Issues](https://github.com/ASNSPY/asnspy-oss/issues)
- **Documentation**: [https://docs.asnspy.com](https://docs.asnspy.com)
- **Enterprise Sales**: [sales@asnspy.com](mailto:sales@asnspy.com)
- **Twitter**: [@asnspy](https://twitter.com/asnspy)

## 🗺️ Roadmap

### Near Term
- [ ] Additional output formats (XML, HTML reports)
- [ ] IPv6 scanning improvements
- [ ] Additional CVE data sources
- [ ] Performance optimizations

### Long Term
- [ ] GUI interface (community contribution welcome)
- [ ] Docker container
- [ ] Kubernetes deployment
- [ ] Additional language bindings

---

**Ready to get started?**

```bash
git clone https://github.com/ASNSPY/asnspy-oss.git
cd asnspy-oss
./asnspy.sh AS15169 --profile deep
```

For enterprise features and support: **https://asnspy.com/enterprise**
