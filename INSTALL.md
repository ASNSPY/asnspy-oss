# ASNSPY Installation Guide

## Quick Install (1 Minute)

```bash
# Download
curl -O https://raw.githubusercontent.com/yourusername/asnspy/main/asnspy.sh

# Make executable
chmod +x asnspy.sh

# Run
./asnspy.sh AS15169
```

That's it! ASNSPY is a single shell script with no compilation required.

## System Requirements

### Supported Operating Systems
- ✅ Ubuntu 18.04+ / Debian 9+
- ✅ RHEL/CentOS 7+
- ✅ Fedora 30+
- ✅ Alpine Linux 3.10+
- ✅ macOS 10.14+
- ✅ FreeBSD 12+
- ✅ Any POSIX-compliant Unix

### Required Dependencies
- `curl` - HTTP client
- `jq` - JSON processor
- `dig` or `drill` - DNS lookups
- `openssl` - TLS connections (for --tls)
- `traceroute` - Network paths (for --trace)
- `flock` - File locking (for parallel mode)

### Optional Dependencies
- `whois` - ASN WHOIS lookups
- `traceroute6` - IPv6 tracing
- `nc` (netcat) - Banner grabbing

## Installation by Platform

### Ubuntu / Debian
```bash
# Install dependencies
sudo apt update
sudo apt install -y curl jq dnsutils traceroute openssl util-linux whois netcat

# Download ASNSPY
wget https://github.com/ASNSPY/asnspy-oss/archive/refs/heads/main.zip
unzip main.zip
cd asnspy-oss-main

# Or clone with git
git clone https://github.com/ASNSPY/asnspy-oss.git
cd asnspy-oss

# Make executable
chmod +x asnspy.sh

# Add to PATH (optional)
sudo cp asnspy.sh /usr/local/bin/asnspy
```

### RHEL / CentOS / Fedora
```bash
# Install dependencies
sudo yum install -y curl jq bind-utils traceroute openssl util-linux whois nc

# Or on newer versions:
sudo dnf install -y curl jq bind-utils traceroute openssl util-linux whois nc

# Download ASNSPY
curl -L https://github.com/ASNSPY/asnspy-oss/archive/refs/heads/main.tar.gz | tar xz
cd asnspy-oss-main

# Make executable
chmod +x asnspy.sh

# Add to PATH (optional)
sudo cp asnspy.sh /usr/local/bin/asnspy
```

### Alpine Linux
```bash
# Install dependencies
sudo apk add curl jq bind-tools traceroute openssl util-linux whois netcat-openbsd

# Download ASNSPY
wget https://github.com/ASNSPY/asnspy-oss/archive/refs/heads/main.tar.gz
tar xzf main.tar.gz
cd asnspy-oss-main

# Make executable
chmod +x asnspy.sh
```

### macOS
```bash
# Install Homebrew (if not already installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install dependencies
brew install curl jq bind openssl

# Download ASNSPY
git clone https://github.com/ASNSPY/asnspy-oss.git
cd asnspy-oss

# Make executable
chmod +x asnspy.sh

# Add to PATH (optional)
sudo cp asnspy.sh /usr/local/bin/asnspy
```

### Docker
```bash
# Pull image
docker pull asnspy/asnspy-oss:latest

# Run scan
docker run --rm asnspy/asnspy-oss AS15169

# Run with output directory
docker run --rm -v $(pwd)/scans:/scans asnspy/asnspy-oss AS15169

# Interactive mode
docker run --rm -it asnspy/asnspy-oss /bin/sh
```

### Build Docker Image Yourself
```bash
# Clone repo
git clone https://github.com/ASNSPY/asnspy-oss.git
cd asnspy-oss

# Build
docker build -t asnspy .

# Run
docker run --rm asnspy AS15169
```

## Verification

### Check Installation
```bash
# Verify script exists
./asnspy.sh --help

# Check dependencies
./asnspy.sh AS15169 --debug
# Will show warnings for any missing tools
```

### Test Scan
```bash
# Quick test (takes 1-2 minutes)
./asnspy.sh AS15169 --profile quick

# Should output:
# - Prefixes found
# - PTR records discovered
# - Domains extracted
# - Results saved to scans/AS15169_########/
```

## Configuration

### Create Config File
```bash
# Generate example
./asnspy.sh --generate-config

# Copy to home directory
cp .asnspyrc.example ~/.asnspyrc

# Edit with your preferences
nano ~/.asnspyrc
```

### Example Configuration
```bash
# ~/.asnspyrc

# Performance
PARALLEL=50
TRACE_PARALLEL=10
TLS_PARALLEL=20
VERSION_PARALLEL=20

# Default Features
DO_TRACE=1
DO_TLS=1
DO_VERSION=1
DO_CVE=1
DO_JSON=1

# Filtering
MODE_INTERNET_ONLY=1
CVE_MIN_SEVERITY=MEDIUM

# Scan Profile
SCAN_PROFILE=security
```

### Config File Locations (Priority Order)
1. `./.asnspyrc` (current directory)
2. `~/.asnspyrc` (home directory)
3. `/etc/asnspy.conf` (system-wide)

## First Scan Tutorial

### Step 1: Basic Scan
```bash
# Scan Google's ASN
./asnspy.sh AS15169
```

This will:
- Fetch prefixes from RIPE
- Enumerate PTR records
- Extract domains
- Save results to `scans/AS15169_########/`

**Time**: 5-10 minutes for typical ASN

### Step 2: View Results
```bash
# Navigate to results
cd scans/AS15169_*/

# View prefixes
cat prefixes.txt

# View discovered hosts
cat ptr_results.txt

# View domains
cat domains.txt

# View JSON summary
cat json/summary.json | jq
```

### Step 3: Security Scan
```bash
# Run comprehensive security scan
./asnspy.sh AS15169 --profile security
```

This adds:
- TLS certificate analysis
- Version detection
- CVE vulnerability lookup
- HTTP security headers
- Cloud provider detection

**Time**: 15-30 minutes

### Step 4: Advanced Features
```bash
# Full deep scan with everything
./asnspy.sh AS15169 --profile deep

# Custom scan
./asnspy.sh AS15169 \
  --trace \
  --tls --tls-mode all \
  --port-scan --port-scan-top 100 \
  --cve --cve-min-severity HIGH \
  --leak-scan \
  --parallel 100
```

## Common Issues

### Issue: "drill/dig not found"
```bash
# Ubuntu/Debian
sudo apt install dnsutils

# RHEL/CentOS
sudo yum install bind-utils

# Alpine
sudo apk add bind-tools
```

### Issue: "jq not found"
```bash
# Ubuntu/Debian
sudo apt install jq

# RHEL/CentOS
sudo yum install jq

# macOS
brew install jq
```

### Issue: "Permission denied"
```bash
# Make script executable
chmod +x asnspy.sh

# Or run with shell directly
sh asnspy.sh AS15169
```

### Issue: "No prefixes found"
```bash
# Check ASN number format
./asnspy.sh AS15169  # Correct
./asnspy.sh 15169    # Will work (AS prefix optional)

# Check internet connectivity
curl -I https://stat.ripe.net

# Try different ASN
./asnspy.sh AS13335  # Cloudflare (always works)
```

### Issue: Scan very slow
```bash
# Increase parallelization
./asnspy.sh AS15169 --parallel 100

# Use quick profile
./asnspy.sh AS15169 --profile quick

# Scan fewer hosts
./asnspy.sh AS15169 --host-range 1-50
```

### Issue: Too much output
```bash
# Use quiet mode
./asnspy.sh AS15169 --quiet

# Disable color
./asnspy.sh AS15169 --no-color

# Both
./asnspy.sh AS15169 --quiet --no-color > scan.log
```

## Upgrading

### Check Version
```bash
./asnspy.sh --help | head -1
# ASNSPY v3.0.0-oss
```

### Update to Latest
```bash
# If installed via git
cd asnspy-oss
git pull origin main

# If downloaded as file
curl -O https://raw.githubusercontent.com/ASNSPY/asnspy-oss/main/asnspy.sh
chmod +x asnspy.sh
```

### Version History
```bash
# View changelog
curl https://raw.githubusercontent.com/ASNSPY/asnspy-oss/main/CHANGELOG.md
```

## Uninstalling

```bash
# Remove from PATH
sudo rm /usr/local/bin/asnspy

# Remove config
rm ~/.asnspyrc

# Remove scan data (CAREFUL!)
rm -rf scans/

# Remove git repo
rm -rf asnspy-oss/
```

## Next Steps

### Learn More
- Read the full [README](https://github.com/ASNSPY/asnspy-oss/blob/main/README.md)
- Check out [examples](https://github.com/ASNSPY/asnspy-oss/blob/main/EXAMPLES.md)
- Read [best practices](https://github.com/ASNSPY/asnspy-oss/blob/main/BEST_PRACTICES.md)

### Get Help
- GitHub Issues: https://github.com/ASNSPY/asnspy-oss/issues
- Documentation: https://docs.asnspy.com
- Community: https://community.asnspy.com

### Contribute
- Report bugs
- Submit pull requests
- Share your use cases
- Improve documentation

### Upgrade to Enterprise
Need automation, SIEM integration, or continuous monitoring?

**Learn more**: https://asnspy.com/enterprise  
**Free trial**: https://asnspy.com/trial  
**Contact sales**: sales@asnspy.com

---

## Quick Reference

```bash
# Basic scan
./asnspy.sh AS15169

# Security audit
./asnspy.sh AS15169 --profile security

# Fast scan
./asnspy.sh AS15169 --profile quick --parallel 100

# Full deep scan
./asnspy.sh AS15169 --profile deep

# Custom scan
./asnspy.sh AS15169 --tls --port-scan --cve

# View help
./asnspy.sh --help

# Generate config
./asnspy.sh --generate-config
```

**Happy scanning!** 🚀
