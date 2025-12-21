# ASNSPY Installation Guide

Complete installation instructions for ASNSPY Open Source Edition across all supported platforms.

## System Requirements

### Minimum Requirements
- POSIX-compliant shell
- 50MB disk space
- Internet connection

### Required Dependencies
- `curl` - HTTP client for API requests
- `jq` - JSON processor for parsing responses
- `dig` or `drill` - DNS lookup tools for reverse DNS

### Optional Dependencies
- `openssl` - TLS certificate scanning
- `traceroute` / `traceroute6` - Network path analysis
- `whois` - ASN metadata lookups
- `nc` (netcat) - Service banner grabbing
- `flock` - File locking for parallel operations

---

## Linux Distributions

### Ubuntu / Debian

```bash
sudo apt update
sudo apt install -y curl jq dnsutils traceroute openssl util-linux whois netcat-openbsd

git clone https://github.com/ASNSPY/asnspy-oss.git
cd asnspy-oss
chmod +x asnspy.sh

./asnspy.sh AS15169
```

**Install to system PATH:**
```bash
sudo cp asnspy.sh /usr/local/bin/asnspy
asnspy AS15169
```

### RHEL / CentOS / Rocky Linux / AlmaLinux

**RHEL/CentOS 7:**
```bash
sudo yum install -y curl jq bind-utils traceroute openssl util-linux whois nc

git clone https://github.com/ASNSPY/asnspy-oss.git
cd asnspy-oss
chmod +x asnspy.sh

./asnspy.sh AS15169
```

**RHEL/CentOS/Rocky/Alma 8+:**
```bash
sudo dnf install -y curl jq bind-utils traceroute openssl util-linux whois nmap-ncat

git clone https://github.com/ASNSPY/asnspy-oss.git
cd asnspy-oss
chmod +x asnspy.sh

./asnspy.sh AS15169
```

### Fedora

```bash
sudo dnf install -y curl jq bind-utils traceroute openssl util-linux whois nmap-ncat

git clone https://github.com/ASNSPY/asnspy-oss.git
cd asnspy-oss
chmod +x asnspy.sh

./asnspy.sh AS15169
```

### Alpine Linux

```bash
sudo apk add curl jq bind-tools traceroute openssl util-linux whois netcat-openbsd git

git clone https://github.com/ASNSPY/asnspy-oss.git
cd asnspy-oss
chmod +x asnspy.sh

./asnspy.sh AS15169
```

### Arch Linux / Manjaro

```bash
sudo pacman -S curl jq bind-tools traceroute openssl util-linux whois openbsd-netcat git

git clone https://github.com/ASNSPY/asnspy-oss.git
cd asnspy-oss
chmod +x asnspy.sh

./asnspy.sh AS15169
```

### openSUSE / SLES

```bash
sudo zypper install -y curl jq bind-utils traceroute openssl util-linux whois netcat-openbsd git

git clone https://github.com/ASNSPY/asnspy-oss.git
cd asnspy-oss
chmod +x asnspy.sh

./asnspy.sh AS15169
```

### Gentoo

```bash
sudo emerge --ask net-misc/curl app-misc/jq net-dns/bind-tools net-analyzer/traceroute dev-libs/openssl sys-apps/util-linux net-misc/whois net-analyzer/netcat

git clone https://github.com/ASNSPY/asnspy-oss.git
cd asnspy-oss
chmod +x asnspy.sh

./asnspy.sh AS15169
```

### Void Linux

```bash
sudo xbps-install -S curl jq bind-utils traceroute openssl util-linux whois openbsd-netcat git

git clone https://github.com/ASNSPY/asnspy-oss.git
cd asnspy-oss
chmod +x asnspy.sh

./asnspy.sh AS15169
```

### NixOS

**Temporary environment:**
```bash
nix-shell -p curl jq bind traceroute openssl util-linux whois netcat git

git clone https://github.com/ASNSPY/asnspy-oss.git
cd asnspy-oss
chmod +x asnspy.sh

./asnspy.sh AS15169
```

**Permanent installation in configuration.nix:**
```nix
environment.systemPackages = with pkgs; [
  curl
  jq
  bind
  traceroute
  openssl
  util-linux
  whois
  netcat
  git
];
```

---

## BSD Distributions

### FreeBSD

```bash
sudo pkg install curl jq bind-tools traceroute openssl whois netcat git

git clone https://github.com/ASNSPY/asnspy-oss.git
cd asnspy-oss
chmod +x asnspy.sh

./asnspy.sh AS15169
```

### OpenBSD

```bash
doas pkg_add curl jq bind-tools traceroute openssl whois netcat git

git clone https://github.com/ASNSPY/asnspy-oss.git
cd asnspy-oss
chmod +x asnspy.sh

./asnspy.sh AS15169
```

### NetBSD

```bash
sudo pkgin install curl jq bind-dig traceroute openssl whois netcat git

git clone https://github.com/ASNSPY/asnspy-oss.git
cd asnspy-oss
chmod +x asnspy.sh

./asnspy.sh AS15169
```

---

## macOS

### Using Homebrew

```bash
brew install curl jq bind traceroute openssl whois netcat git

git clone https://github.com/ASNSPY/asnspy-oss.git
cd asnspy-oss
chmod +x asnspy.sh

./asnspy.sh AS15169
```

### Using MacPorts

```bash
sudo port install curl jq bind9 traceroute openssl3 whois netcat git

git clone https://github.com/ASNSPY/asnspy-oss.git
cd asnspy-oss
chmod +x asnspy.sh

./asnspy.sh AS15169
```

---

## Solaris / illumos

### OpenIndiana

```bash
sudo pkg install curl jq bind traceroute openssl whois netcat git

git clone https://github.com/ASNSPY/asnspy-oss.git
cd asnspy-oss
chmod +x asnspy.sh

./asnspy.sh AS15169
```

### Oracle Solaris 11

```bash
sudo pkg install curl jq bind traceroute openssl whois netcat git

git clone https://github.com/ASNSPY/asnspy-oss.git
cd asnspy-oss
chmod +x asnspy.sh

./asnspy.sh AS15169
```

---

## Specialized Distributions

### Kali Linux

```bash
sudo apt update
sudo apt install -y curl jq dnsutils traceroute openssl util-linux whois netcat-openbsd

git clone https://github.com/ASNSPY/asnspy-oss.git
cd asnspy-oss
chmod +x asnspy.sh

./asnspy.sh AS15169
```

### Parrot Security OS

```bash
sudo apt update
sudo apt install -y curl jq dnsutils traceroute openssl util-linux whois netcat-openbsd

git clone https://github.com/ASNSPY/asnspy-oss.git
cd asnspy-oss
chmod +x asnspy.sh

./asnspy.sh AS15169
```

### BlackArch

```bash
sudo pacman -S curl jq bind-tools traceroute openssl util-linux whois openbsd-netcat git

git clone https://github.com/ASNSPY/asnspy-oss.git
cd asnspy-oss
chmod +x asnspy.sh

./asnspy.sh AS15169
```

---

## Windows

### WSL2 (Recommended)

**Install WSL2 with Ubuntu:**
```powershell
wsl --install -d Ubuntu
```

**Then inside WSL:**
```bash
sudo apt update
sudo apt install -y curl jq dnsutils traceroute openssl util-linux whois netcat-openbsd git

git clone https://github.com/ASNSPY/asnspy-oss.git
cd asnspy-oss
chmod +x asnspy.sh

./asnspy.sh AS15169
```

### Git Bash / MSYS2

**Install MSYS2 from https://www.msys2.org**

**Then in MSYS2 terminal:**
```bash
pacman -S curl jq bind traceroute openssl util-linux whois netcat git

git clone https://github.com/ASNSPY/asnspy-oss.git
cd asnspy-oss
chmod +x asnspy.sh

./asnspy.sh AS15169
```

### Cygwin

**Install Cygwin from https://www.cygwin.com**

**Select these packages during installation:**
- curl
- jq
- bind-utils
- traceroute
- openssl
- util-linux
- whois
- netcat
- git

**Then in Cygwin terminal:**
```bash
git clone https://github.com/ASNSPY/asnspy-oss.git
cd asnspy-oss
chmod +x asnspy.sh

./asnspy.sh AS15169
```

---

## Mobile Platforms

### Android (Termux)

**Install Termux from F-Droid or Play Store**

```bash
pkg update
pkg install -y curl jq bind-tools traceroute openssl util-linux whois netcat-openbsd git

git clone https://github.com/ASNSPY/asnspy-oss.git
cd asnspy-oss
chmod +x asnspy.sh

./asnspy.sh AS15169
```

---

## Container Platforms

### Docker

**Using official image:**
```bash
docker pull asnspy/asnspy-oss:latest
docker run -it asnspy/asnspy-oss:latest AS15169
```

**Building from source:**
```bash
git clone https://github.com/ASNSPY/asnspy-oss.git
cd asnspy-oss

docker build -t asnspy:local .
docker run -it asnspy:local AS15169
```

**Saving results locally:**
```bash
docker run -it -v $(pwd)/results:/scans asnspy/asnspy-oss:latest AS15169
```

### Podman

```bash
podman pull asnspy/asnspy-oss:latest
podman run -it asnspy/asnspy-oss:latest AS15169
```

### Kubernetes

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: asnspy-scan
spec:
  template:
    spec:
      containers:
      - name: asnspy
        image: asnspy/asnspy-oss:latest
        args: ["AS15169", "--profile", "security", "--json"]
        volumeMounts:
        - name: results
          mountPath: /scans
      volumes:
      - name: results
        persistentVolumeClaim:
          claimName: asnspy-results
      restartPolicy: Never
```

---

## Verification

After installation, verify everything works:

```bash
./asnspy.sh AS15169 --profile quick
```

Expected output:
```
========================================
        ASNSPY v3.0.0 Open Source
    Advanced ASN Reconnaissance Suite
========================================

[*] Fetching prefixes for AS15169...
[+] Found 256 prefixes to scan
[*] PTR scan: 1/256 - 8.8.8.0/24
...
```

Check dependencies:
```bash
command -v curl && echo "curl: OK"
command -v jq && echo "jq: OK"
command -v dig && echo "dig: OK" || command -v drill && echo "drill: OK"
command -v openssl && echo "openssl: OK"
command -v traceroute && echo "traceroute: OK"
```

---

## Troubleshooting

### Missing Dependencies

**Error: "command not found: jq"**
```bash
sudo apt install jq
```

**Error: "command not found: dig"**
```bash
sudo apt install dnsutils
```

**Error: "command not found: drill"**
```bash
sudo apk add bind-tools
```

### Permission Issues

**Error: "Permission denied"**
```bash
chmod +x asnspy.sh
```

**Error: "Cannot write to /usr/local/bin"**
```bash
sudo cp asnspy.sh /usr/local/bin/asnspy
```

### Network Issues

**Error: "Could not resolve host"**

Check DNS resolution:
```bash
dig google.com
```

Check internet connectivity:
```bash
curl -I https://stat.ripe.net
```

### Path Issues

**Error: "asnspy: command not found"**

Add to PATH temporarily:
```bash
export PATH="$PATH:$(pwd)"
```

Add to PATH permanently in `~/.bashrc` or `~/.zshrc`:
```bash
export PATH="$PATH:/path/to/asnspy-oss"
```

---

## Updating

### Git Update

```bash
cd asnspy-oss
git pull origin main
chmod +x asnspy.sh
```

### Docker Update

```bash
docker pull asnspy/asnspy-oss:latest
```

### Manual Update

```bash
curl -O https://raw.githubusercontent.com/ASNSPY/asnspy-oss/main/asnspy.sh
chmod +x asnspy.sh
```

---

## Uninstallation

### Remove from directory

```bash
rm -rf asnspy-oss
```

### Remove from system PATH

```bash
sudo rm /usr/local/bin/asnspy
```

### Remove Docker image

```bash
docker rmi asnspy/asnspy-oss:latest
```

---

## Next Steps

After installation:

1. **Read the README:** [https://github.com/ASNSPY/asnspy-oss](https://github.com/ASNSPY/asnspy-oss)
2. **View help:** `./asnspy.sh --help`
3. **Run quick scan:** `./asnspy.sh AS15169 --profile quick`
4. **Try security profile:** `./asnspy.sh AS15169 --profile security`

For detailed usage examples and features, see the main [README.md](https://github.com/ASNSPY/asnspy-oss/blob/main/README.md).
