#!/bin/sh
# ASNSPY v3.0.0 -- OPEN SOURCE EDITION (POSIX COMPLIANT)
# Advanced ASN reconnaissance with network path analysis
# GitHub: https://github.com/ASNSPY/asnspy-oss

VERSION="3.0.0"

# Authorization bypass (for automation)
AUTO_CONFIRM=0  # 0 = require authorization (default), 1 = skip prompts

# ASN Range Scanning
ASN_RANGE_MODE=0  # 0 = single ASN, 1 = range mode
ASN_START=""
ASN_END=""
FETCH_PREFIXES=0  # Fetch full prefix lists in range mode
ASN_PARALLEL=1    # Parallel ASN lookups (default: 1 = serial/verbose)

# Scan parameters
SWEEP_START=1
SWEEP_END=255
PARALLEL=1

PREFIX_START=0
PREFIX_END=255

# Scan modes
SKIP_PTR=0
SKIP_DEAD=0
MODE_INTERNET_ONLY=0
MODE_STRICT_VALID=0
MODE_GATEWAY_ONLY=0

# Protocol support
DO_IPV4=1
DO_IPV6=1

# Traceroute parameters
DO_TRACE=0
TRACE_MODE="ptr"
TRACE_PARALLEL=0  # 0 = inherit from PARALLEL
MAX_HOPS=30
TRACE_TIMEOUT=5

# ASN lookup for hops
DO_HOP_ASN=1

# CT scan
DO_CT=0
CT_TIMEOUT=0  # 0 = no timeout (wait indefinitely)

# TLS scan
DO_TLS=0
TLS_MODE="ptr"  # ptr|all|gateway
TLS_PORT=443
TLS_TIMEOUT=0  # 0 = no timeout (wait indefinitely)
TLS_PARALLEL=0  # 0 = inherit from PARALLEL

# Version detection
DO_VERSION=0
VERSION_MODE="ptr"  # ptr|all|gateway
VERSION_PORTS="80,443,8080,8443"  # Comma-separated ports to check
VERSION_TIMEOUT=5
VERSION_PARALLEL=0  # 0 = inherit from PARALLEL

# CVE detection
DO_CVE=0
CVE_API="nvd"  # nvd|vulners|cveorg|all
CVE_TIMEOUT=10  # Timeout per API request
CVE_RATE_LIMIT=5  # Requests per 30 seconds (NVD limit)
CVE_MIN_SEVERITY="LOW"  # LOW|MEDIUM|HIGH|CRITICAL (default: show all)
CVE_TOTAL_TIMEOUT=0  # 0 = no timeout (wait indefinitely), N = max seconds for entire CVE phase

# JSON export
DO_JSON=0

# Cloud provider detection
DO_CLOUD_DETECT=0

# HTTP security headers
DO_HTTP_SECURITY=0
HTTP_SECURITY_MODE="ptr"  # ptr|all|gateway
HTTP_SECURITY_PORTS="80,443"
HTTP_SECURITY_TIMEOUT=5
HTTP_SECURITY_PARALLEL=0  # 0 = inherit from PARALLEL

# Port scanning
DO_PORT_SCAN=0
PORT_SCAN_MODE="ptr"  # ptr|all|gateway
PORT_SCAN_PARALLEL=0  # 0 = inherit from PARALLEL
PORT_SCAN_TIMEOUT=1
PORT_SCAN_METHOD="tcp"  # tcp|syn (syn requires root)
# Common service ports by default, or specify custom
PORT_SCAN_PORTS="21,22,23,25,53,80,110,143,443,445,3306,3389,5432,5900,6379,8080,8443,9200,27017"
PORT_SCAN_TOP_PORTS=0  # If set to N>0, scan top N ports instead of PORT_SCAN_PORTS

# Leak detection
DO_LEAK_SCAN=0
LEAK_MODE="ptr"  # ptr|all|gateway
LEAK_TIMEOUT=5
LEAK_PARALLEL=0  # 0 = inherit from PARALLEL
LEAK_CHECK_BANNERS=1
# Default ports: FTP, SSH, Telnet, SMTP, HTTP, POP3, IMAP, HTTPS, MySQL, PostgreSQL, Redis, HTTP-alt, Elasticsearch, MongoDB, RDP, VNC
LEAK_PORTS="21,22,23,25,80,110,143,443,3306,5432,6379,8080,9200,27017,3389,5900"

# Data Export & Compliance
EXPORT_FULL_INDICATORS=0  # 0 = sanitized only (default), 1 = full indicators
EXPORT_RAW_CREDENTIALS=0  # 0 = hash credentials (default), 1 = export raw (dangerous)
EXPORT_RETENTION_DAYS=30  # Default retention period

# UI/UX modes
QUIET_MODE=0
DEBUG_MODE=0
NO_COLOR=0
SCAN_PROFILE=""

# Color codes (ANSI) - will be set based on terminal
RED=''
GREEN=''
YELLOW=''
BLUE=''
CYAN=''
BOLD=''
DIM=''
NC=''

# =============================
# Initialize Colors
# =============================
init_colors() {
    if [ "$NO_COLOR" -eq 1 ] || [ ! -t 1 ]; then
        return
    fi
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    CYAN='\033[0;36m'
    BOLD='\033[1m'
    DIM='\033[2m'
    NC='\033[0m'
}

# =============================
# Logging Functions
# =============================
log_info() {
    [ "$QUIET_MODE" -eq 1 ] && return
    printf "[*] %s\n" "$1"
}

log_success() {
    [ "$QUIET_MODE" -eq 1 ] && return
    printf "${GREEN}[+]${NC} %s\n" "$1"
}

log_warning() {
    printf "${YELLOW}[!]${NC} %s\n" "$1" >&2
}

log_error() {
    printf "${RED}[!] ERROR:${NC} %s\n" "$1" >&2
}

log_debug() {
    [ "$DEBUG_MODE" -eq 0 ] && return
    printf "${DIM}[DEBUG]${NC} %s\n" "$1" >&2
}

log_header() {
    [ "$QUIET_MODE" -eq 1 ] && return
    printf "\n${GREEN}${BOLD}========================================${NC}\n"
    printf "${GREEN}${BOLD}%s${NC}\n" "$1"
    printf "${GREEN}${BOLD}========================================${NC}\n"
}

log_progress() {
    [ "$QUIET_MODE" -eq 1 ] && return
    printf "\r${CYAN}[*]${NC} %s" "$1"
}

# Highlight important values (IPs, counts, filenames)
log_highlight() {
    printf "${CYAN}%s${NC}" "$1"
}

# =============================
# Scan Profiles
# =============================
apply_scan_profile() {
    case "$SCAN_PROFILE" in
        quick)
            log_info "Applying QUICK scan profile"
            PARALLEL=50
            SKIP_PTR=0
            DO_TRACE=0
            DO_CT=0
            DO_TLS=0
            DO_VERSION=0
            DO_CVE=0
            MODE_INTERNET_ONLY=1
            SWEEP_START=1
            SWEEP_END=50
            ;;
        standard)
            log_info "Applying STANDARD scan profile (default)"
            # Keep defaults
            ;;
        deep)
            log_info "Applying DEEP scan profile (comprehensive)"
            PARALLEL=100
            TRACE_PARALLEL=20
            TLS_PARALLEL=20
            VERSION_PARALLEL=20
            HTTP_SECURITY_PARALLEL=20
            PORT_SCAN_PARALLEL=100
            LEAK_PARALLEL=30
            DO_TRACE=1
            DO_CT=1
            DO_TLS=1
            DO_VERSION=1
            DO_CVE=1
            DO_CLOUD_DETECT=1
            DO_HTTP_SECURITY=1
            DO_LEAK_SCAN=1
            FETCH_PREFIXES=1
            DO_JSON=1
            ;;
        stealth)
            log_info "Applying STEALTH scan profile (slow and careful)"
            PARALLEL=1
            TRACE_PARALLEL=1
            TLS_PARALLEL=1
            VERSION_PARALLEL=1
            HTTP_SECURITY_PARALLEL=1
            PORT_SCAN_PARALLEL=1
            LEAK_PARALLEL=1
            DO_TRACE=1
            DO_TLS=1
            DO_VERSION=1
            # Add delays between requests
            STEALTH_MODE=1
            ;;
        security)
            log_info "Applying SECURITY scan profile (vulnerabilities focus)"
            PARALLEL=20
            TLS_PARALLEL=20
            VERSION_PARALLEL=20
            HTTP_SECURITY_PARALLEL=20
            PORT_SCAN_PARALLEL=100
            LEAK_PARALLEL=20
            DO_TLS=1
            DO_VERSION=1
            DO_CVE=1
            DO_HTTP_SECURITY=1
            DO_CLOUD_DETECT=1
            DO_LEAK_SCAN=1
            CVE_MIN_SEVERITY="MEDIUM"
            DO_JSON=1
            ;;
        *)
            if [ -n "$SCAN_PROFILE" ]; then
                log_error "Unknown profile: $SCAN_PROFILE"
                echo "Available profiles: quick, standard, deep, stealth, security"
                exit 1
            fi
            ;;
    esac
}

# =============================
# Config File Support
# =============================
load_config_file() {
    CONFIG_FILE=""
    
    # Check for config file in order of priority
    if [ -f ".asnspyrc" ]; then
        CONFIG_FILE=".asnspyrc"
    elif [ -f "$HOME/.asnspyrc" ]; then
        CONFIG_FILE="$HOME/.asnspyrc"
    elif [ -f "/etc/asnspy.conf" ]; then
        CONFIG_FILE="/etc/asnspy.conf"
    fi
    
    if [ -z "$CONFIG_FILE" ]; then
        return
    fi
    
    log_debug "Loading config from: $CONFIG_FILE"
    
    # Parse config file (simple KEY=VALUE format)
    while IFS='=' read -r key value; do
        # Skip comments and empty lines
        case "$key" in
            \#*|'') continue ;;
        esac
        
        # Remove leading/trailing whitespace and quotes
        key=$(echo "$key" | sed 's/^ *//;s/ *$//')
        value=$(echo "$value" | sed 's/^ *//;s/ *$//;s/^"//;s/"$//')
        
        # Set variables
        case "$key" in
            PARALLEL) PARALLEL="$value" ;;
            TRACE_PARALLEL) TRACE_PARALLEL="$value" ;;
            TLS_PARALLEL) TLS_PARALLEL="$value" ;;
            VERSION_PARALLEL) VERSION_PARALLEL="$value" ;;
            ASN_PARALLEL) ASN_PARALLEL="$value" ;;
            DO_TRACE) DO_TRACE="$value" ;;
            DO_CT) DO_CT="$value" ;;
            DO_TLS) DO_TLS="$value" ;;
            DO_VERSION) DO_VERSION="$value" ;;
            DO_CVE) DO_CVE="$value" ;;
            DO_JSON) DO_JSON="$value" ;;
            DO_CLOUD_DETECT) DO_CLOUD_DETECT="$value" ;;
            DO_HTTP_SECURITY) DO_HTTP_SECURITY="$value" ;;
            QUIET_MODE) QUIET_MODE="$value" ;;
            DEBUG_MODE) DEBUG_MODE="$value" ;;
            SCAN_PROFILE) SCAN_PROFILE="$value" ;;
            CVE_MIN_SEVERITY) CVE_MIN_SEVERITY="$value" ;;
            FETCH_PREFIXES) FETCH_PREFIXES="$value" ;;
            MODE_INTERNET_ONLY) MODE_INTERNET_ONLY="$value" ;;
            SKIP_DEAD) SKIP_DEAD="$value" ;;
            DO_SIEM) DO_SIEM="$value" ;;
            SIEM_TYPE) SIEM_TYPE="$value" ;;
            SIEM_HOST) SIEM_HOST="$value" ;;
            SIEM_TOKEN) SIEM_TOKEN="$value" ;;
            SIEM_INDEX) SIEM_INDEX="$value" ;;
            SIEM_PROTOCOL) SIEM_PROTOCOL="$value" ;;
            DO_DATABASE) DO_DATABASE="$value" ;;
            DB_TYPE) DB_TYPE="$value" ;;
            DB_FILE) DB_FILE="$value" ;;
            DB_HOST) DB_HOST="$value" ;;
            DB_PORT) DB_PORT="$value" ;;
            DB_NAME) DB_NAME="$value" ;;
            DB_USER) DB_USER="$value" ;;
            DB_PASS) DB_PASS="$value" ;;
            DO_DIFF) DO_DIFF="$value" ;;
            DIFF_BASELINE) DIFF_BASELINE="$value" ;;
            DIFF_DIR) DIFF_DIR="$value" ;;
            DIFF_ALERT_NEW_CRITICAL) DIFF_ALERT_NEW_CRITICAL="$value" ;;
            EXPORT_FULL_INDICATORS) EXPORT_FULL_INDICATORS="$value" ;;
            EXPORT_RAW_CREDENTIALS) EXPORT_RAW_CREDENTIALS="$value" ;;
            EXPORT_RETENTION_DAYS) EXPORT_RETENTION_DAYS="$value" ;;
        esac
    done < "$CONFIG_FILE"
    
    log_info "Loaded configuration from $CONFIG_FILE"
}


# =============================
# Webhook Notifications System
# =============================

# Webhook variables
DO_WEBHOOKS=0
WEBHOOK_URL=""
WEBHOOK_TYPE=""          # slack|discord|teams|pagerduty|generic
WEBHOOK_EVENTS="scan_complete"  # Comma-separated: scan_start,scan_complete,critical_finding,error
WEBHOOK_SEVERITY="HIGH"  # Minimum severity to trigger: LOW|MEDIUM|HIGH|CRITICAL
WEBHOOK_TIMEOUT=10       # Timeout for webhook requests

# Convert severity to numeric value for comparison
severity_to_num() {
    # Enterprise feature - removed from OSS
    return 0
}


# Check if event should trigger webhook
should_send_webhook() {
    # Enterprise feature - removed from OSS
    return 0
}


# Escape JSON strings
json_escape() {
    # Enterprise feature - removed from OSS
    return 0
}


# Build Slack webhook payload
build_slack_payload() {
    # Enterprise feature - removed from OSS
    return 0
}


# Build Discord webhook payload
build_discord_payload() {
    # Enterprise feature - removed from OSS
    return 0
}


# Build Microsoft Teams webhook payload
build_teams_payload() {
    # Enterprise feature - removed from OSS
    return 0
}


# Build PagerDuty event payload
build_pagerduty_payload() {
    # Enterprise feature - removed from OSS
    return 0
}


# Build generic webhook payload
build_generic_payload() {
    # Enterprise feature - removed from OSS
    return 0
}


# Main webhook send function
send_webhook() {
    # Enterprise feature - removed from OSS
    return 0
}


# Helper: Send scan start notification
webhook_scan_start() {
    FIELDS='[
        {"title": "ASN", "value": "'"$ASN"'", "short": true},
        {"title": "Profile", "value": "'"${SCAN_PROFILE:-standard}"'", "short": true},
        {"title": "Scan ID", "value": "'"$SCAN_HASH"'", "short": false}
    ]'
    
    send_webhook "scan_start"         "ÃƒÂ°Ã…Â¸Ã¢â‚¬ÂÃ‚Â ASNSPY Scan Started"         "Security reconnaissance scan initiated for $ASN"         "$FIELDS"         "LOW"
}

# Helper: Send scan complete notification
webhook_scan_complete() {
    DURATION="$1"
    
    # Count findings from files
    VULNS=0
    CRITICAL_VULNS=0
    LEAKS=0
    CRITICAL_LEAKS=0
    
    if [ -f "$CVE_CSV" ]; then
        VULNS=$(awk 'NR>1' "$CVE_CSV" | wc -l)
        CRITICAL_VULNS=$(awk -F, 'NR>1 && $6=="CRITICAL"' "$CVE_CSV" | wc -l)
    fi
    
    if [ -f "$LEAK_CSV" ]; then
        LEAKS=$(awk 'NR>1' "$LEAK_CSV" | wc -l)
        CRITICAL_LEAKS=$(awk -F, 'NR>1 && $4=="CRITICAL"' "$LEAK_CSV" | wc -l)
    fi
    
    TOTAL_CRITICAL=$((CRITICAL_VULNS + CRITICAL_LEAKS))
    
    FIELDS='[
        {"title": "ASN", "value": "'"$ASN"'", "short": true},
        {"title": "Duration", "value": "'"$DURATION"'", "short": true},
        {"title": "Vulnerabilities", "value": "'"$VULNS"'", "short": true},
        {"title": "Critical Findings", "value": "'"$TOTAL_CRITICAL"'", "short": true},
        {"title": "Exposures", "value": "'"$LEAKS"'", "short": true},
        {"title": "Results", "value": "'"$OUTDIR"'", "short": false}
    ]'
    
    if [ "$TOTAL_CRITICAL" -gt 0 ]; then
        MESSAGE="ÃƒÂ¢Ã…Â¡Ã‚Â ÃƒÂ¯Ã‚Â¸Ã‚Â Scan complete with $TOTAL_CRITICAL CRITICAL findings requiring immediate attention"
        SEVERITY="CRITICAL"
    elif [ "$VULNS" -gt 0 ] || [ "$LEAKS" -gt 0 ]; then
        MESSAGE="Scan complete with $((VULNS + LEAKS)) total findings"
        SEVERITY="HIGH"
    else
        MESSAGE="Scan complete - no vulnerabilities detected"
        SEVERITY="LOW"
    fi
    
    send_webhook "scan_complete"         "ÃƒÂ¢Ã…â€œÃ¢â‚¬Â¦ ASNSPY Scan Complete"         "$MESSAGE"         "$FIELDS"         "$SEVERITY"
}

# Helper: Send critical finding notification
webhook_critical_finding() {
    FINDING_TYPE="$1"  # vulnerability, leak, certificate
    DETAILS="$2"       # Description of finding
    IP="$3"
    
    FIELDS='[
        {"title": "ASN", "value": "'"$ASN"'", "short": true},
        {"title": "Finding Type", "value": "'"$FINDING_TYPE"'", "short": true},
        {"title": "IP Address", "value": "'"$IP"'", "short": true},
        {"title": "Severity", "value": "CRITICAL", "short": true}
    ]'
    
    send_webhook "critical_finding"         "ÃƒÂ°Ã…Â¸Ã…Â¡Ã‚Â¨ CRITICAL Security Finding"         "$DETAILS"         "$FIELDS"         "CRITICAL"
}

# Helper: Send error notification
webhook_error() {
    ERROR_MSG="$1"
    PHASE="$2"
    
    FIELDS='[
        {"title": "ASN", "value": "'"$ASN"'", "short": true},
        {"title": "Phase", "value": "'"$PHASE"'", "short": true},
        {"title": "Scan ID", "value": "'"$SCAN_HASH"'", "short": false}
    ]'
    
    send_webhook "error"         "ÃƒÂ¢Ã‚ÂÃ…â€™ ASNSPY Scan Error"         "$ERROR_MSG"         "$FIELDS"         "HIGH"
}

# =============================
# SIEM Integration Module
# =============================
# Supports: Splunk, Elasticsearch, QRadar, ArcSight, Graylog, Sumo Logic, Syslog

# SIEM Configuration Variables
DO_SIEM=0
SIEM_TYPE=""           # splunk|elasticsearch|qradar|arcsight|graylog|sumologic|syslog
SIEM_HOST=""           # hostname:port
SIEM_TOKEN=""          # Authentication token/API key
SIEM_INDEX=""          # Splunk index or Elasticsearch index
SIEM_PROTOCOL="https"  # https|http|tcp|udp
SIEM_TIMEOUT=10        # Timeout for SIEM requests
SIEM_BATCH_SIZE=100    # Batch events before sending
SIEM_RETRY_COUNT=3     # Number of retries on failure

# SIEM event buffer (for batching)
SIEM_BUFFER_FILE=""

# =============================
# Initialize SIEM
# =============================
init_siem() {
    # Enterprise feature - removed from OSS
    return 0
}


# =============================
# JSON Escape Helper
# =============================
siem_json_escape() {
    echo "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\t/\\t/g; s/\r/\\r/g' | tr -d '\n'
}

# =============================
# Build Splunk HEC Payload
# =============================
build_splunk_payload() {
    # Enterprise feature - removed from OSS
    return 0
}


# =============================
# Build Elasticsearch Payload
# =============================
build_elasticsearch_payload() {
    # Enterprise feature - removed from OSS
    return 0
}


# =============================
# Build CEF Payload (QRadar/ArcSight)
# =============================
build_cef_payload() {
    # Enterprise feature - removed from OSS
    return 0
}


# =============================
# Build GELF Payload (Graylog)
# =============================
build_gelf_payload() {
    # Enterprise feature - removed from OSS
    return 0
}


# =============================
# Build Sumo Logic Payload
# =============================
build_sumologic_payload() {
    # Enterprise feature - removed from OSS
    return 0
}


# =============================
# Send to SIEM
# =============================
send_to_siem() {
    # Enterprise feature - removed from OSS
    return 0
}


# =============================
# Helper: Send Vulnerability to SIEM
# =============================
siem_send_vulnerability() {
    IP="$1"
    PORT="$2"
    CVE="$3"
    SEVERITY="$4"
    DESCRIPTION="$5"
    
    DATA=$(cat << VULNDATA
{
  "finding_type": "vulnerability",
  "ip": "$IP",
  "port": $PORT,
  "cve": "$CVE",
  "description": "$(siem_json_escape "$DESCRIPTION")"
}
VULNDATA
)
    
    send_to_siem "vulnerability" "$SCAN_HASH" "$ASN" "$SEVERITY" "$DATA" "$IP" "$PORT" "Vulnerability $CVE detected"
}

# =============================
# Helper: Send Leak to SIEM
# =============================
siem_send_leak() {
    IP="$1"
    URL="$2"
    LEAK_TYPE="$3"
    SEVERITY="$4"
    
    DATA=$(cat << LEAKDATA
{
  "finding_type": "credential_leak",
  "ip": "$IP",
  "url": "$(siem_json_escape "$URL")",
  "leak_type": "$LEAK_TYPE"
}
LEAKDATA
)
    
    send_to_siem "credential_leak" "$SCAN_HASH" "$ASN" "$SEVERITY" "$DATA" "$IP" "" "Credential leak detected"
}

# =============================
# Helper: Send Certificate Issue to SIEM
# =============================
siem_send_cert_issue() {
    IP="$1"
    PORT="$2"
    CN="$3"
    ISSUE_TYPE="$4"
    SEVERITY="$5"
    DAYS_REMAINING="${6:-}"
    
    DATA=$(cat << CERTDATA
{
  "finding_type": "certificate_issue",
  "ip": "$IP",
  "port": $PORT,
  "cn": "$(siem_json_escape "$CN")",
  "issue_type": "$ISSUE_TYPE",
  "days_remaining": "$DAYS_REMAINING"
}
CERTDATA
)
    
    send_to_siem "certificate_issue" "$SCAN_HASH" "$ASN" "$SEVERITY" "$DATA" "$IP" "$PORT" "Certificate issue: $ISSUE_TYPE"
}

# =============================
# Helper: Send Scan Complete to SIEM
# =============================
siem_send_scan_complete() {
    DURATION="$1"
    FINDINGS_TOTAL="$2"
    FINDINGS_CRITICAL="${3:-0}"
    FINDINGS_HIGH="${4:-0}"
    
    # Determine severity based on findings
    if [ "$FINDINGS_CRITICAL" -gt 0 ]; then
        SEVERITY="CRITICAL"
    elif [ "$FINDINGS_HIGH" -gt 0 ]; then
        SEVERITY="HIGH"
    else
        SEVERITY="LOW"
    fi
    
    DATA=$(cat << COMPLETEDATA
{
  "finding_type": "scan_complete",
  "duration_seconds": $DURATION,
  "findings_total": $FINDINGS_TOTAL,
  "findings_critical": $FINDINGS_CRITICAL,
  "findings_high": $FINDINGS_HIGH
}
COMPLETEDATA
)
    
    send_to_siem "scan_complete" "$SCAN_HASH" "$ASN" "$SEVERITY" "$DATA" "" "" "Scan completed with $FINDINGS_TOTAL findings"
}

# =============================
# Flush SIEM Buffer (if batching)
# =============================
flush_siem_buffer() {
    [ "$DO_SIEM" -eq 0 ] && return 0
    [ ! -f "$SIEM_BUFFER_FILE" ] && return 0
    
    # For future batch implementation
    # Currently sending events immediately
    
    return 0
}

# =============================
# Database Support Module
# =============================
# Supports: SQLite (default), PostgreSQL, MySQL/MariaDB

# Database Configuration Variables
DO_DATABASE=0
DB_TYPE="sqlite"       # sqlite|postgresql|mysql
DB_FILE="asnspy.db"    # For SQLite
DB_HOST=""             # For PostgreSQL/MySQL
DB_PORT=""             # 5432 for PostgreSQL, 3306 for MySQL
DB_NAME="asnspy"
DB_USER=""
DB_PASS=""
DB_TIMEOUT=10

# Database connection info
DB_INITIALIZED=0
DB_CONN_STRING=""

# =============================
# Database Schema Version
# =============================
DB_SCHEMA_VERSION=1

# =============================
# Initialize Database Connection
# =============================
init_database() {
    # Enterprise feature - removed from OSS
    return 0
}


# =============================
# Execute SQL (with proper escaping)
# =============================
db_exec() {
    # Enterprise feature - removed from OSS
    return 0
}


# =============================
# Create Database Schema
# =============================
create_database_schema() {
    # Enterprise feature - removed from OSS
    return 0
}


# =============================
# SQL Escape Helper
# =============================
sql_escape() {
    # Enterprise feature - removed from OSS
    return 0
}


# =============================
# Insert Scan Record
# =============================
db_insert_scan() {
    SCAN_ID="$1"
    ASN_VAL="$2"
    SCAN_HASH_VAL="$3"
    PROFILE_VAL="$4"
    OUTPUT_DIR_VAL="$5"
    
    [ "$DB_INITIALIZED" -eq 0 ] && return 0
    
    TIMESTAMP=$(date -u '+%Y-%m-%d %H:%M:%S')
    
    SQL="INSERT INTO scans (scan_id, asn, start_time, scan_hash, profile, output_dir, status)
         VALUES ('$(sql_escape "$SCAN_ID")', 
                 '$(sql_escape "$ASN_VAL")', 
                 '$TIMESTAMP',
                 '$(sql_escape "$SCAN_HASH_VAL")', 
                 '$(sql_escape "$PROFILE_VAL")', 
                 '$(sql_escape "$OUTPUT_DIR_VAL")',
                 'running');"
    
    db_exec "$SQL"
    log_debug "Scan record inserted: $SCAN_ID"
}

# =============================
# Update Scan Record (completion)
# =============================
db_update_scan() {
    SCAN_ID="$1"
    DURATION="$2"
    STATUS="$3"
    
    [ "$DB_INITIALIZED" -eq 0 ] && return 0
    
    TIMESTAMP=$(date -u '+%Y-%m-%d %H:%M:%S')
    
    SQL="UPDATE scans 
         SET end_time='$TIMESTAMP', 
             duration_seconds=$DURATION, 
             status='$(sql_escape "$STATUS")'
         WHERE scan_id='$(sql_escape "$SCAN_ID")';"
    
    db_exec "$SQL"
    log_debug "Scan record updated: $SCAN_ID"
}

# =============================
# Insert Finding
# =============================
db_insert_finding() {
    SCAN_ID="$1"
    FINDING_TYPE="$2"
    SEVERITY="$3"
    IP="$4"
    PORT="$5"
    DETAILS="$6"
    CVE_ID="${7:-}"
    PRODUCT="${8:-}"
    VERSION="${9:-}"
    
    [ "$DB_INITIALIZED" -eq 0 ] && return 0
    
    HOSTNAME=$(grep "^$IP," "$PTR_FILE" 2>/dev/null | cut -d, -f2 | head -1)
    [ -z "$HOSTNAME" ] && HOSTNAME=""
    
    SQL="INSERT INTO findings (scan_id, finding_type, severity, ip, port, hostname, details, cve_id, product, version)
         VALUES ('$(sql_escape "$SCAN_ID")', 
                 '$(sql_escape "$FINDING_TYPE")', 
                 '$(sql_escape "$SEVERITY")', 
                 '$(sql_escape "$IP")', 
                 $PORT,
                 '$(sql_escape "$HOSTNAME")', 
                 '$(sql_escape "$DETAILS")', 
                 '$(sql_escape "$CVE_ID")', 
                 '$(sql_escape "$PRODUCT")', 
                 '$(sql_escape "$VERSION")');"
    
    db_exec "$SQL"
}

# =============================
# Insert or Update Asset
# =============================
db_upsert_asset() {
    IP="$1"
    ASN_VAL="$2"
    HOSTNAME="$3"
    CLOUD_PROVIDER="${4:-}"
    
    [ "$DB_INITIALIZED" -eq 0 ] && return 0
    
    # Check if asset exists
    EXISTS=$(db_exec "SELECT COUNT(*) FROM assets WHERE ip='$(sql_escape "$IP")';")
    
    if [ "$EXISTS" = "0" ]; then
        # Insert new asset
        SQL="INSERT INTO assets (ip, asn, hostname, cloud_provider)
             VALUES ('$(sql_escape "$IP")', 
                     '$(sql_escape "$ASN_VAL")', 
                     '$(sql_escape "$HOSTNAME")', 
                     '$(sql_escape "$CLOUD_PROVIDER")');"
    else
        # Update existing asset
        TIMESTAMP=$(date -u '+%Y-%m-%d %H:%M:%S')
        SQL="UPDATE assets 
             SET last_seen='$TIMESTAMP', 
                 hostname='$(sql_escape "$HOSTNAME")',
                 is_active=1"
        
        [ -n "$CLOUD_PROVIDER" ] && SQL="$SQL, cloud_provider='$(sql_escape "$CLOUD_PROVIDER")'"
        
        SQL="$SQL WHERE ip='$(sql_escape "$IP")';"
    fi
    
    db_exec "$SQL"
}

# =============================
# Insert or Update Vulnerability
# =============================
db_upsert_vulnerability() {
    CVE_ID="$1"
    SEVERITY="$2"
    DESCRIPTION="$3"
    
    [ "$DB_INITIALIZED" -eq 0 ] && return 0
    
    # Extract CVSS score from description if present
    CVSS_SCORE="NULL"
    
    EXISTS=$(db_exec "SELECT COUNT(*) FROM vulnerabilities WHERE cve_id='$(sql_escape "$CVE_ID")';")
    
    TIMESTAMP=$(date -u '+%Y-%m-%d %H:%M:%S')
    
    if [ "$EXISTS" = "0" ]; then
        SQL="INSERT INTO vulnerabilities (cve_id, severity, description, first_detected, last_detected)
             VALUES ('$(sql_escape "$CVE_ID")', 
                     '$(sql_escape "$SEVERITY")', 
                     '$(sql_escape "$DESCRIPTION")', 
                     '$TIMESTAMP',
                     '$TIMESTAMP');"
    else
        SQL="UPDATE vulnerabilities 
             SET last_detected='$TIMESTAMP',
                 severity='$(sql_escape "$SEVERITY")'
             WHERE cve_id='$(sql_escape "$CVE_ID")';"
    fi
    
    db_exec "$SQL"
}

# =============================
# Insert Certificate
# =============================
db_insert_certificate() {
    SCAN_ID="$1"
    IP="$2"
    PORT="$3"
    CN="$4"
    SANS="$5"
    ISSUER="$6"
    DAYS_REMAINING="$7"
    IS_EXPIRED="$8"
    IS_SELF_SIGNED="$9"
    
    [ "$DB_INITIALIZED" -eq 0 ] && return 0
    
    SQL="INSERT INTO certificates (scan_id, ip, port, cn, sans, issuer, days_remaining, is_expired, is_self_signed)
         VALUES ('$(sql_escape "$SCAN_ID")', 
                 '$(sql_escape "$IP")', 
                 $PORT,
                 '$(sql_escape "$CN")', 
                 '$(sql_escape "$SANS")', 
                 '$(sql_escape "$ISSUER")', 
                 $DAYS_REMAINING,
                 $IS_EXPIRED,
                 $IS_SELF_SIGNED);"
    
    db_exec "$SQL"
}

# =============================
# Update Scan Statistics
# =============================
db_update_scan_stats() {
    SCAN_ID="$1"
    
    [ "$DB_INITIALIZED" -eq 0 ] && return 0
    
    # Count findings by severity
    CRITICAL=$(db_exec "SELECT COUNT(*) FROM findings WHERE scan_id='$(sql_escape "$SCAN_ID")' AND severity='CRITICAL';")
    HIGH=$(db_exec "SELECT COUNT(*) FROM findings WHERE scan_id='$(sql_escape "$SCAN_ID")' AND severity='HIGH';")
    MEDIUM=$(db_exec "SELECT COUNT(*) FROM findings WHERE scan_id='$(sql_escape "$SCAN_ID")' AND severity='MEDIUM';")
    LOW=$(db_exec "SELECT COUNT(*) FROM findings WHERE scan_id='$(sql_escape "$SCAN_ID")' AND severity='LOW';")
    TOTAL=$(db_exec "SELECT COUNT(*) FROM findings WHERE scan_id='$(sql_escape "$SCAN_ID")';")
    
    # Count prefixes and hosts
    PREFIXES=0
    HOSTS=0
    [ -f "$PREFIX_FILE" ] && PREFIXES=$(wc -l < "$PREFIX_FILE")
    [ -f "$PTR_FILE" ] && HOSTS=$(wc -l < "$PTR_FILE")
    
    SQL="UPDATE scans 
         SET findings_total=$TOTAL,
             findings_critical=$CRITICAL,
             findings_high=$HIGH,
             findings_medium=$MEDIUM,
             findings_low=$LOW,
             prefixes_count=$PREFIXES,
             hosts_discovered=$HOSTS
         WHERE scan_id='$(sql_escape "$SCAN_ID")';"
    
    db_exec "$SQL"
    log_debug "Scan statistics updated: $SCAN_ID"
}

# =============================
# Get Latest Scan ID
# =============================
db_get_latest_scan() {
    ASN_VAL="$1"
    
    [ "$DB_INITIALIZED" -eq 0 ] && return 1
    
    LATEST=$(db_exec "SELECT scan_id FROM scans WHERE asn='$(sql_escape "$ASN_VAL")' AND status='completed' ORDER BY end_time DESC LIMIT 1;")
    
    echo "$LATEST"
}

# =============================
# Import CSV Data to Database
# =============================
db_import_csv_data() {
    SCAN_ID="$1"
    
    [ "$DB_INITIALIZED" -eq 0 ] && return 0
    
    log_info "Importing scan data to database..."
    
    # Import CVE findings
    if [ -f "$CVE_CSV" ] && [ $(wc -l < "$CVE_CSV") -gt 1 ]; then
        awk -F, 'NR>1 {print $0}' "$CVE_CSV" | while IFS=',' read IP PORT PRODUCT VERSION CVE_ID SEVERITY DESCRIPTION; do
            # Clean fields
            IP=$(echo "$IP" | tr -d '"')
            PRODUCT=$(echo "$PRODUCT" | tr -d '"')
            VERSION=$(echo "$VERSION" | tr -d '"')
            CVE_ID=$(echo "$CVE_ID" | tr -d '"')
            SEVERITY=$(echo "$SEVERITY" | tr -d '"')
            DESCRIPTION=$(echo "$DESCRIPTION" | tr -d '"' | cut -c1-200)
            
            # Insert finding
            db_insert_finding "$SCAN_ID" "vulnerability" "$SEVERITY" "$IP" "$PORT" "$DESCRIPTION" "$CVE_ID" "$PRODUCT" "$VERSION"
            
            # Update vulnerability record
            db_upsert_vulnerability "$CVE_ID" "$SEVERITY" "$DESCRIPTION"
        done
    fi
    
    # Import TLS certificate data
    if [ -f "$TLS_CSV" ] && [ $(wc -l < "$TLS_CSV") -gt 1 ]; then
        awk -F, 'NR>1 {print $0}' "$TLS_CSV" | while IFS=',' read IP PORT CN SAN_COUNT SANS ORG COUNTRY ISSUER ISSUER_ORG VALID_FROM VALID_TO DAYS_REMAINING STATUS REST; do
            # Clean fields
            IP=$(echo "$IP" | tr -d '"')
            CN=$(echo "$CN" | tr -d '"')
            ISSUER=$(echo "$ISSUER" | tr -d '"')
            
            IS_EXPIRED=0
            [ "$STATUS" = "expired" ] && IS_EXPIRED=1
            
            IS_SELF_SIGNED=0
            echo "$REST" | grep -q "yes" && IS_SELF_SIGNED=1
            
            # Insert certificate
            db_insert_certificate "$SCAN_ID" "$IP" "$PORT" "$CN" "$SANS" "$ISSUER" "$DAYS_REMAINING" "$IS_EXPIRED" "$IS_SELF_SIGNED"
            
            # If expired or expiring soon, create finding
            if [ "$IS_EXPIRED" -eq 1 ]; then
                db_insert_finding "$SCAN_ID" "certificate" "HIGH" "$IP" "$PORT" "Expired TLS certificate: $CN"
            elif [ "$DAYS_REMAINING" -lt 30 ] && [ "$DAYS_REMAINING" -ge 0 ]; then
                db_insert_finding "$SCAN_ID" "certificate" "MEDIUM" "$IP" "$PORT" "TLS certificate expiring in $DAYS_REMAINING days: $CN"
            fi
        done
    fi
    
    # Import assets (from PTR records)
    if [ -f "$PTR_FILE" ] && [ -s "$PTR_FILE" ]; then
        while IFS=',' read IP HOSTNAME; do
            db_upsert_asset "$IP" "$ASN" "$HOSTNAME"
        done < "$PTR_FILE"
    fi
    
    # Update final statistics
    db_update_scan_stats "$SCAN_ID"
    
    log_success "Database import complete"
}

# =============================
# Finalize Database (at scan end)
# =============================
db_finalize_scan() {
    SCAN_ID="$1"
    DURATION="$2"
    
    [ "$DB_INITIALIZED" -eq 0 ] && return 0
    
    # Import all CSV data
    db_import_csv_data "$SCAN_ID"
    
    # Mark scan as completed
    db_update_scan "$SCAN_ID" "$DURATION" "completed"
    
    log_success "Scan data stored in database"
}

# =============================
# Diff Mode Module
# =============================
# Compare scans to detect changes and new findings

# Diff Mode Configuration Variables
DO_DIFF=0
DIFF_BASELINE=""           # Scan ID to compare against, or "LATEST"
DIFF_DIR=""                # Alternative: path to previous scan directory
DIFF_ALERT_NEW_CRITICAL=1  # Alert on new critical findings
DIFF_REPORT=""             # Path to diff report file

# Diff results tracking
DIFF_NEW_ASSETS=0
DIFF_REMOVED_ASSETS=0
DIFF_NEW_VULNS=0
DIFF_RESOLVED_VULNS=0
DIFF_NEW_CRITICAL=0
DIFF_NEW_LEAKS=0
DIFF_CERT_CHANGES=0

# =============================
# Initialize Diff Mode
# =============================
init_diff_mode() {
    [ "$DO_DIFF" -eq 0 ] && return 0
    
    log_info "Initializing diff mode: baseline=$DIFF_BASELINE"
    
    # Determine baseline scan
    if [ "$DIFF_BASELINE" = "LATEST" ]; then
        # Get latest scan from database
        if [ "$DO_DATABASE" -eq 1 ] && [ "$DB_INITIALIZED" -eq 1 ]; then
            BASELINE_SCAN_ID=$(db_get_latest_scan "$ASN")
            if [ -n "$BASELINE_SCAN_ID" ]; then
                log_info "Using latest scan from database: $BASELINE_SCAN_ID"
                DIFF_BASELINE="$BASELINE_SCAN_ID"
            else
                log_warning "No previous scans found in database for $ASN"
                DO_DIFF=0
                return 1
            fi
        else
            log_error "LATEST baseline requires --database enabled"
            DO_DIFF=0
            return 1
        fi
    elif [ -n "$DIFF_DIR" ]; then
        # Use directory path
        if [ ! -d "$DIFF_DIR" ]; then
            log_error "Baseline directory not found: $DIFF_DIR"
            DO_DIFF=0
            return 1
        fi
        log_info "Using baseline directory: $DIFF_DIR"
    elif [ -n "$DIFF_BASELINE" ]; then
        # Use specific scan ID - need to find it in database
        if [ "$DO_DATABASE" -eq 0 ]; then
            log_error "Scan ID baseline requires --database enabled"
            DO_DIFF=0
            return 1
        fi
    else
        log_error "No baseline specified for diff mode"
        DO_DIFF=0
        return 1
    fi
    
    DIFF_REPORT="$OUTDIR/diff_report.txt"
    
    return 0
}

# =============================
# Compare Assets (IPs)
# =============================
diff_compare_assets() {
    BASELINE_DIR="$1"
    CURRENT_DIR="$2"
    
    BASELINE_PTR="$BASELINE_DIR/ptr_results.txt"
    CURRENT_PTR="$CURRENT_DIR/ptr_results.txt"
    
    [ ! -f "$BASELINE_PTR" ] && return 1
    [ ! -f "$CURRENT_PTR" ] && return 1
    
    # Extract IPs
    BASELINE_IPS=$(mktemp)
    CURRENT_IPS=$(mktemp)
    
    cut -d, -f1 "$BASELINE_PTR" | sort -u > "$BASELINE_IPS"
    cut -d, -f1 "$CURRENT_PTR" | sort -u > "$CURRENT_IPS"
    
    # Find new assets (in current but not in baseline)
    NEW_ASSETS=$(mktemp)
    comm -13 "$BASELINE_IPS" "$CURRENT_IPS" > "$NEW_ASSETS"
    DIFF_NEW_ASSETS=$(wc -l < "$NEW_ASSETS")
    
    # Find removed assets (in baseline but not in current)
    REMOVED_ASSETS=$(mktemp)
    comm -23 "$BASELINE_IPS" "$CURRENT_IPS" > "$REMOVED_ASSETS"
    DIFF_REMOVED_ASSETS=$(wc -l < "$REMOVED_ASSETS")
    
    # Write to diff report
    {
        echo "==================================="
        echo "ASSET CHANGES"
        echo "==================================="
        echo
        echo "New Assets Discovered: $DIFF_NEW_ASSETS"
        if [ "$DIFF_NEW_ASSETS" -gt 0 ]; then
            echo
            head -20 "$NEW_ASSETS" | while read IP; do
                HOSTNAME=$(grep "^$IP," "$CURRENT_PTR" | cut -d, -f2)
                echo "  + $IP - $HOSTNAME"
            done
            [ "$DIFF_NEW_ASSETS" -gt 20 ] && echo "  ... and $((DIFF_NEW_ASSETS - 20)) more"
        fi
        echo
        
        echo "Assets No Longer Responding: $DIFF_REMOVED_ASSETS"
        if [ "$DIFF_REMOVED_ASSETS" -gt 0 ]; then
            echo
            head -20 "$REMOVED_ASSETS" | while read IP; do
                HOSTNAME=$(grep "^$IP," "$BASELINE_PTR" | cut -d, -f2)
                echo "  - $IP - $HOSTNAME"
            done
            [ "$DIFF_REMOVED_ASSETS" -gt 20 ] && echo "  ... and $((DIFF_REMOVED_ASSETS - 20)) more"
        fi
        echo
    } >> "$DIFF_REPORT"
    
    # Cleanup
    rm -f "$BASELINE_IPS" "$CURRENT_IPS" "$NEW_ASSETS" "$REMOVED_ASSETS"
}

# =============================
# Compare Vulnerabilities
# =============================
diff_compare_vulnerabilities() {
    BASELINE_DIR="$1"
    CURRENT_DIR="$2"
    
    BASELINE_CVE="$BASELINE_DIR/vulnerabilities.csv"
    CURRENT_CVE="$CURRENT_DIR/vulnerabilities.csv"
    
    [ ! -f "$BASELINE_CVE" ] && [ ! -f "$CURRENT_CVE" ] && return 0
    
    # Extract CVE IDs with IP:PORT
    BASELINE_VULNS=$(mktemp)
    CURRENT_VULNS=$(mktemp)
    
    if [ -f "$BASELINE_CVE" ]; then
        awk -F, 'NR>1 {print $1":"$2":"$5}' "$BASELINE_CVE" | sort -u > "$BASELINE_VULNS"
    else
        touch "$BASELINE_VULNS"
    fi
    
    if [ -f "$CURRENT_CVE" ]; then
        awk -F, 'NR>1 {print $1":"$2":"$5}' "$CURRENT_CVE" | sort -u > "$CURRENT_VULNS"
    else
        touch "$CURRENT_VULNS"
    fi
    
    # Find new vulnerabilities
    NEW_VULNS=$(mktemp)
    comm -13 "$BASELINE_VULNS" "$CURRENT_VULNS" > "$NEW_VULNS"
    DIFF_NEW_VULNS=$(wc -l < "$NEW_VULNS")
    
    # Count new critical
    DIFF_NEW_CRITICAL=0
    while read VULN_LINE; do
        IP=$(echo "$VULN_LINE" | cut -d: -f1)
        PORT=$(echo "$VULN_LINE" | cut -d: -f2)
        CVE=$(echo "$VULN_LINE" | cut -d: -f3)
        
        # Get severity from current CSV
        SEVERITY=$(awk -F, -v ip="$IP" -v port="$PORT" -v cve="$CVE" \
            'NR>1 && $1==ip && $2==port && $5==cve {print $6}' "$CURRENT_CVE" | head -1)
        
        [ "$SEVERITY" = "CRITICAL" ] && DIFF_NEW_CRITICAL=$((DIFF_NEW_CRITICAL + 1))
    done < "$NEW_VULNS"
    
    # Find resolved vulnerabilities
    RESOLVED_VULNS=$(mktemp)
    comm -23 "$BASELINE_VULNS" "$CURRENT_VULNS" > "$RESOLVED_VULNS"
    DIFF_RESOLVED_VULNS=$(wc -l < "$RESOLVED_VULNS")
    
    # Write to diff report
    {
        echo "==================================="
        echo "VULNERABILITY CHANGES"
        echo "==================================="
        echo
        echo "New Vulnerabilities: $DIFF_NEW_VULNS"
        if [ "$DIFF_NEW_CRITICAL" -gt 0 ]; then
            echo "  ÃƒÂ¢Ã…Â¡Ã‚Â ÃƒÂ¯Ã‚Â¸Ã‚Â  NEW CRITICAL: $DIFF_NEW_CRITICAL"
        fi
        
        if [ "$DIFF_NEW_VULNS" -gt 0 ]; then
            echo
            echo "Details:"
            head -30 "$NEW_VULNS" | while IFS=: read IP PORT CVE; do
                # Get full details from current CSV
                DETAILS=$(awk -F, -v ip="$IP" -v port="$PORT" -v cve="$CVE" \
                    'NR>1 && $1==ip && $2==port && $5==cve {print $3"/"$4" - "$6" - "$7}' "$CURRENT_CVE" | head -1)
                
                SEVERITY=$(echo "$DETAILS" | awk -F' - ' '{print $2}')
                
                if [ "$SEVERITY" = "CRITICAL" ]; then
                    echo "  ÃƒÂ°Ã…Â¸Ã¢â‚¬ÂÃ‚Â´ $IP:$PORT - $CVE ($DETAILS)"
                elif [ "$SEVERITY" = "HIGH" ]; then
                    echo "  ÃƒÂ°Ã…Â¸Ã…Â¸Ã‚Â  $IP:$PORT - $CVE ($DETAILS)"
                else
                    echo "  ÃƒÂ°Ã…Â¸Ã…Â¸Ã‚Â¡ $IP:$PORT - $CVE ($DETAILS)"
                fi
            done
            [ "$DIFF_NEW_VULNS" -gt 30 ] && echo "  ... and $((DIFF_NEW_VULNS - 30)) more"
        fi
        echo
        
        echo "Resolved Vulnerabilities: $DIFF_RESOLVED_VULNS"
        if [ "$DIFF_RESOLVED_VULNS" -gt 0 ]; then
            echo
            echo "Details (no longer detected):"
            head -20 "$RESOLVED_VULNS" | while IFS=: read IP PORT CVE; do
                echo "  ÃƒÂ¢Ã…â€œÃ¢â‚¬Â¦ $IP:$PORT - $CVE (FIXED or host no longer responds)"
            done
            [ "$DIFF_RESOLVED_VULNS" -gt 20 ] && echo "  ... and $((DIFF_RESOLVED_VULNS - 20)) more"
        fi
        echo
    } >> "$DIFF_REPORT"
    
    # Cleanup
    rm -f "$BASELINE_VULNS" "$CURRENT_VULNS" "$NEW_VULNS" "$RESOLVED_VULNS"
}

# =============================
# Compare Port Changes
# =============================
diff_compare_ports() {
    BASELINE_DIR="$1"
    CURRENT_DIR="$2"
    
    BASELINE_PORTS="$BASELINE_DIR/open_ports.csv"
    CURRENT_PORTS="$CURRENT_DIR/open_ports.csv"
    
    [ ! -f "$BASELINE_PORTS" ] && [ ! -f "$CURRENT_PORTS" ] && return 0
    
    # Extract IP:PORT combinations
    BASELINE_OPEN=$(mktemp)
    CURRENT_OPEN=$(mktemp)
    
    if [ -f "$BASELINE_PORTS" ]; then
        awk -F, 'NR>1 && $3=="open" {print $1":"$2}' "$BASELINE_PORTS" | sort -u > "$BASELINE_OPEN"
    else
        touch "$BASELINE_OPEN"
    fi
    
    if [ -f "$CURRENT_PORTS" ]; then
        awk -F, 'NR>1 && $3=="open" {print $1":"$2}' "$CURRENT_PORTS" | sort -u > "$CURRENT_OPEN"
    else
        touch "$CURRENT_OPEN"
    fi
    
    # Find newly opened ports
    NEW_PORTS=$(mktemp)
    comm -13 "$BASELINE_OPEN" "$CURRENT_OPEN" > "$NEW_PORTS"
    NEW_PORT_COUNT=$(wc -l < "$NEW_PORTS")
    
    # Find closed ports
    CLOSED_PORTS=$(mktemp)
    comm -23 "$BASELINE_OPEN" "$CURRENT_OPEN" > "$CLOSED_PORTS"
    CLOSED_PORT_COUNT=$(wc -l < "$CLOSED_PORTS")
    
    # Write to diff report
    {
        echo "==================================="
        echo "PORT CHANGES"
        echo "==================================="
        echo
        echo "Newly Opened Ports: $NEW_PORT_COUNT"
        if [ "$NEW_PORT_COUNT" -gt 0 ]; then
            echo
            head -30 "$NEW_PORTS" | while IFS=: read IP PORT; do
                # Get service info if available
                SERVICE=$(awk -F, -v ip="$IP" -v port="$PORT" \
                    'NR>1 && $1==ip && $2==port {print $4}' "$CURRENT_PORTS" 2>/dev/null | head -1)
                [ -z "$SERVICE" ] && SERVICE="unknown"
                echo "  + $IP:$PORT - $SERVICE"
            done
            [ "$NEW_PORT_COUNT" -gt 30 ] && echo "  ... and $((NEW_PORT_COUNT - 30)) more"
        fi
        echo
        
        echo "Closed Ports: $CLOSED_PORT_COUNT"
        if [ "$CLOSED_PORT_COUNT" -gt 0 ]; then
            echo
            head -20 "$CLOSED_PORTS" | while IFS=: read IP PORT; do
                echo "  - $IP:$PORT"
            done
            [ "$CLOSED_PORT_COUNT" -gt 20 ] && echo "  ... and $((CLOSED_PORT_COUNT - 20)) more"
        fi
        echo
    } >> "$DIFF_REPORT"
    
    # Cleanup
    rm -f "$BASELINE_OPEN" "$CURRENT_OPEN" "$NEW_PORTS" "$CLOSED_PORTS"
}

# =============================
# Compare Certificates
# =============================
diff_compare_certificates() {
    BASELINE_DIR="$1"
    CURRENT_DIR="$2"
    
    BASELINE_CERTS="$BASELINE_DIR/tls_certificates.csv"
    CURRENT_CERTS="$CURRENT_DIR/tls_certificates.csv"
    
    [ ! -f "$BASELINE_CERTS" ] && [ ! -f "$CURRENT_CERTS" ] && return 0
    
    DIFF_CERT_CHANGES=0
    
    # Find newly expired certificates
    NEWLY_EXPIRED=$(mktemp)
    if [ -f "$CURRENT_CERTS" ]; then
        awk -F, 'NR>1 && $13=="expired" {print $1":"$2":"$3}' "$CURRENT_CERTS" > "$NEWLY_EXPIRED"
        
        # Check if these were valid before
        while IFS=: read IP PORT CN; do
            if [ -f "$BASELINE_CERTS" ]; then
                WAS_VALID=$(awk -F, -v ip="$IP" -v port="$PORT" \
                    'NR>1 && $1==ip && $2==port && $13=="valid" {print "yes"}' "$BASELINE_CERTS" | head -1)
                
                if [ "$WAS_VALID" = "yes" ]; then
                    DIFF_CERT_CHANGES=$((DIFF_CERT_CHANGES + 1))
                fi
            fi
        done < "$NEWLY_EXPIRED"
    fi
    
    # Find certificates expiring soon (< 30 days) that weren't before
    EXPIRING_SOON=$(mktemp)
    if [ -f "$CURRENT_CERTS" ]; then
        awk -F, 'NR>1 && $13=="expiring_soon" {print $1":"$2":"$3":"$12}' "$CURRENT_CERTS" > "$EXPIRING_SOON"
    fi
    
    NEWLY_EXPIRING=0
    if [ -f "$BASELINE_CERTS" ]; then
        while IFS=: read IP PORT CN DAYS; do
            WAS_OKAY=$(awk -F, -v ip="$IP" -v port="$PORT" \
                'NR>1 && $1==ip && $2==port && $12>30 {print "yes"}' "$BASELINE_CERTS" | head -1)
            
            [ "$WAS_OKAY" = "yes" ] && NEWLY_EXPIRING=$((NEWLY_EXPIRING + 1))
        done < "$EXPIRING_SOON"
    fi
    
    # Write to diff report
    {
        echo "==================================="
        echo "CERTIFICATE CHANGES"
        echo "==================================="
        echo
        
        if [ "$DIFF_CERT_CHANGES" -gt 0 ]; then
            echo "Newly Expired Certificates: $DIFF_CERT_CHANGES"
            echo
            head -20 "$NEWLY_EXPIRED" | while IFS=: read IP PORT CN; do
                echo "  ÃƒÂ¢Ã…Â¡Ã‚Â ÃƒÂ¯Ã‚Â¸Ã‚Â  $IP:$PORT - $CN (EXPIRED)"
            done
            echo
        fi
        
        if [ "$NEWLY_EXPIRING" -gt 0 ]; then
            echo "Certificates Now Expiring Soon: $NEWLY_EXPIRING"
            echo
            head -20 "$EXPIRING_SOON" | while IFS=: read IP PORT CN DAYS; do
                # Check if this is newly expiring
                if [ -f "$BASELINE_CERTS" ]; then
                    WAS_OKAY=$(awk -F, -v ip="$IP" -v port="$PORT" \
                        'NR>1 && $1==ip && $2==port && $12>30 {print "yes"}' "$BASELINE_CERTS" | head -1)
                    
                    if [ "$WAS_OKAY" = "yes" ]; then
                        echo "  ÃƒÂ°Ã…Â¸Ã…Â¸Ã‚Â¡ $IP:$PORT - $CN ($DAYS days remaining)"
                    fi
                fi
            done
            echo
        fi
        
        if [ "$DIFF_CERT_CHANGES" -eq 0 ] && [ "$NEWLY_EXPIRING" -eq 0 ]; then
            echo "No certificate expiry changes detected."
            echo
        fi
    } >> "$DIFF_REPORT"
    
    # Cleanup
    rm -f "$NEWLY_EXPIRED" "$EXPIRING_SOON"
}

# =============================
# Compare Leak Exposures
# =============================
diff_compare_leaks() {
    BASELINE_DIR="$1"
    CURRENT_DIR="$2"
    
    BASELINE_LEAKS="$BASELINE_DIR/leak_exposures.csv"
    CURRENT_LEAKS="$CURRENT_DIR/leak_exposures.csv"
    
    [ ! -f "$CURRENT_LEAKS" ] && return 0
    
    # Extract URL exposures
    BASELINE_EXPOSED=$(mktemp)
    CURRENT_EXPOSED=$(mktemp)
    
    if [ -f "$BASELINE_LEAKS" ]; then
        awk -F, 'NR>1 {print $2}' "$BASELINE_LEAKS" | sort -u > "$BASELINE_EXPOSED"
    else
        touch "$BASELINE_EXPOSED"
    fi
    
    awk -F, 'NR>1 {print $2}' "$CURRENT_LEAKS" | sort -u > "$CURRENT_EXPOSED"
    
    # Find new exposures
    NEW_LEAKS=$(mktemp)
    comm -13 "$BASELINE_EXPOSED" "$CURRENT_EXPOSED" > "$NEW_LEAKS"
    DIFF_NEW_LEAKS=$(wc -l < "$NEW_LEAKS")
    
    # Find resolved exposures
    RESOLVED_LEAKS=$(mktemp)
    comm -23 "$BASELINE_EXPOSED" "$CURRENT_EXPOSED" > "$RESOLVED_LEAKS"
    RESOLVED_COUNT=$(wc -l < "$RESOLVED_LEAKS")
    
    # Write to diff report
    {
        echo "==================================="
        echo "LEAK EXPOSURE CHANGES"
        echo "==================================="
        echo
        echo "New Exposures: $DIFF_NEW_LEAKS"
        if [ "$DIFF_NEW_LEAKS" -gt 0 ]; then
            echo
            head -20 "$NEW_LEAKS" | while read URL; do
                # Get severity
                SEVERITY=$(awk -F, -v url="$URL" 'NR>1 && $2==url {print $4}' "$CURRENT_LEAKS" | head -1)
                CONTENT_TYPE=$(awk -F, -v url="$URL" 'NR>1 && $2==url {print $5}' "$CURRENT_LEAKS" | head -1)
                
                if [ "$SEVERITY" = "CRITICAL" ]; then
                    echo "  ÃƒÂ°Ã…Â¸Ã¢â‚¬ÂÃ‚Â´ $URL - $CONTENT_TYPE"
                else
                    echo "  ÃƒÂ°Ã…Â¸Ã…Â¸Ã‚Â¡ $URL - $CONTENT_TYPE"
                fi
            done
            [ "$DIFF_NEW_LEAKS" -gt 20 ] && echo "  ... and $((DIFF_NEW_LEAKS - 20)) more"
        fi
        echo
        
        echo "Resolved Exposures: $RESOLVED_COUNT"
        if [ "$RESOLVED_COUNT" -gt 0 ]; then
            echo
            head -10 "$RESOLVED_LEAKS" | while read URL; do
                echo "  ÃƒÂ¢Ã…â€œÃ¢â‚¬Â¦ $URL (no longer accessible)"
            done
        fi
        echo
    } >> "$DIFF_REPORT"
    
    # Cleanup
    rm -f "$BASELINE_EXPOSED" "$CURRENT_EXPOSED" "$NEW_LEAKS" "$RESOLVED_LEAKS"
}

# =============================
# Run Complete Diff Analysis
# =============================
run_diff_analysis() {
    [ "$DO_DIFF" -eq 0 ] && return 0
    
    log_header "DIFF ANALYSIS: Change Detection"
    
    # Determine baseline directory
    if [ -n "$DIFF_DIR" ]; then
        BASELINE_DIR="$DIFF_DIR"
    else
        # Try to find baseline scan directory from database
        log_warning "Database-based diff not yet implemented - requires DIFF_DIR"
        return 1
    fi
    
    if [ ! -d "$BASELINE_DIR" ]; then
        log_error "Baseline directory not found: $BASELINE_DIR"
        return 1
    fi
    
    CURRENT_DIR="$OUTDIR"
    
    log_info "Baseline: $BASELINE_DIR"
    log_info "Current:  $CURRENT_DIR"
    echo
    
    # Initialize report
    {
        echo "==================================="
        echo "ASNSPY DIFF REPORT"
        echo "==================================="
        echo
        echo "ASN:              $ASN"
        echo "Baseline Scan:    $BASELINE_DIR"
        echo "Current Scan:     $CURRENT_DIR"
        echo "Generated:        $(date '+%Y-%m-%d %H:%M:%S %Z')"
        echo
    } > "$DIFF_REPORT"
    
    # Run comparisons
    log_info "Comparing assets..."
    diff_compare_assets "$BASELINE_DIR" "$CURRENT_DIR"
    
    log_info "Comparing vulnerabilities..."
    diff_compare_vulnerabilities "$BASELINE_DIR" "$CURRENT_DIR"
    
    log_info "Comparing ports..."
    diff_compare_ports "$BASELINE_DIR" "$CURRENT_DIR"
    
    log_info "Comparing certificates..."
    diff_compare_certificates "$BASELINE_DIR" "$CURRENT_DIR"
    
    if [ "$DO_LEAK_SCAN" -eq 1 ]; then
        log_info "Comparing leak exposures..."
        diff_compare_leaks "$BASELINE_DIR" "$CURRENT_DIR"
    fi
    
    # Add summary
    {
        echo "==================================="
        echo "SUMMARY"
        echo "==================================="
        echo
        echo "Assets:"
        echo "  New:              $DIFF_NEW_ASSETS"
        echo "  Removed:          $DIFF_REMOVED_ASSETS"
        echo
        echo "Vulnerabilities:"
        echo "  New:              $DIFF_NEW_VULNS"
        echo "  New CRITICAL:     $DIFF_NEW_CRITICAL"
        echo "  Resolved:         $DIFF_RESOLVED_VULNS"
        echo
        if [ "$DO_LEAK_SCAN" -eq 1 ]; then
            echo "Leaks:"
            echo "  New Exposures:    $DIFF_NEW_LEAKS"
            echo
        fi
        echo "Certificates:"
        echo "  Newly Expired:    $DIFF_CERT_CHANGES"
        echo
    } >> "$DIFF_REPORT"
    
    log_success "Diff analysis complete"
    cat "$DIFF_REPORT"
    echo
    
    # Send alerts if new critical findings
    if [ "$DIFF_NEW_CRITICAL" -gt 0 ] && [ "$DIFF_ALERT_NEW_CRITICAL" -eq 1 ]; then
        log_warning "ÃƒÂ¢Ã…Â¡Ã‚Â ÃƒÂ¯Ã‚Â¸Ã‚Â  $DIFF_NEW_CRITICAL new CRITICAL vulnerabilities detected!"
        
        # Send webhook
        webhook_critical_finding "$DIFF_NEW_CRITICAL new CRITICAL vulnerabilities" "See diff report: $DIFF_REPORT"
        
        # Send SIEM event
        if [ "$DO_SIEM" -eq 1 ]; then
            DATA=$(cat << DIFFDATA
{
  "finding_type": "diff_critical",
  "new_critical_count": $DIFF_NEW_CRITICAL,
  "new_vulnerabilities": $DIFF_NEW_VULNS,
  "baseline": "$BASELINE_DIR",
  "current": "$CURRENT_DIR"
}
DIFFDATA
)
            send_to_siem "diff_critical_findings" "$SCAN_HASH" "$ASN" "CRITICAL" "$DATA"
        fi
    fi
}








# =============================
# Dependency Check - Enhanced
# =============================
check_deps() {
    MISSING=""
    OPTIONAL=""
    
    # Core dependencies
    for cmd in curl jq; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            MISSING="$MISSING $cmd"
        fi
    done
    
    # DNS tool (drill or dig)
    if ! command -v drill >/dev/null 2>&1 && ! command -v dig >/dev/null 2>&1; then
        MISSING="$MISSING drill/dig"
    fi
    
    # Traceroute tools
    if [ "$DO_TRACE" -eq 1 ]; then
        if ! command -v traceroute >/dev/null 2>&1; then
            MISSING="$MISSING traceroute"
        fi
        if [ "$DO_IPV6" -eq 1 ] && ! command -v traceroute6 >/dev/null 2>&1; then
            OPTIONAL="$OPTIONAL traceroute6"
        fi
    fi
    
    # Parallel processing
    if [ "$PARALLEL" -gt 1 ] || [ "$TRACE_PARALLEL" -gt 1 ]; then
        if ! command -v flock >/dev/null 2>&1; then
            MISSING="$MISSING flock"
        fi
    fi
    
    # openssl (optional for TLS scanning)
    if [ "$DO_TLS" -eq 1 ]; then
        if ! command -v openssl >/dev/null 2>&1; then
            MISSING="$MISSING openssl"
        fi
    fi
    
    if [ -n "$MISSING" ]; then
        log_error "Missing required dependencies:$MISSING"
        echo
        echo "Installation instructions:"
        echo
        
        for cmd in $MISSING; do
            case "$cmd" in
                curl)
                    echo "  ${BOLD}curl:${NC}"
                    echo "    Ubuntu/Debian: sudo apt install curl"
                    echo "    RHEL/CentOS:   sudo yum install curl"
                    echo "    Alpine:        sudo apk add curl"
                    echo
                    ;;
                jq)
                    echo "  ${BOLD}jq:${NC}"
                    echo "    Ubuntu/Debian: sudo apt install jq"
                    echo "    RHEL/CentOS:   sudo yum install jq"
                    echo "    Alpine:        sudo apk add jq"
                    echo "    macOS:         brew install jq"
                    echo
                    ;;
                drill/dig)
                    echo "  ${BOLD}DNS tools (dig or drill):${NC}"
                    echo "    Ubuntu/Debian: sudo apt install dnsutils"
                    echo "    RHEL/CentOS:   sudo yum install bind-utils"
                    echo "    Alpine:        sudo apk add bind-tools"
                    echo
                    ;;
                traceroute)
                    echo "  ${BOLD}traceroute:${NC}"
                    echo "    Ubuntu/Debian: sudo apt install traceroute"
                    echo "    RHEL/CentOS:   sudo yum install traceroute"
                    echo "    Alpine:        sudo apk add traceroute"
                    echo
                    ;;
                flock)
                    echo "  ${BOLD}flock (for parallel processing):${NC}"
                    echo "    Ubuntu/Debian: sudo apt install util-linux"
                    echo "    RHEL/CentOS:   sudo yum install util-linux"
                    echo "    Alpine:        sudo apk add util-linux"
                    echo
                    ;;
                openssl)
                    echo "  ${BOLD}openssl:${NC}"
                    echo "    Ubuntu/Debian: sudo apt install openssl"
                    echo "    RHEL/CentOS:   sudo yum install openssl"
                    echo "    Alpine:        sudo apk add openssl"
                    echo
                    ;;
                whois)
                    echo "  ${BOLD}whois:${NC}"
                    echo "    Ubuntu/Debian: sudo apt install whois"
                    echo "    RHEL/CentOS:   sudo yum install jwhois"
                    echo "    Alpine:        sudo apk add whois"
                    echo
                    ;;
            esac
        done
        
        exit 1
    fi
    
    if [ -n "$OPTIONAL" ]; then
        log_warning "WARNING: Missing optional commands:$OPTIONAL"
        log_warning "Some features may be unavailable."
        echo
    fi
}

# =============================
# ASCII Banner
# =============================
print_ascii_banner() {
    cat << 'BANNER'
═══════════════════════════════════════════════════════════════════════════════
    ___   _____ _   _______ ______  __  |  
   /   | / ___// | / / ___// __ \ \/ /  |  v3.0.0 - Open Source Edition
  / /| | \__ \/  |/ /\__ \/ /_/ /\  /   |
 / ___ |___/ / /|  /___/ / ____/ / /    |  https://github.com/ASNSPY/asnspy-oss
/_/  |_/____/_/ |_//____/_/     /_/     |
═══════════════════════════════════════════════════════════════════════════════
BANNER
}

# =============================
# Banner
# =============================
banner() {
    print_ascii_banner
    echo
}

# =============================
# Build TLS target list
# =============================
build_tls_targets() {
    rm -f "$TLS_TARGETS"
    
    case "$TLS_MODE" in
        ptr)
            # Only IPs with PTR records
            if [ -s "$PTR_FILE" ]; then
                cut -d, -f1 "$PTR_FILE" > "$TLS_TARGETS"
            fi
            ;;
        gateway)
            # Only gateway IPs (.1 and .254)
            while read PREF; do
                case "$PREF" in
                    *.*)
                        BLOCK=$(echo "$PREF" | cut -d/ -f1 | cut -d. -f1-3)
                        echo "$BLOCK.1" >> "$TLS_TARGETS"
                        echo "$BLOCK.254" >> "$TLS_TARGETS"
                        ;;
                esac
            done < "$PREFIX_FILE"
            ;;
        all)
            # Every IP in scan ranges
            while read PREF; do
                case "$PREF" in
                    *.*)
                        BLOCK=$(echo "$PREF" | cut -d/ -f1 | cut -d. -f1-3)
                        for i in $(seq $SWEEP_START $SWEEP_END); do
                            filter_octet "$i" && echo "$BLOCK.$i" >> "$TLS_TARGETS"
                        done
                        ;;
                    *:*)
                        BASE=$(echo "$PREF" | cut -d/ -f1)
                        for i in $(seq $SWEEP_START $SWEEP_END); do
                            HEX=$(printf "%x" "$i")
                            echo "${BASE}${HEX}" >> "$TLS_TARGETS"
                        done
                        ;;
                esac
            done < "$PREFIX_FILE"
            ;;
    esac
    
    if [ -s "$TLS_TARGETS" ]; then
        sort -u "$TLS_TARGETS" -o "$TLS_TARGETS"
    fi
}

# =============================
# Single TLS certificate scan
# =============================
scan_tls_certificate() {
    IP="$1"
    PORT="$2"
    TIMEOUT="$3"
    
    # Try to connect and get certificate
    if [ "$TIMEOUT" -eq 0 ]; then
        # No timeout - wait indefinitely
        CERT_OUTPUT=$(echo | openssl s_client -connect "$IP:$PORT" -servername "$IP" </dev/null 2>&1)
    else
        # With timeout
        CERT_OUTPUT=$(echo | timeout "$TIMEOUT" openssl s_client -connect "$IP:$PORT" -servername "$IP" </dev/null 2>&1)
    fi
    
    EXIT_CODE=$?
    
    # Filter out timeout/connection messages
    CERT_DATA=$(echo "$CERT_OUTPUT" | grep -v "^Terminated" | sed -n '/^CONNECTED/,/^---$/p')
    
    if [ -z "$CERT_DATA" ] || [ $EXIT_CODE -eq 124 ] || [ $EXIT_CODE -eq 143 ] || [ $EXIT_CODE -ne 0 ]; then
        echo "==================================="
        echo "IP: $IP:$PORT"
        echo "Status: CONNECTION_FAILED"
        echo "==================================="
        echo
        echo "$IP,$PORT,CONNECTION_FAILED,0,,,,,,,,,connection_failed,,,,,,,,,,,," >> "$TLS_CSV"
        return
    fi
    
    # Extract certificate details
    CERT_TEXT=$(echo "$CERT_OUTPUT" | openssl x509 -noout -text 2>/dev/null)
    
    if [ -z "$CERT_TEXT" ]; then
        echo "==================================="
        echo "IP: $IP:$PORT"
        echo "Status: NO_CERTIFICATE"
        echo "==================================="
        echo
        echo "$IP,$PORT,NO_CERT,0,,,,,,,,,no_certificate,,,,,,,,,,,," >> "$TLS_CSV"
        return
    fi
    
    # Parse certificate fields for CSV
    CN=$(echo "$CERT_TEXT" | grep "Subject:.*CN" | sed "s/.*CN *= *//" | sed "s/,.*//;s/ *$//" | head -1)
    [ -z "$CN" ] && CN="-"
    
    SANS=$(echo "$CERT_TEXT" | grep -A1 "Subject Alternative Name" | tail -1 | sed "s/DNS://g;s/IP Address://g;s/, */ /g" | tr -s " ")
    [ -z "$SANS" ] && SANS="-"
    SAN_COUNT=$(echo "$SANS" | wc -w)
    
    ORG=$(echo "$CERT_TEXT" | grep "Subject:.*O *=" | sed "s/.*O *= *//" | sed "s/,.*//;s/ *$//" | head -1)
    [ -z "$ORG" ] && ORG="-"
    COUNTRY=$(echo "$CERT_TEXT" | grep "Subject:.*C *=" | sed "s/.*C *= *//" | sed "s/,.*//;s/ *$//" | head -1)
    [ -z "$COUNTRY" ] && COUNTRY="-"
    
    ISSUER=$(echo "$CERT_TEXT" | grep "Issuer:.*CN" | sed "s/.*CN *= *//" | sed "s/,.*//;s/ *$//" | head -1)
    [ -z "$ISSUER" ] && ISSUER="-"
    ISSUER_ORG=$(echo "$CERT_TEXT" | grep "Issuer:.*O *=" | sed "s/.*O *= *//" | sed "s/,.*//;s/ *$//" | head -1)
    [ -z "$ISSUER_ORG" ] && ISSUER_ORG="-"
    
    VALID_FROM=$(echo "$CERT_TEXT" | grep "Not Before" | sed "s/[^:]*: *//")
    VALID_TO=$(echo "$CERT_TEXT" | grep "Not After" | sed "s/[^:]*: *//")
    
    # Calculate days remaining with BusyBox support
    if [ -n "$VALID_TO" ]; then
        VALID_TO_CLEAN=$(echo "$VALID_TO" | sed 's/ GMT$//')
        
        # Try BusyBox, GNU, then BSD date
        VALID_TO_EPOCH=$(date -D "%b %d %T %Y" -d "$VALID_TO_CLEAN" +%s 2>/dev/null)
        if [ -z "$VALID_TO_EPOCH" ]; then
            VALID_TO_EPOCH=$(date -d "$VALID_TO" +%s 2>/dev/null)
        fi
        if [ -z "$VALID_TO_EPOCH" ]; then
            VALID_TO_EPOCH=$(date -j -f "%b %d %T %Y %Z" "$VALID_TO" +%s 2>/dev/null)
        fi
        
        NOW_EPOCH=$(date +%s)
        
        if [ -n "$VALID_TO_EPOCH" ] && [ "$VALID_TO_EPOCH" -gt 0 ]; then
            DAYS_REMAINING=$(( (VALID_TO_EPOCH - NOW_EPOCH) / 86400 ))
        else
            DAYS_REMAINING="N/A"
        fi
    else
        DAYS_REMAINING="N/A"
    fi
    
    # Determine status
    CERT_STATUS="valid"
    if [ "$DAYS_REMAINING" != "N/A" ]; then
        if [ "$DAYS_REMAINING" -lt 0 ]; then
            CERT_STATUS="expired"
        elif [ "$DAYS_REMAINING" -lt 30 ]; then
            CERT_STATUS="expiring_soon"
        fi
    fi
    
    # Key details
    KEY_TYPE=$(echo "$CERT_TEXT" | grep "Public Key Algorithm" | sed "s/.*: *//" | head -1)
    [ -z "$KEY_TYPE" ] && KEY_TYPE="-"
    KEY_BITS=$(echo "$CERT_TEXT" | grep "Public-Key:" | sed "s/.*(\(.*\) bit).*/\1/" | head -1)
    [ -z "$KEY_BITS" ] && KEY_BITS="-"
    
    SIG_ALGO=$(echo "$CERT_TEXT" | grep "Signature Algorithm:" | sed "s/.*: *//" | head -1)
    [ -z "$SIG_ALGO" ] && SIG_ALGO="-"
    
    SERIAL=$(echo "$CERT_TEXT" | grep "Serial Number:" -A1 | tail -1 | tr -d " 
:")
    [ -z "$SERIAL" ] && SERIAL="-"
    
    # Protocol and cipher
    # Try new format first: "New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384"
    TLS_VER=$(echo "$CERT_OUTPUT" | grep "Cipher is" | sed -n 's/.*\(TLSv[0-9.]*\).*/\1/p' | head -1)
    # Try old format if new format didn't work: "Protocol : TLSv1.3"
    if [ -z "$TLS_VER" ]; then
        TLS_VER=$(echo "$CERT_OUTPUT" | grep "Protocol *:" | awk '{print $NF}' | head -1)
    fi
    [ -z "$TLS_VER" ] && TLS_VER="-"
    
    # Try new format first: "Cipher is TLS_AES_256_GCM_SHA384"
    CIPHER=$(echo "$CERT_OUTPUT" | grep "Cipher is" | sed -n 's/.*Cipher is \([^ ]*\).*/\1/p' | head -1)
    # Try old format if new format didn't work: "Cipher : TLS_AES_256_GCM_SHA384"
    if [ -z "$CIPHER" ]; then
        CIPHER=$(echo "$CERT_OUTPUT" | grep "Cipher *:" | awk '{print $NF}' | head -1)
    fi
    [ -z "$CIPHER" ] && CIPHER="-"
    
    # Flags
    IS_WILDCARD=$(echo "$CN $SANS" | grep -q "\*\." && echo "yes" || echo "no")
    IS_SELF_SIGNED=$([ "$CN" = "$ISSUER" ] && echo "yes" || echo "no")
    
    # Check weak key
    IS_WEAK="no"
    if [ "$KEY_BITS" != "-" ]; then
        if echo "$KEY_TYPE" | grep -qi "rsa" && [ "$KEY_BITS" -lt 2048 ]; then
            IS_WEAK="yes"
        elif echo "$KEY_TYPE" | grep -qi "ec" && [ "$KEY_BITS" -lt 256 ]; then
            IS_WEAK="yes"
        fi
    fi
    
    # Check deprecated TLS
    IS_DEPRECATED="no"
    case "$TLS_VER" in
        TLSv1|TLSv1.0|TLSv1.1|SSLv*) IS_DEPRECATED="yes" ;;
    esac
    
    # Check for SCT
    SCT_COUNT=$(echo "$CERT_TEXT" | grep -c "CT Precertificate SCTs" || echo "0")
    
    # Escape CSV fields
    CN_ESC=$(echo "$CN" | sed 's/"/\"\"/g')
    SANS_ESC=$(echo "$SANS" | sed 's/"/\"\"/g')
    ORG_ESC=$(echo "$ORG" | sed 's/"/\"\"/g')
    ISSUER_ESC=$(echo "$ISSUER" | sed 's/"/\"\"/g')
    ISSUER_ORG_ESC=$(echo "$ISSUER_ORG" | sed 's/"/\"\"/g')
    
    # Write CSV line
    echo "$IP,$PORT,\"$CN_ESC\",$SAN_COUNT,\"$SANS_ESC\",\"$ORG_ESC\",$COUNTRY,\"$ISSUER_ESC\",\"$ISSUER_ORG_ESC\",$VALID_FROM,$VALID_TO,$DAYS_REMAINING,$CERT_STATUS,$KEY_TYPE,$KEY_BITS,$SIG_ALGO,$SERIAL,$TLS_VER,$CIPHER,$IS_WILDCARD,$IS_SELF_SIGNED,$IS_WEAK,$IS_DEPRECATED,$SCT_COUNT" >> "$TLS_CSV"
    
    # Store the full output for raw file
    echo "==================================="
    echo "IP: $IP:$PORT"
    echo "Timestamp: $(date '+%Y-%m-%d %H:%M:%S %Z')"
    echo "==================================="
    echo "$CERT_DATA"
    echo
    echo "==================================="
    echo "Certificate Details:"
    echo "==================================="
    echo "$CERT_TEXT"
    echo
    echo
}

# =============================
# TLS scanning phase
# =============================
run_tls_phase() {
    [ "$DO_TLS" -eq 0 ] && return
    
    
    log_header "TLS Certificate Analysis"
    
    build_tls_targets
    
    if [ ! -s "$TLS_TARGETS" ]; then
        log_warning "No targets to scan for TLS (empty target list)"
        return
    fi
    
    TLS_COUNT=$(wc -l < "$TLS_TARGETS")
    log_info "TLS scan mode: $TLS_MODE"
    log_info "Targets to scan: $TLS_COUNT"
    log_info "Port: $TLS_PORT"
    log_info "Parallel scans: $TLS_PARALLEL"
    if [ "$TLS_TIMEOUT" -eq 0 ]; then
        log_info "Timeout: None (unlimited)"
    else
        log_info "Timeout: ${TLS_TIMEOUT}s"
    fi
    echo
    
    # Initialize TLS file
    echo "ASNSPY TLS Certificate Scan Results - Raw Data" > "$TLS_FILE"
    echo "Generated: $(date '+%Y-%m-%d %H:%M:%S %Z')" >> "$TLS_FILE"
    echo "Port: $TLS_PORT" >> "$TLS_FILE"
    echo "Total targets: $TLS_COUNT" >> "$TLS_FILE"
    echo >> "$TLS_FILE"
    echo "========================================" >> "$TLS_FILE"
    echo >> "$TLS_FILE"
    
    # Initialize CSV file
    echo "ip,port,cn,san_count,sans,organization,country,issuer,issuer_org,valid_from,valid_to,days_remaining,status,key_type,key_bits,signature_algorithm,serial_number,tls_version,cipher,is_wildcard,is_self_signed,is_weak_key,is_deprecated_tls,sct_count" > "$TLS_CSV"
    
    if [ "$TLS_PARALLEL" -le 1 ]; then
        COUNT=0
        while read TARGET; do
            COUNT=$((COUNT + 1))
            printf "\r[*] TLS scan: %d/%d - %s          " "$COUNT" "$TLS_COUNT" "$TARGET"
            scan_tls_certificate "$TARGET" "$TLS_PORT" "$TLS_TIMEOUT" >> "$TLS_FILE"
        done < "$TLS_TARGETS"
        echo
    else
        export TLS_PORT TLS_TIMEOUT TLS_FILE TLS_CSV
        
        # Progress counter
        log_info "Scanning in parallel (dots = attempts)..."
        
        cat "$TLS_TARGETS" | xargs -P "$TLS_PARALLEL" -I{} sh -c '
            IP="{}"
            
            # Try to connect and get certificate
            if [ "$TLS_TIMEOUT" -eq 0 ]; then
                # No timeout - wait indefinitely (max 30s for safety in parallel)
                CERT_OUTPUT=$(echo | timeout 30 openssl s_client -connect "$IP:$TLS_PORT" -servername "$IP" </dev/null 2>&1)
            else
                # With timeout
                CERT_OUTPUT=$(echo | timeout "$TLS_TIMEOUT" openssl s_client -connect "$IP:$TLS_PORT" -servername "$IP" </dev/null 2>&1)
            fi
            
            EXIT_CODE=$?
            
            # Check connection status
            if echo "$CERT_OUTPUT" | grep -q "^CONNECTED"; then
                # We connected - now check if we got a certificate
                if echo "$CERT_OUTPUT" | grep -q "no peer certificate available"; then
                    # Connected but server sent no certificate
                    RESULT="===================================
IP: $IP:$TLS_PORT
Status: NO_CERTIFICATE (connected but server offers no cert)
===================================
$CERT_OUTPUT

"
                    CSV_LINE="$IP,$TLS_PORT,NO_CERT,0,,,,,,,,,no_certificate,,,,,,,,,,,"
                    STATUS="nocert"
                elif echo "$CERT_OUTPUT" | grep -q "BEGIN CERTIFICATE"; then
                    # Got a certificate - extract and parse
                    CERT_TEXT=$(echo "$CERT_OUTPUT" | openssl x509 -noout -text 2>/dev/null)
                    
                    if [ -n "$CERT_TEXT" ]; then
                        # Parse certificate fields
                        CN=$(echo "$CERT_TEXT" | grep "Subject:.*CN" | sed "s/.*CN *= *//" | sed "s/,.*//;s/ *$//" | head -1)
                        [ -z "$CN" ] && CN="-"
                        
                        # Get all SANs
                        SANS=$(echo "$CERT_TEXT" | grep -A1 "Subject Alternative Name" | tail -1 | sed "s/DNS://g;s/IP Address://g;s/, */ /g" | tr -s " ")
                        [ -z "$SANS" ] && SANS="-"
                        SAN_COUNT=$(echo "$SANS" | wc -w)
                        
                        # Organization and Country from Subject
                        ORG=$(echo "$CERT_TEXT" | grep "Subject:.*O *=" | sed "s/.*O *= *//" | sed "s/,.*//;s/ *$//" | head -1)
                        [ -z "$ORG" ] && ORG="-"
                        COUNTRY=$(echo "$CERT_TEXT" | grep "Subject:.*C *=" | sed "s/.*C *= *//" | sed "s/,.*//;s/ *$//" | head -1)
                        [ -z "$COUNTRY" ] && COUNTRY="-"
                        
                        # Issuer
                        ISSUER=$(echo "$CERT_TEXT" | grep "Issuer:.*CN" | sed "s/.*CN *= *//" | sed "s/,.*//;s/ *$//" | head -1)
                        [ -z "$ISSUER" ] && ISSUER="-"
                        ISSUER_ORG=$(echo "$CERT_TEXT" | grep "Issuer:.*O *=" | sed "s/.*O *= *//" | sed "s/,.*//;s/ *$//" | head -1)
                        [ -z "$ISSUER_ORG" ] && ISSUER_ORG="-"
                        
                        # Validity
                        VALID_FROM=$(echo "$CERT_TEXT" | grep "Not Before" | sed "s/[^:]*: *//")
                        VALID_TO=$(echo "$CERT_TEXT" | grep "Not After" | sed "s/[^:]*: *//")
                        
                        # Calculate days remaining
                        if [ -n "$VALID_TO" ]; then
                            # Remove timezone for BusyBox compatibility
                            VALID_TO_CLEAN=$(echo "$VALID_TO" | sed 's/ GMT$//')
                            
                            # Try different date parsing methods
                            # 1. BusyBox date (common in embedded systems)
                            VALID_TO_EPOCH=$(date -D "%b %d %T %Y" -d "$VALID_TO_CLEAN" +%s 2>/dev/null)
                            
                            # 2. GNU date (Linux)
                            if [ -z "$VALID_TO_EPOCH" ]; then
                                VALID_TO_EPOCH=$(date -d "$VALID_TO" +%s 2>/dev/null)
                            fi
                            
                            # 3. BSD date (macOS/FreeBSD)
                            if [ -z "$VALID_TO_EPOCH" ]; then
                                VALID_TO_EPOCH=$(date -j -f "%b %d %T %Y %Z" "$VALID_TO" +%s 2>/dev/null)
                            fi
                            
                            NOW_EPOCH=$(date +%s)
                            
                            if [ -n "$VALID_TO_EPOCH" ] && [ "$VALID_TO_EPOCH" -gt 0 ]; then
                                DAYS_REMAINING=$(( (VALID_TO_EPOCH - NOW_EPOCH) / 86400 ))
                            else
                                DAYS_REMAINING="N/A"
                            fi
                        else
                            DAYS_REMAINING="N/A"
                        fi
                        
                        # Determine status
                        CERT_STATUS="valid"
                        if [ "$DAYS_REMAINING" != "N/A" ]; then
                            if [ "$DAYS_REMAINING" -lt 0 ]; then
                                CERT_STATUS="expired"
                            elif [ "$DAYS_REMAINING" -lt 30 ]; then
                                CERT_STATUS="expiring_soon"
                            fi
                        fi
                        
                        # Key details
                        KEY_TYPE=$(echo "$CERT_TEXT" | grep "Public Key Algorithm" | sed "s/.*: *//" | head -1)
                        [ -z "$KEY_TYPE" ] && KEY_TYPE="-"
                        KEY_BITS=$(echo "$CERT_TEXT" | grep "Public-Key:" | sed "s/.*(\(.*\) bit).*/\1/" | head -1)
                        [ -z "$KEY_BITS" ] && KEY_BITS="-"
                        
                        SIG_ALGO=$(echo "$CERT_TEXT" | grep "Signature Algorithm:" | sed "s/.*: *//" | head -1)
                        [ -z "$SIG_ALGO" ] && SIG_ALGO="-"
                        
                        SERIAL=$(echo "$CERT_TEXT" | grep "Serial Number:" -A1 | tail -1 | tr -d " 
:")
                        [ -z "$SERIAL" ] && SERIAL="-"
                        
                        # Protocol and cipher from connection
                        # Try new format: "New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384"
                        TLS_VER=$(echo "$CERT_OUTPUT" | grep "Cipher is" | sed -n "s/.*\(TLSv[0-9.]*\).*/\1/p" | head -1)
                        if [ -z "$TLS_VER" ]; then
                            TLS_VER=$(echo "$CERT_OUTPUT" | grep "Protocol *:" | awk "{print \$NF}" | head -1)
                        fi
                        [ -z "$TLS_VER" ] && TLS_VER="-"
                        
                        CIPHER=$(echo "$CERT_OUTPUT" | grep "Cipher is" | sed -n "s/.*Cipher is \([^ ]*\).*/\1/p" | head -1)
                        if [ -z "$CIPHER" ]; then
                            CIPHER=$(echo "$CERT_OUTPUT" | grep "Cipher *:" | awk "{print \$NF}" | head -1)
                        fi
                        [ -z "$CIPHER" ] && CIPHER="-"
                        
                        # Flags
                        IS_WILDCARD=$(echo "$CN $SANS" | grep -q "\*\." && echo "yes" || echo "no")
                        IS_SELF_SIGNED=$([ "$CN" = "$ISSUER" ] && echo "yes" || echo "no")
                        
                        # Check weak key
                        IS_WEAK="no"
                        if [ "$KEY_BITS" != "-" ]; then
                            if echo "$KEY_TYPE" | grep -qi "rsa" && [ "$KEY_BITS" -lt 2048 ]; then
                                IS_WEAK="yes"
                            elif echo "$KEY_TYPE" | grep -qi "ec" && [ "$KEY_BITS" -lt 256 ]; then
                                IS_WEAK="yes"
                            fi
                        fi
                        
                        # Check deprecated TLS
                        IS_DEPRECATED="no"
                        case "$TLS_VER" in
                            TLSv1|TLSv1.0|TLSv1.1|SSLv*) IS_DEPRECATED="yes" ;;
                        esac
                        
                        # Check for SCT (Certificate Transparency)
                        SCT_COUNT=$(echo "$CERT_TEXT" | grep -c "CT Precertificate SCTs" || echo "0")
                        
                        # Check if self-signed by comparing issuer
                        if [ "$IS_SELF_SIGNED" = "no" ]; then
                            if echo "$ISSUER_ORG" | grep -qi "self"; then
                                IS_SELF_SIGNED="yes"
                            fi
                        fi
                        
                        # Build CSV line (escape quotes in fields)
                        CN_ESC=$(echo "$CN" | sed "s/\"/\"\"/g")
                        SANS_ESC=$(echo "$SANS" | sed "s/\"/\"\"/g")
                        ORG_ESC=$(echo "$ORG" | sed "s/\"/\"\"/g")
                        ISSUER_ESC=$(echo "$ISSUER" | sed "s/\"/\"\"/g")
                        ISSUER_ORG_ESC=$(echo "$ISSUER_ORG" | sed "s/\"/\"\"/g")
                        
                        CSV_LINE="$IP,$TLS_PORT,\"$CN_ESC\",$SAN_COUNT,\"$SANS_ESC\",\"$ORG_ESC\",$COUNTRY,\"$ISSUER_ESC\",\"$ISSUER_ORG_ESC\",$VALID_FROM,$VALID_TO,$DAYS_REMAINING,$CERT_STATUS,$KEY_TYPE,$KEY_BITS,$SIG_ALGO,$SERIAL,$TLS_VER,$CIPHER,$IS_WILDCARD,$IS_SELF_SIGNED,$IS_WEAK,$IS_DEPRECATED,$SCT_COUNT"
                        
                        RESULT="===================================
IP: $IP:$TLS_PORT
Timestamp: $(date "+%Y-%m-%d %H:%M:%S %Z")
===================================
$CERT_OUTPUT

===================================
Certificate Details:
===================================
$CERT_TEXT


"
                        STATUS="success"
                    else
                        RESULT="===================================
IP: $IP:$TLS_PORT
Status: CERTIFICATE_PARSE_ERROR
===================================
$CERT_OUTPUT

"
                        CSV_LINE="$IP,$TLS_PORT,PARSE_ERROR,0,,,,,,,,,parse_error,,,,,,,,,,,"
                        STATUS="parseerr"
                    fi
                else
                    # Connected but something else went wrong
                    RESULT="===================================
IP: $IP:$TLS_PORT
Status: HANDSHAKE_FAILED
===================================
$CERT_OUTPUT

"
                    CSV_LINE="$IP,$TLS_PORT,HANDSHAKE_FAILED,0,,,,,,,,,handshake_failed,,,,,,,,,,,"
                    STATUS="handshake"
                fi
            else
                # Could not connect at all
                RESULT="===================================
IP: $IP:$TLS_PORT
Status: CONNECTION_REFUSED
===================================

"
                CSV_LINE="$IP,$TLS_PORT,CONNECTION_REFUSED,0,,,,,,,,,connection_refused,,,,,,,,,,,"
                STATUS="refused"
            fi
            
            (
                flock -x 200
                printf "%s" "$RESULT" >> "'"$TLS_FILE"'"
                echo "$CSV_LINE" >> "'"$TLS_CSV"'"
            ) 200>"'"$TLS_FILE"'.lock"
            
            # Visual feedback based on result
            case "$STATUS" in
                success) printf "+" ;;
                nocert) printf "-" ;;
                parseerr|handshake) printf "?" ;;
                refused) printf "." ;;
            esac
        ' 2>/dev/null
        echo
        echo
        log_info "Legend: + = cert found, - = no cert offered, ? = error, . = refused"
    fi
    
    echo "[+] TLS scanning complete"
    
    # Generate all analysis reports
    generate_tls_analysis
}

# =============================
# Generate TLS analysis reports
# =============================
generate_tls_analysis() {
    [ ! -s "$TLS_CSV" ] || [ $(wc -l < "$TLS_CSV") -le 1 ] && return
    
    log_info "Generating TLS analysis reports..."
    
    # 1. Generate issues report
    {
        echo "==================================="
        echo "TLS Certificate Issues Report"
        echo "==================================="
        echo
        
        # Expired certificates
        EXPIRED=$(awk -F, 'NR>1 && $13=="expired" {print $1}' "$TLS_CSV" | wc -l)
        if [ "$EXPIRED" -gt 0 ]; then
            echo "EXPIRED CERTIFICATES: $EXPIRED"
            awk -F, 'NR>1 && $13=="expired" {days = $12; if (days < 0) days = -days; printf "  %s - CN: %s (expired %s days ago)\n", $1, $3, days}' "$TLS_CSV"
            echo
        fi
        
        # Expiring soon
        EXPIRING=$(awk -F, 'NR>1 && $13=="expiring_soon" {print $1}' "$TLS_CSV" | wc -l)
        if [ "$EXPIRING" -gt 0 ]; then
            echo "EXPIRING SOON (< 30 days): $EXPIRING"
            awk -F, 'NR>1 && $13=="expiring_soon" {printf "  %s - CN: %s (%s days remaining)\n", $1, $3, $12}' "$TLS_CSV"
            echo
        fi
        
        # Self-signed certificates
        SELF_SIGNED=$(awk -F, 'NR>1 && $21=="yes" {print $1}' "$TLS_CSV" | wc -l)
        if [ "$SELF_SIGNED" -gt 0 ]; then
            echo "SELF-SIGNED CERTIFICATES: $SELF_SIGNED"
            awk -F, 'NR>1 && $21=="yes" {printf "  %s - CN: %s\n", $1, $3}' "$TLS_CSV" | head -20
            echo
        fi
        
        # Weak keys
        WEAK_KEYS=$(awk -F, 'NR>1 && $22=="yes" {print $1}' "$TLS_CSV" | wc -l)
        if [ "$WEAK_KEYS" -gt 0 ]; then
            echo "WEAK KEY SIZES: $WEAK_KEYS"
            awk -F, 'NR>1 && $22=="yes" {printf "  %s - %s %s bits\n", $1, $14, $15}' "$TLS_CSV"
            echo
        fi
        
        # Deprecated TLS
        DEPRECATED=$(awk -F, 'NR>1 && $23=="yes" {print $1}' "$TLS_CSV" | wc -l)
        if [ "$DEPRECATED" -gt 0 ]; then
            echo "DEPRECATED TLS VERSIONS: $DEPRECATED"
            awk -F, 'NR>1 && $23=="yes" {printf "  %s - %s\n", $1, $18}' "$TLS_CSV"
            echo
        fi
        
        # Connection failures
        REFUSED=$(awk -F, 'NR>1 && $13=="connection_refused" {print $1}' "$TLS_CSV" | wc -l)
        NO_CERT=$(awk -F, 'NR>1 && $13=="no_certificate" {print $1}' "$TLS_CSV" | wc -l)
        
        echo "CONNECTION ISSUES:"
        echo "  Connection refused: $REFUSED"
        echo "  No certificate offered: $NO_CERT"
        echo
    } > "$TLS_ISSUES"
    
    # 2. Generate certificate chains report
    {
        echo "==================================="
        echo "TLS Certificate Chains"
        echo "==================================="
        echo
        echo "Top Certificate Issuers:"
        awk -F, 'NR>1 && $8!="" && $8!="-" {count[$8]++} 
                 END {for(issuer in count) print count[issuer], issuer}' "$TLS_CSV" | \
            sort -rn | head -15 | awk '{printf "  %3d certs - %s\n", $1, substr($0, index($0,$2))}'
        echo
        
        echo "Top Issuing Organizations:"
        awk -F, 'NR>1 && $9!="" && $9!="-" {count[$9]++} 
                 END {for(org in count) print count[org], org}' "$TLS_CSV" | \
            sort -rn | head -15 | awk '{printf "  %3d certs - %s\n", $1, substr($0, index($0,$2))}'
        echo
    } > "$TLS_CHAINS"
    
    # 3. Generate statistics report
    {
        echo "==================================="
        echo "TLS Certificate Statistics"
        echo "==================================="
        echo
        
        TOTAL=$(awk 'NR>1' "$TLS_CSV" | wc -l)
        VALID=$(awk -F, 'NR>1 && $13=="valid" {print $1}' "$TLS_CSV" | wc -l)
        
        echo "Certificate Overview:"
        echo "  Total scanned:        $TOTAL"
        echo "  Valid certificates:   $VALID"
        echo "  Expired:              $EXPIRED"
        echo "  Expiring soon:        $EXPIRING"
        echo "  Self-signed:          $SELF_SIGNED"
        echo "  Weak keys:            $WEAK_KEYS"
        echo "  Deprecated TLS:       $DEPRECATED"
        echo
        
        echo "Key Types:"
        awk -F, 'NR>1 && $14!="" && $14!="-" {count[$14]++} 
                 END {for(type in count) print count[type], type}' "$TLS_CSV" | \
            sort -rn | awk '{printf "  %3d - %s\n", $1, $2}'
        echo
        
        echo "Key Sizes:"
        awk -F, 'NR>1 && $15!="" && $15!="-" {count[$15]++} 
                 END {for(size in count) print count[size], size}' "$TLS_CSV" | \
            sort -rn | awk '{printf "  %3d - %s bits\n", $1, $2}'
        echo
        
        echo "TLS Versions:"
        awk -F, 'NR>1 && $18!="" && $18!="-" {count[$18]++} 
                 END {for(ver in count) print count[ver], ver}' "$TLS_CSV" | \
            sort -rn | awk '{printf "  %3d - %s\n", $1, $2}'
        echo
        
        echo "Wildcard Certificates:"
        WILDCARDS=$(awk -F, 'NR>1 && $20=="yes" {print $1}' "$TLS_CSV" | wc -l)
        echo "  $WILDCARDS certificates use wildcards"
        echo
        
        echo "Certificate Transparency:"
        WITH_SCT=$(awk -F, 'NR>1 && $24>0 {print $1}' "$TLS_CSV" | wc -l)
        echo "  $WITH_SCT certificates have SCT logs"
        echo
    } > "$TLS_STATS"
    
    # 4. Generate summary (calls existing function)
    generate_tls_summary
    
    echo "[+] TLS analysis complete"
    echo "    - Issues report:  $TLS_ISSUES"
    echo "    - Chains report:  $TLS_CHAINS"
    echo "    - Statistics:     $TLS_STATS"
    echo "    - Summary:        $TLS_SUMMARY"
    echo
}

# =============================
# Generate TLS analysis reports
# =============================
generate_tls_analysis() {
    [ ! -s "$TLS_CSV" ] || [ $(wc -l < "$TLS_CSV") -le 1 ] && return
    
    log_info "Generating TLS analysis reports..."
    
    # 1. Generate issues report
    {
        echo "==================================="
        echo "TLS Certificate Issues Report"
        echo "==================================="
        echo
        
        # Expired certificates
        EXPIRED=$(awk -F, 'NR>1 && $13=="expired" {print $1}' "$TLS_CSV" | wc -l)
        if [ "$EXPIRED" -gt 0 ]; then
            echo "EXPIRED CERTIFICATES: $EXPIRED"
            awk -F, 'NR>1 && $13=="expired" {days = $12; if (days < 0) days = -days; printf "  %s - CN: %s (expired %s days ago)\n", $1, $3, days}' "$TLS_CSV"
            echo
        fi
        
        # Expiring soon
        EXPIRING=$(awk -F, 'NR>1 && $13=="expiring_soon" {print $1}' "$TLS_CSV" | wc -l)
        if [ "$EXPIRING" -gt 0 ]; then
            echo "EXPIRING SOON (< 30 days): $EXPIRING"
            awk -F, 'NR>1 && $13=="expiring_soon" {printf "  %s - CN: %s (%s days remaining)\n", $1, $3, $12}' "$TLS_CSV"
            echo
        fi
        
        # Self-signed certificates
        SELF_SIGNED=$(awk -F, 'NR>1 && $21=="yes" {print $1}' "$TLS_CSV" | wc -l)
        if [ "$SELF_SIGNED" -gt 0 ]; then
            echo "SELF-SIGNED CERTIFICATES: $SELF_SIGNED"
            awk -F, 'NR>1 && $21=="yes" {printf "  %s - CN: %s\n", $1, $3}' "$TLS_CSV" | head -20
            echo
        fi
        
        # Weak keys
        WEAK_KEYS=$(awk -F, 'NR>1 && $22=="yes" {print $1}' "$TLS_CSV" | wc -l)
        if [ "$WEAK_KEYS" -gt 0 ]; then
            echo "WEAK KEY SIZES: $WEAK_KEYS"
            awk -F, 'NR>1 && $22=="yes" {printf "  %s - %s %s bits\n", $1, $14, $15}' "$TLS_CSV"
            echo
        fi
        
        # Deprecated TLS
        DEPRECATED=$(awk -F, 'NR>1 && $23=="yes" {print $1}' "$TLS_CSV" | wc -l)
        if [ "$DEPRECATED" -gt 0 ]; then
            echo "DEPRECATED TLS VERSIONS: $DEPRECATED"
            awk -F, 'NR>1 && $23=="yes" {printf "  %s - %s\n", $1, $18}' "$TLS_CSV"
            echo
        fi
        
        # Connection failures
        REFUSED=$(awk -F, 'NR>1 && $13=="connection_refused" {print $1}' "$TLS_CSV" | wc -l)
        NO_CERT=$(awk -F, 'NR>1 && $13=="no_certificate" {print $1}' "$TLS_CSV" | wc -l)
        
        echo "CONNECTION ISSUES:"
        echo "  Connection refused: $REFUSED"
        echo "  No certificate offered: $NO_CERT"
        echo
    } > "$TLS_ISSUES"
    
    # 2. Generate certificate chains report
    {
        echo "==================================="
        echo "TLS Certificate Chains"
        echo "==================================="
        echo
        echo "Top Certificate Issuers:"
        awk -F, 'NR>1 && $8!="" && $8!="-" {count[$8]++} 
                 END {for(issuer in count) print count[issuer], issuer}' "$TLS_CSV" | \
            sort -rn | head -15 | awk '{printf "  %3d certs - %s\n", $1, substr($0, index($0,$2))}'
        echo
        
        echo "Top Issuing Organizations:"
        awk -F, 'NR>1 && $9!="" && $9!="-" {count[$9]++} 
                 END {for(org in count) print count[org], org}' "$TLS_CSV" | \
            sort -rn | head -15 | awk '{printf "  %3d certs - %s\n", $1, substr($0, index($0,$2))}'
        echo
    } > "$TLS_CHAINS"
    
    # 3. Generate statistics report
    {
        echo "==================================="
        echo "TLS Certificate Statistics"
        echo "==================================="
        echo
        
        TOTAL=$(awk 'NR>1' "$TLS_CSV" | wc -l)
        VALID=$(awk -F, 'NR>1 && $13=="valid" {print $1}' "$TLS_CSV" | wc -l)
        
        echo "Certificate Overview:"
        echo "  Total scanned:        $TOTAL"
        echo "  Valid certificates:   $VALID"
        echo "  Expired:              $EXPIRED"
        echo "  Expiring soon:        $EXPIRING"
        echo "  Self-signed:          $SELF_SIGNED"
        echo "  Weak keys:            $WEAK_KEYS"
        echo "  Deprecated TLS:       $DEPRECATED"
        echo
        
        echo "Key Types:"
        awk -F, 'NR>1 && $14!="" && $14!="-" {count[$14]++} 
                 END {for(type in count) print count[type], type}' "$TLS_CSV" | \
            sort -rn | awk '{printf "  %3d - %s\n", $1, $2}'
        echo
        
        echo "Key Sizes:"
        awk -F, 'NR>1 && $15!="" && $15!="-" {count[$15]++} 
                 END {for(size in count) print count[size], size}' "$TLS_CSV" | \
            sort -rn | awk '{printf "  %3d - %s bits\n", $1, $2}'
        echo
        
        echo "TLS Versions:"
        awk -F, 'NR>1 && $18!="" && $18!="-" {count[$18]++} 
                 END {for(ver in count) print count[ver], ver}' "$TLS_CSV" | \
            sort -rn | awk '{printf "  %3d - %s\n", $1, $2}'
        echo
        
        echo "Wildcard Certificates:"
        WILDCARDS=$(awk -F, 'NR>1 && $20=="yes" {print $1}' "$TLS_CSV" | wc -l)
        echo "  $WILDCARDS certificates use wildcards"
        echo
        
        echo "Certificate Transparency:"
        WITH_SCT=$(awk -F, 'NR>1 && $24>0 {print $1}' "$TLS_CSV" | wc -l)
        echo "  $WITH_SCT certificates have SCT logs"
        echo
    } > "$TLS_STATS"
    
    # 4. Generate summary (calls existing function)
    generate_tls_summary
    
    echo "[+] TLS analysis complete"
    echo "    - Issues report:  $TLS_ISSUES"
    echo "    - Chains report:  $TLS_CHAINS"
    echo "    - Statistics:     $TLS_STATS"
    echo "    - Summary:        $TLS_SUMMARY"
    echo
}

# =============================
# Generate TLS summary
# =============================
generate_tls_summary() {
    [ ! -s "$TLS_FILE" ] && return
    
    log_info "Generating TLS certificate summary..."
    
    TOTAL=$(grep -c "^IP:" "$TLS_FILE")
    SUCCESS=$(grep -c "Certificate Details:" "$TLS_FILE")
    NO_CERT=$(grep -c "NO_CERTIFICATE" "$TLS_FILE")
    REFUSED=$(grep -c "CONNECTION_REFUSED" "$TLS_FILE")
    HANDSHAKE=$(grep -c "HANDSHAKE_FAILED" "$TLS_FILE")
    
    {
        echo "==================================="
        echo "TLS Certificate Scan Summary"
        echo "==================================="
        echo
        echo "Total IPs scanned:        $TOTAL"
        echo "Certificates retrieved:   $SUCCESS"
        echo "No certificate offered:   $NO_CERT"
        echo "Connection refused:       $REFUSED"
        echo "Handshake failed:         $HANDSHAKE"
        echo
        
        if [ "$SUCCESS" -gt 0 ]; then
            echo "Successfully retrieved certificates from:"
            grep -B2 "Certificate Details:" "$TLS_FILE" | grep "^IP:" | sed 's/IP: /  /' | head -20
            echo
        fi
        
        echo "Results saved in: $TLS_FILE"
        echo
        echo "To analyze certificates, use:"
        echo "  grep 'Subject:' $TLS_FILE"
        echo "  grep 'Issuer:' $TLS_FILE"
        echo "  grep 'Not After' $TLS_FILE"
        echo "  grep 'DNS:' $TLS_FILE"
    } > "$TLS_SUMMARY"
    
    cat "$TLS_SUMMARY"
    echo
}

# =============================
# Cloud Provider Detection
# =============================
detect_cloud_provider() {
    IP="$1"
    
    # Quick pattern matching first (faster)
    case "$IP" in
        3.*|13.*|15.*|18.*|34.*|35.*|52.*|54.*|99.*|100.*)
            CLOUD_INFO=$(curl -s --max-time 2 "https://ipinfo.io/${IP}/org" 2>/dev/null)
            echo "$CLOUD_INFO" | grep -qi "amazon\|aws" && echo "AWS" && return
            ;;
        20.*|40.*|51.*|104.*|137.*|138.*|168.*)
            CLOUD_INFO=$(curl -s --max-time 2 "https://ipinfo.io/${IP}/org" 2>/dev/null)
            echo "$CLOUD_INFO" | grep -qi "microsoft\|azure" && echo "Azure" && return
            ;;
        104.16.*|104.17.*|104.18.*|172.6[4-7].*|173.245.*|188.114.*)
            echo "Cloudflare" && return
            ;;
    esac
    
    # Fallback: Query ipinfo.io
    CLOUD_INFO=$(curl -s --max-time 2 "https://ipinfo.io/${IP}/org" 2>/dev/null)
    case "$CLOUD_INFO" in
        *Amazon*|*AWS*) echo "AWS" ;;
        *Microsoft*|*Azure*) echo "Azure" ;;
        *Google*|*GCP*) echo "GCP" ;;
        *Cloudflare*) echo "Cloudflare" ;;
        *DigitalOcean*) echo "DigitalOcean" ;;
        *Linode*) echo "Linode" ;;
        *OVH*) echo "OVH" ;;
        *Hetzner*) echo "Hetzner" ;;
        *) echo "Other" ;;
    esac
}

enrich_ptr_with_cloud() {
    [ "$DO_CLOUD_DETECT" -eq 0 ] && return
    [ ! -f "$PTR_FILE" ] || [ ! -s "$PTR_FILE" ] && return
    
    log_header "Cloud Provider Detection"
    
    CLOUD_FILE="$OUTDIR/cloud_providers.csv"
    echo "ip,hostname,cloud_provider" > "$CLOUD_FILE"
    
    COUNT=0
    TOTAL=$(wc -l < "$PTR_FILE")
    
    log_info "Detecting cloud providers for $TOTAL hosts..."
    
    while IFS=, read -r IP HOSTNAME; do
        COUNT=$((COUNT + 1))
        log_progress "Cloud detection: $COUNT/$TOTAL"
        
        CLOUD=$(detect_cloud_provider "$IP")
        echo "$IP,$HOSTNAME,$CLOUD" >> "$CLOUD_FILE"
        sleep 0.1
    done < "$PTR_FILE"
    
    echo
    log_success "Cloud provider detection complete"
    
    # Summary
    {
        echo "==================================="
        echo "Cloud Provider Distribution"
        echo "==================================="
        echo
        awk -F, 'NR>1 && $3!="" && $3!="Other" {count[$3]++} 
                 END {for(p in count) print count[p], p}' "$CLOUD_FILE" | \
            sort -rn | awk '{printf "  %-20s %d hosts\n", $2, $1}'
        OTHER=$(awk -F, 'NR>1 && $3=="Other"' "$CLOUD_FILE" | wc -l)
        [ "$OTHER" -gt 0 ] && echo "  Other: $OTHER hosts"
    } | tee "$OUTDIR/cloud_summary.txt"
    echo
}

# =============================
# HTTP Security Headers Check
# =============================
check_http_security_single() {
    IP="$1"
    PORT="$2"
    PROTOCOL="$3"
    
    URL="${PROTOCOL}://${IP}:${PORT}/"
    HEADERS=$(curl -s -I --max-time "$HTTP_SECURITY_TIMEOUT" -L "$URL" 2>/dev/null)
    
    [ $? -ne 0 ] && echo "$IP,$PORT,failed,-,-,-,-,-,-,-,-,-,-,-" && return
    
    # Extract headers
    HSTS=$(echo "$HEADERS" | grep -i "^Strict-Transport-Security:" | cut -d: -f2- | sed 's/^ *//;s/ *$//' | tr -d '\r\n')
    CSP=$(echo "$HEADERS" | grep -i "^Content-Security-Policy:" | cut -d: -f2- | sed 's/^ *//;s/ *$//' | tr -d '\r\n' | cut -c1-100)
    X_FRAME=$(echo "$HEADERS" | grep -i "^X-Frame-Options:" | cut -d: -f2- | sed 's/^ *//;s/ *$//' | tr -d '\r\n')
    X_CONTENT=$(echo "$HEADERS" | grep -i "^X-Content-Type-Options:" | cut -d: -f2- | sed 's/^ *//;s/ *$//' | tr -d '\r\n')
    X_XSS=$(echo "$HEADERS" | grep -i "^X-XSS-Protection:" | cut -d: -f2- | sed 's/^ *//;s/ *$//' | tr -d '\r\n')
    REFERRER=$(echo "$HEADERS" | grep -i "^Referrer-Policy:" | cut -d: -f2- | sed 's/^ *//;s/ *$//' | tr -d '\r\n')
    PERMISSIONS=$(echo "$HEADERS" | grep -i "^Permissions-Policy:" | cut -d: -f2- | sed 's/^ *//;s/ *$//' | tr -d '\r\n' | cut -c1-100)
    
    # Determine status for each header
    HSTS_STATUS="MISSING"
    CSP_STATUS="MISSING"
    X_FRAME_STATUS="MISSING"
    X_CONTENT_STATUS="MISSING"
    X_XSS_STATUS="MISSING"
    REFERRER_STATUS="MISSING"
    PERMISSIONS_STATUS="MISSING"
    
    [ -n "$HSTS" ] && HSTS_STATUS="PRESENT"
    [ -n "$CSP" ] && CSP_STATUS="PRESENT"
    [ -n "$X_FRAME" ] && X_FRAME_STATUS="PRESENT"
    [ -n "$X_CONTENT" ] && X_CONTENT_STATUS="PRESENT"
    [ -n "$X_XSS" ] && X_XSS_STATUS="PRESENT"
    [ -n "$REFERRER" ] && REFERRER_STATUS="PRESENT"
    [ -n "$PERMISSIONS" ] && PERMISSIONS_STATUS="PRESENT"
    
    # Determine overall risk level
    CRITICAL_MISSING=0
    HIGH_MISSING=0
    MEDIUM_MISSING=0
    
    # CRITICAL: HSTS on HTTPS sites
    if [ "$PROTOCOL" = "https" ] && [ "$HSTS_STATUS" = "MISSING" ]; then
        CRITICAL_MISSING=$((CRITICAL_MISSING + 1))
        HSTS_STATUS="MISSING_CRITICAL"
    fi
    
    # HIGH: CSP and X-Frame-Options (prevent XSS and clickjacking)
    [ "$CSP_STATUS" = "MISSING" ] && HIGH_MISSING=$((HIGH_MISSING + 1))
    [ "$X_FRAME_STATUS" = "MISSING" ] && HIGH_MISSING=$((HIGH_MISSING + 1))
    
    # MEDIUM: Other headers
    [ "$X_CONTENT_STATUS" = "MISSING" ] && MEDIUM_MISSING=$((MEDIUM_MISSING + 1))
    [ "$X_XSS_STATUS" = "MISSING" ] && MEDIUM_MISSING=$((MEDIUM_MISSING + 1))
    [ "$REFERRER_STATUS" = "MISSING" ] && MEDIUM_MISSING=$((MEDIUM_MISSING + 1))
    [ "$PERMISSIONS_STATUS" = "MISSING" ] && MEDIUM_MISSING=$((MEDIUM_MISSING + 1))
    
    # Determine overall risk
    if [ "$CRITICAL_MISSING" -gt 0 ]; then
        RISK_LEVEL="CRITICAL"
    elif [ "$HIGH_MISSING" -ge 2 ]; then
        RISK_LEVEL="HIGH"
    elif [ "$HIGH_MISSING" -ge 1 ]; then
        RISK_LEVEL="MEDIUM"
    elif [ "$MEDIUM_MISSING" -ge 2 ]; then
        RISK_LEVEL="LOW"
    else
        RISK_LEVEL="GOOD"
    fi
    
    # Escape CSV fields (replace quotes, keep empty if missing)
    CSP_ESC=$(echo "$CSP" | sed 's/"/""/g')
    PERMISSIONS_ESC=$(echo "$PERMISSIONS" | sed 's/"/""/g')
    HSTS_ESC=$(echo "$HSTS" | sed 's/"/""/g')
    
    # CSV output: ip,port,status,risk_level,hsts_status,csp_status,x_frame_status,x_content_status,x_xss_status,referrer_status,permissions_status,hsts_value,csp_value,permissions_value
    echo "$IP,$PORT,success,$RISK_LEVEL,$HSTS_STATUS,$CSP_STATUS,$X_FRAME_STATUS,$X_CONTENT_STATUS,$X_XSS_STATUS,$REFERRER_STATUS,$PERMISSIONS_STATUS,\"$HSTS_ESC\",\"$CSP_ESC\",\"$PERMISSIONS_ESC\""
}

run_http_security_phase() {
    [ "$DO_HTTP_SECURITY" -eq 0 ] && return
    
    log_header "HTTP Security Headers Analysis"
    
    HTTP_SECURITY_FILE="$OUTDIR/http_security.csv"
    HTTP_SECURITY_TARGETS="$OUTDIR/.http_security_targets.tmp"
    rm -f "$HTTP_SECURITY_TARGETS"
    
    case "$HTTP_SECURITY_MODE" in
        ptr)
            [ -s "$PTR_FILE" ] && cut -d, -f1 "$PTR_FILE" > "$HTTP_SECURITY_TARGETS"
            ;;
        gateway)
            while read PREF; do
                case "$PREF" in
                    *.*)
                        BLOCK=$(echo "$PREF" | cut -d/ -f1 | cut -d. -f1-3)
                        echo "$BLOCK.1" >> "$HTTP_SECURITY_TARGETS"
                        echo "$BLOCK.254" >> "$HTTP_SECURITY_TARGETS"
                        ;;
                esac
            done < "$PREFIX_FILE"
            ;;
    esac
    
    [ ! -s "$HTTP_SECURITY_TARGETS" ] && log_warning "No targets for HTTP security check" && return
    
    sort -u "$HTTP_SECURITY_TARGETS" -o "$HTTP_SECURITY_TARGETS"
    TARGET_COUNT=$(wc -l < "$HTTP_SECURITY_TARGETS")
    
    log_info "Mode: $HTTP_SECURITY_MODE"
    log_info "Targets: $TARGET_COUNT"
    log_info "Ports: $HTTP_SECURITY_PORTS"
    echo
    
    # CSV header
    echo "ip,port,status,risk_level,hsts_status,csp_status,x_frame_status,x_content_status,x_xss_status,referrer_status,permissions_status,hsts_value,csp_value,permissions_value" > "$HTTP_SECURITY_FILE"
    
    for PORT in $(echo "$HTTP_SECURITY_PORTS" | tr ',' ' '); do
        PROTOCOL="http"
        [ "$PORT" = "443" ] || [ "$PORT" = "8443" ] && PROTOCOL="https"
        
        log_info "Checking port $PORT ($PROTOCOL)..."
        
        COUNT=0
        while read IP; do
            COUNT=$((COUNT + 1))
            printf "\r[*] Progress: $COUNT/$TARGET_COUNT"
            check_http_security_single "$IP" "$PORT" "$PROTOCOL" >> "$HTTP_SECURITY_FILE"
        done < "$HTTP_SECURITY_TARGETS"
        echo
    done
    
    log_success "HTTP security checks complete"
    
    # Summary
    {
        echo "==================================="
        echo "HTTP Security Headers Summary"
        echo "==================================="
        echo
        TOTAL=$(awk -F, 'NR>1' "$HTTP_SECURITY_FILE" | wc -l)
        SUCCESS=$(awk -F, 'NR>1 && $3=="success"' "$HTTP_SECURITY_FILE" | wc -l)
        echo "Total checks: $TOTAL"
        echo "Successful: $SUCCESS"
        echo
        
        echo "Risk Distribution:"
        CRITICAL=$(awk -F, 'NR>1 && $4=="CRITICAL"' "$HTTP_SECURITY_FILE" | wc -l)
        HIGH=$(awk -F, 'NR>1 && $4=="HIGH"' "$HTTP_SECURITY_FILE" | wc -l)
        MEDIUM=$(awk -F, 'NR>1 && $4=="MEDIUM"' "$HTTP_SECURITY_FILE" | wc -l)
        LOW=$(awk -F, 'NR>1 && $4=="LOW"' "$HTTP_SECURITY_FILE" | wc -l)
        GOOD=$(awk -F, 'NR>1 && $4=="GOOD"' "$HTTP_SECURITY_FILE" | wc -l)
        
        echo "  CRITICAL (HSTS missing on HTTPS): $CRITICAL"
        echo "  HIGH (Missing CSP + X-Frame):     $HIGH"
        echo "  MEDIUM (Missing 1 high-priority): $MEDIUM"
        echo "  LOW (Missing 2+ medium-priority): $LOW"
        echo "  GOOD (All recommended present):   $GOOD"
        echo
        
        if [ "$CRITICAL" -gt 0 ]; then
            echo "⚠️  CRITICAL FINDINGS:"
            echo "  $CRITICAL HTTPS sites missing HSTS (vulnerable to SSL stripping)"
            echo
            echo "  Affected hosts:"
            awk -F, 'NR>1 && $4=="CRITICAL" {print "    " $1 ":" $2}' "$HTTP_SECURITY_FILE" | head -10
            [ "$CRITICAL" -gt 10 ] && echo "    ... and $((CRITICAL - 10)) more"
            echo
        fi
        
        echo "Missing Headers (by priority):"
        echo
        echo "  HIGH PRIORITY:"
        HSTS_MISSING=$(awk -F, 'NR>1 && $3=="success" && $5 ~ /MISSING/' "$HTTP_SECURITY_FILE" | wc -l)
        CSP_MISSING=$(awk -F, 'NR>1 && $3=="success" && $6=="MISSING"' "$HTTP_SECURITY_FILE" | wc -l)
        X_FRAME_MISSING=$(awk -F, 'NR>1 && $3=="success" && $7=="MISSING"' "$HTTP_SECURITY_FILE" | wc -l)
        
        echo "    HSTS missing:              $HSTS_MISSING servers"
        echo "    CSP missing:               $CSP_MISSING servers"
        echo "    X-Frame-Options missing:   $X_FRAME_MISSING servers"
        echo
        echo "  MEDIUM PRIORITY:"
        X_CONTENT_MISSING=$(awk -F, 'NR>1 && $3=="success" && $8=="MISSING"' "$HTTP_SECURITY_FILE" | wc -l)
        X_XSS_MISSING=$(awk -F, 'NR>1 && $3=="success" && $9=="MISSING"' "$HTTP_SECURITY_FILE" | wc -l)
        REFERRER_MISSING=$(awk -F, 'NR>1 && $3=="success" && $10=="MISSING"' "$HTTP_SECURITY_FILE" | wc -l)
        PERMISSIONS_MISSING=$(awk -F, 'NR>1 && $3=="success" && $11=="MISSING"' "$HTTP_SECURITY_FILE" | wc -l)
        
        echo "    X-Content-Type-Options missing:    $X_CONTENT_MISSING servers"
        echo "    X-XSS-Protection missing:          $X_XSS_MISSING servers"
        echo "    Referrer-Policy missing:           $REFERRER_MISSING servers"
        echo "    Permissions-Policy missing:        $PERMISSIONS_MISSING servers"
        echo
        
        echo "RECOMMENDATIONS:"
        if [ "$CRITICAL" -gt 0 ]; then
            echo "  🔴 URGENT: Enable HSTS on all HTTPS endpoints"
            echo "     Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"
            echo "     Risk: SSL stripping attacks, downgrade to HTTP"
            echo
        fi
        if [ "$HIGH" -gt 0 ]; then
            echo "  🟠 HIGH PRIORITY: Implement Content-Security-Policy and X-Frame-Options"
            echo "     CSP: Start with 'default-src https:' and refine"
            echo "     X-Frame: Use 'DENY' or 'SAMEORIGIN'"
            echo "     Risk: XSS attacks, clickjacking, code injection"
            echo
        fi
        if [ "$MEDIUM" -gt 0 ]; then
            echo "  🟡 MEDIUM PRIORITY: Add one missing high-priority header"
            echo "     Review HIGH PRIORITY recommendations above"
            echo "     Risk: Partial protection leaves attack vectors open"
            echo
        fi
        if [ "$LOW" -gt 0 ]; then
            echo "  🟢 LOW PRIORITY: Optional security hardening (not all may be necessary)"
            echo
            echo "     Recommended (if applicable to your use case):"
            echo "       • X-Content-Type-Options: nosniff"
            echo "         Prevents MIME confusion attacks - recommended for all sites"
            echo
            echo "       • Referrer-Policy: strict-origin-when-cross-origin"
            echo "         Protects user privacy - recommended if handling sensitive data"
            echo
            echo "       • Permissions-Policy: geolocation=(), microphone=(), camera=()"
            echo "         Restricts browser features - only needed if you don't use these features"
            echo
            echo "     Optional/Legacy (may not be needed):"
            echo "       • X-XSS-Protection: 1; mode=block"
            echo "         DEPRECATED - Modern browsers ignore this (CSP is preferred)"
            echo "         Only useful for legacy IE/Edge support"
            echo
            echo "     Risk: Minor defense-in-depth gaps, but core protections are in place"
            echo
        fi
        if [ "$GOOD" -eq "$SUCCESS" ] && [ "$SUCCESS" -gt 0 ]; then
            echo "  ✅ EXCELLENT: All scanned servers have recommended security headers!"
            echo "     Continue monitoring for configuration drift"
            echo
        fi
        echo "  📋 Full details: $HTTP_SECURITY_FILE"
    } | tee "$OUTDIR/http_security_summary.txt"
    echo
}

# =============================
# =============================
# =============================
# Authorization Prompts
# =============================

# Check if running in automation mode (quiet/non-interactive)
is_interactive() {
    # Check if stdin is a terminal and not in quiet mode
    [ -t 0 ] && [ "$QUIET_MODE" -eq 0 ] && return 0
    return 1
}

# Port scan authorization prompt
prompt_port_scan_authorization() {
    [ "$DO_PORT_SCAN" -eq 0 ] && return 0
    
    # Skip prompt in non-interactive mode
    if ! is_interactive; then
        log_warning "Running in non-interactive mode - assuming authorization for port scanning"
        return 0
    fi
    
    echo
    printf "${BOLD}${YELLOW}###############################################################################${NC}\n"
    printf "${BOLD}${YELLOW}PORT SCANNING AUTHORIZATION REQUIRED${NC}\n"
    printf "${BOLD}${YELLOW}###############################################################################${NC}\n"
    echo
    printf "You are about to perform ${BOLD}PORT SCANNING${NC} on network infrastructure.\n"
    echo
    printf "${BOLD}LEGAL REQUIREMENTS:${NC}\n"
    printf "  * You must have ${BOLD}EXPLICIT WRITTEN AUTHORIZATION${NC} to scan this network\n"
    echo "  * Unauthorized port scanning may violate:"
    echo "    - Computer Fraud and Abuse Act (CFAA) - USA"
    echo "    - Computer Misuse Act - UK"
    echo "    - Similar laws in other jurisdictions"
    echo "  * Penalties can include fines and imprisonment"
    echo
    printf "${BOLD}ACCEPTABLE AUTHORIZATION:${NC}\n"
    echo "  * You own the network infrastructure"
    echo "  * Written permission from network owner"
    echo "  * Bug bounty program with defined scope"
    echo "  * Paid security assessment contract"
    echo "  * Internal security team with corporate authorization"
    echo
    printf "${BOLD}SCAN DETAILS:${NC}\n"
    echo "  * Target ASN: $ASN"
    echo "  * Scan Mode: $PORT_SCAN_MODE"
    echo "  * Method: TCP connect scan (no stealth)"
    echo
    printf "${BOLD}Do you have authorization to port scan this network? (yes/no): ${NC}"
    read -r RESPONSE
    
    case "$RESPONSE" in
        yes|YES|y|Y)
            log_success "Authorization confirmed - proceeding with port scan"
            return 0
            ;;
        *)
            log_error "Authorization denied or not confirmed"
            echo
            printf "Port scanning has been ${BOLD}DISABLED${NC}.\n"
            echo "To scan, you must:"
            echo "  1. Obtain proper authorization"
            echo "  2. Re-run with --port-scan flag"
            echo "  3. Confirm authorization when prompted"
            echo
            DO_PORT_SCAN=0
            return 1
            ;;
    esac
}

# Leak detection authorization prompt
prompt_leak_scan_authorization() {
    [ "$DO_LEAK_SCAN" -eq 0 ] && return 0
    
    # Skip prompt in non-interactive mode
    if ! is_interactive; then
        log_warning "Running in non-interactive mode - assuming authorization for leak detection"
        return 0
    fi
    
    echo
    printf "${BOLD}${YELLOW}###############################################################################${NC}\n"
    printf "${BOLD}${YELLOW}SECURITY LEAK DETECTION AUTHORIZATION REQUIRED${NC}\n"
    printf "${BOLD}${YELLOW}###############################################################################${NC}\n"
    echo
    printf "You are about to perform ${BOLD}SECURITY LEAK DETECTION${NC} scanning.\n"
    echo
    printf "${BOLD}LEGAL REQUIREMENTS:${NC}\n"
    printf "  * You must have ${BOLD}EXPLICIT WRITTEN AUTHORIZATION${NC} to scan this network\n"
    echo "  * This scan will attempt to:"
    echo "    - Access publicly exposed configuration files"
    echo "    - Check for exposed credentials and API keys"
    echo "    - Grab service banners from open ports"
    echo "    - Identify security misconfigurations"
    echo "  * Unauthorized security scanning may violate computer crime laws"
    echo
    printf "${BOLD}ETHICAL CONSIDERATIONS:${NC}\n"
    printf "  * Tool will ${BOLD}NOT REDACT${NC} exposed credentials in reports\n"
    echo "  * This follows industry standards (Burp Suite, Metasploit, etc.)"
    echo "  * Provides complete evidence for incident response"
    echo "  * YOU are responsible for:"
    echo "    - Handling reports securely"
    echo "    - Redacting before public sharing (if applicable)"
    echo "    - Following responsible disclosure practices"
    echo "    - Notifying affected parties appropriately"
    echo
    printf "${BOLD}SCAN BEHAVIOR:${NC}\n"
    printf "  * Only scans ${BOLD}PUBLIC${NC} endpoints (no authentication bypass)\n"
    echo "  * Attempts to access common exposed files (.env, config, etc.)"
    echo "  * Checks for credential patterns in responses"
    echo "  * Banner grabs from specified ports: $LEAK_PORTS"
    echo
    printf "${BOLD}SCAN DETAILS:${NC}\n"
    echo "  * Target ASN: $ASN"
    echo "  * Scan Mode: $LEAK_MODE"
    echo "  * Ports: $LEAK_PORTS"
    echo "  * Banner Grabbing: $([ "$LEAK_CHECK_BANNERS" -eq 1 ] && echo 'Enabled' || echo 'Disabled')"
    echo
    printf "${BOLD}Do you have authorization to perform leak detection on this network? (yes/no): ${NC}"
    read -r RESPONSE
    
    case "$RESPONSE" in
        yes|YES|y|Y)
            log_success "Authorization confirmed - proceeding with leak detection"
            echo
            printf "${BOLD}${YELLOW}REMINDER:${NC} You are responsible for:\n"
            echo "  * Secure handling of any discovered credentials"
            echo "  * Appropriate notification of findings"
            echo "  * Compliance with disclosure policies"
            sleep 2
            return 0
            ;;
        *)
            log_error "Authorization denied or not confirmed"
            echo
            printf "Leak detection has been ${BOLD}DISABLED${NC}.\n"
            echo "To scan, you must:"
            echo "  1. Obtain proper authorization"
            echo "  2. Re-run with --leak-scan flag"
            echo "  3. Confirm authorization when prompted"
            echo
            DO_LEAK_SCAN=0
            return 1
            ;;
    esac
}

# Call both prompts early in execution (after banner, before scanning)
check_all_authorizations() {
    # Check if any sensitive scans are enabled
    if [ "$DO_PORT_SCAN" -eq 0 ] && [ "$DO_LEAK_SCAN" -eq 0 ]; then
        return 0
    fi
    
    # If running non-interactively, show warning once
    if ! is_interactive; then
        log_warning "Running in NON-INTERACTIVE mode"
        log_warning "Assuming you have AUTHORIZATION for all enabled scans"
        log_warning "User is responsible for legal compliance"
        echo
        sleep 1
        return 0
    fi
    
    # Interactive mode - prompt for each
    prompt_port_scan_authorization
    prompt_leak_scan_authorization
}


# =============================
# Port Scanning Phase
# =============================

# Top port lists (nmap-style - top 200 most common)
get_top_ports() {
    N="$1"
    
    # Top 200 ports (most common first - based on nmap frequency data)
    TOP_PORTS="80,23,443,21,22,25,3389,110,445,139,143,53,135,3306,8080,1723,111,995,993,5900,1025,587,8888,199,1720,465,548,113,81,6001,10000,514,5060,179,1026,2000,8443,8000,32768,554,26,1433,49152,2001,515,8008,49154,1027,5666,646,5000,5631,631,49153,8081,2049,88,79,5800,106,2121,1110,49155,6000,513,990,5357,427,49156,543,544,5101,144,7,389,8009,3128,444,9999,5009,7070,5190,3000,5432,1900,3986,13,1029,9,5051,6646,49157,1028,873,1755,2717,4899,9100,119,37,1000,3001,5001,82,10010,1030,9090,2107,1024,2103,6004,1801,5050,19,8031,1041,255,1049,1048,1053,3703,1056,1065,1064,1054,17,808,3689,1031,1044,1071,5901,100,9102,8010,2869,1039,5120,4001,9000,2105,636,1038,2601,1,7000,1066,1069,625,311,280,254,4000,1993,1761,5003,2002,2005,1998,1032,1050,6112,3690,1521,2161,6002,1080,2401,4045,902,7937,787,1058,2383,32771,1033,1040,1059,50000,5555,10001,1494,593,2301,4,3268,7938,1234,1022,1074,8002,1036,1035,9001,1037,464,497,1935,6666,2003,6543,1352,24,3269,1111,407,500,20,2006,3260,1034,15000,1218,4444,264,33,2004"
    
    # Return first N ports
    echo "$TOP_PORTS" | tr ',' '\n' | head -n "$N" | tr '\n' ',' | sed 's/,$//'
}

# Build port scan target list
build_port_scan_targets() {
    rm -f "$PORT_SCAN_TARGETS"
    
    case "$PORT_SCAN_MODE" in
        ptr)
            if [ -s "$PTR_FILE" ]; then
                cut -d, -f1 "$PTR_FILE" > "$PORT_SCAN_TARGETS"
            fi
            ;;
        gateway)
            while read PREF; do
                case "$PREF" in
                    *.*)
                        BLOCK=$(echo "$PREF" | cut -d/ -f1 | cut -d. -f1-3)
                        echo "$BLOCK.1" >> "$PORT_SCAN_TARGETS"
                        echo "$BLOCK.254" >> "$PORT_SCAN_TARGETS"
                        ;;
                esac
            done < "$PREFIX_FILE"
            ;;
        all)
            while read PREF; do
                case "$PREF" in
                    *.*)
                        BLOCK=$(echo "$PREF" | cut -d/ -f1 | cut -d. -f1-3)
                        for i in $(seq $SWEEP_START $SWEEP_END); do
                            filter_octet "$i" && echo "$BLOCK.$i" >> "$PORT_SCAN_TARGETS"
                        done
                        ;;
                esac
            done < "$PREFIX_FILE"
            ;;
    esac
    
    if [ -s "$PORT_SCAN_TARGETS" ]; then
        sort -u "$PORT_SCAN_TARGETS" -o "$PORT_SCAN_TARGETS"
    fi
}

# Main port scanning phase
run_port_scan_phase() {
    [ "$DO_PORT_SCAN" -eq 0 ] && return
    
    log_header "Port Scanning"
    
    build_port_scan_targets
    
    if [ ! -s "$PORT_SCAN_TARGETS" ]; then
        log_warning "No targets for port scanning"
        return
    fi
    
    # Determine which ports to scan
    if [ "$PORT_SCAN_TOP_PORTS" -gt 0 ]; then
        SCAN_PORTS=$(get_top_ports "$PORT_SCAN_TOP_PORTS")
        log_info "Scanning top $PORT_SCAN_TOP_PORTS ports"
    else
        SCAN_PORTS="$PORT_SCAN_PORTS"
        PORT_COUNT=$(echo "$SCAN_PORTS" | tr ',' '\n' | wc -l)
        log_info "Scanning $PORT_COUNT specified ports"
    fi
    
    TARGET_COUNT=$(wc -l < "$PORT_SCAN_TARGETS")
    log_info "Mode: $PORT_SCAN_MODE"
    log_info "Targets: $TARGET_COUNT"
    log_info "Parallel scans: $PORT_SCAN_PARALLEL"
    log_info "Timeout: ${PORT_SCAN_TIMEOUT}s per port"
    echo
    
    # Initialize CSV
    echo "ip,port,state,protocol" > "$PORT_SCAN_CSV"
    
    # Export variables for parallel execution
    export SCAN_PORTS PORT_SCAN_TIMEOUT PORT_SCAN_CSV
    
    log_info "Scanning (dots = hosts scanned)..."
    
    cat "$PORT_SCAN_TARGETS" | xargs -P "$PORT_SCAN_PARALLEL" -I{} sh -c '
        IP="{}"
        
        for PORT in $(echo "$SCAN_PORTS" | tr "," " "); do
            if timeout "$PORT_SCAN_TIMEOUT" bash -c "echo >/dev/tcp/$IP/$PORT" 2>/dev/null; then
                (
                    flock -x 200
                    echo "$IP,$PORT,open,tcp" >> "$PORT_SCAN_CSV"
                ) 200>"$PORT_SCAN_CSV.lock"
            fi
        done
        
        printf "."
    ' 2>/dev/null
    echo
    echo
    
    log_success "Port scanning complete"
    
    # Generate summary
    generate_port_scan_summary
    
    # If leak detection is enabled and no custom leak ports specified,
    # use discovered open ports
    if [ "$DO_LEAK_SCAN" -eq 1 ]; then
        # Check if user specified custom leak ports
        if echo "$LEAK_PORTS" | grep -q "21,22,23,25,80,110,143,443,3306,5432,6379,8080,9200,27017,3389,5900"; then
            # User is using defaults - check if we found open ports
            if [ -s "$PORT_SCAN_CSV" ] && [ $(wc -l < "$PORT_SCAN_CSV") -gt 1 ]; then
                # Extract unique open ports from scan
                DISCOVERED_PORTS=$(awk -F, 'NR>1 {print $2}' "$PORT_SCAN_CSV" | sort -u | tr '\n' ',' | sed 's/,$//')
                if [ -n "$DISCOVERED_PORTS" ]; then
                    log_info "Auto-configuring leak detection to use discovered open ports"
                    LEAK_PORTS="$DISCOVERED_PORTS"
                    export LEAK_PORTS
                fi
            fi
        fi
    fi
}

# Generate port scan summary
generate_port_scan_summary() {
    [ ! -s "$PORT_SCAN_CSV" ] || [ $(wc -l < "$PORT_SCAN_CSV") -le 1 ] && {
        log_warning "No open ports found"
        return
    }
    
    log_info "Generating port scan summary..."
    
    {
        echo "==================================="
        echo "Port Scan Summary"
        echo "==================================="
        echo
        
        TOTAL_SCANS=$(awk 'NR>1' "$PORT_SCAN_CSV" | wc -l)
        UNIQUE_IPS=$(awk -F, 'NR>1 {print $1}' "$PORT_SCAN_CSV" | sort -u | wc -l)
        UNIQUE_PORTS=$(awk -F, 'NR>1 {print $2}' "$PORT_SCAN_CSV" | sort -u | wc -l)
        
        echo "Open ports found:      $TOTAL_SCANS"
        echo "Hosts with open ports: $UNIQUE_IPS"
        echo "Unique ports open:     $UNIQUE_PORTS"
        echo
        
        echo "Top 10 Open Ports:"
        awk -F, 'NR>1 {count[$2]++} 
                 END {for(port in count) print count[port], port}' "$PORT_SCAN_CSV" | \
            sort -rn | head -10 | awk '{printf "  Port %5s: %3d hosts\n", $2, $1}'
        echo
        
        echo "Hosts with Most Open Ports:"
        awk -F, 'NR>1 {count[$1]++} 
                 END {for(ip in count) print count[ip], ip}' "$PORT_SCAN_CSV" | \
            sort -rn | head -10 | awk '{printf "  %15s: %3d ports\n", $2, $1}'
        echo
        
        echo "Full results in: $PORT_SCAN_CSV"
    } > "$PORT_SCAN_SUMMARY"
    
    cat "$PORT_SCAN_SUMMARY"
    echo
}
# Security Leak Detection Module
# =============================
# Scans for publicly exposed configuration files, credentials, and sensitive data
# LEGAL: Only checks public endpoints, no authentication bypass

# Leak detection variables
DO_LEAK_SCAN=0
LEAK_MODE="ptr"  # ptr|all|gateway
LEAK_PARALLEL=10
LEAK_TIMEOUT=5
LEAK_CHECK_BANNERS=1
LEAK_PORTS="21,22,23,25,80,110,143,443,3306,5432,6379,8080,9200,27017"

# Common leak paths - comprehensive list
LEAK_PATHS_COMMON=".env .git/config .git/HEAD wp-config.php .gitignore"
LEAK_PATHS_BACKUP="backup.sql db_backup.sql dump.sql database.sql backup.zip"
LEAK_PATHS_CONFIG="config.json config.yaml config.yml settings.py settings.json docker-compose.yml"
LEAK_PATHS_LOGS="debug.log error.log laravel.log storage/logs/laravel.log"
LEAK_PATHS_IDE=".idea/workspace.xml .vscode/settings.json .project .classpath"
LEAK_PATHS_ENV=".env.local .env.production .env.development .env.test .env.example .env.backup"
LEAK_PATHS_CREDS="credentials.json secrets.json api-keys.json token.json"
LEAK_PATHS_SERVER="server-status .htaccess .htpasswd phpinfo.php info.php"

# Severity levels for different types of leaks
LEAK_SEVERITY_CRITICAL=".env wp-config.php credentials.json secrets.json backup.sql database.sql"
LEAK_SEVERITY_HIGH=".git/config docker-compose.yml api-keys.json token.json"
LEAK_SEVERITY_MEDIUM="config.json settings.py .env.example debug.log"
LEAK_SEVERITY_LOW=".gitignore .idea/workspace.xml server-status"

# Pattern matching for sensitive data
LEAK_PATTERNS_CRITICAL="password|passwd|pwd|api_key|apikey|secret|token|access_key|private_key"
LEAK_PATTERNS_HIGH="database|db_pass|connection_string|auth|credential"
LEAK_PATTERNS_MEDIUM="smtp|mail_password|session|cookie"

# =============================
# Single IP leak scan
# =============================
scan_ip_for_leaks() {
    IP="$1"
    FINDINGS=0
    CRITICAL_FINDINGS=0
    
    # Combine all leak paths
    ALL_PATHS="$LEAK_PATHS_COMMON $LEAK_PATHS_BACKUP $LEAK_PATHS_CONFIG $LEAK_PATHS_LOGS $LEAK_PATHS_IDE $LEAK_PATHS_ENV $LEAK_PATHS_CREDS $LEAK_PATHS_SERVER"
    
    # Try both HTTP and HTTPS
    for PROTOCOL in http https; do
        for PATH in $ALL_PATHS; do
            URL="${PROTOCOL}://${IP}/${PATH}"
            
            # Check if endpoint is accessible
            RESPONSE=$(curl -o /dev/null -s -w "%{http_code}" --max-time "$LEAK_TIMEOUT" -k "$URL" 2>/dev/null)
            
            # 200 = accessible, 403 = exists but forbidden (still a leak), 401 = auth required (exposed)
            case "$RESPONSE" in
                200|403|401)
                    FINDINGS=$((FINDINGS + 1))
                    
                    # Determine severity
                    SEVERITY="LOW"
                    echo "$LEAK_SEVERITY_CRITICAL" | grep -q "$PATH" && SEVERITY="CRITICAL"
                    echo "$LEAK_SEVERITY_HIGH" | grep -q "$PATH" && SEVERITY="HIGH"
                    echo "$LEAK_SEVERITY_MEDIUM" | grep -q "$PATH" && SEVERITY="MEDIUM"
                    
                    [ "$SEVERITY" = "CRITICAL" ] && CRITICAL_FINDINGS=$((CRITICAL_FINDINGS + 1))
                    
                    # Get content for 200 responses only
                    CONTENT_CHECK=""
                    if [ "$RESPONSE" = "200" ]; then
                        CONTENT=$(curl -s --max-time "$LEAK_TIMEOUT" -k "$URL" 2>/dev/null | head -n 100)
                        
                        # Check for credential patterns (without revealing actual values)
                        if echo "$CONTENT" | grep -Eiq "$LEAK_PATTERNS_CRITICAL"; then
                            CONTENT_CHECK="CREDENTIALS_DETECTED"
                            CRITICAL_FINDINGS=$((CRITICAL_FINDINGS + 1))
                        elif echo "$CONTENT" | grep -Eiq "$LEAK_PATTERNS_HIGH"; then
                            CONTENT_CHECK="SENSITIVE_DATA"
                        elif echo "$CONTENT" | grep -Eiq "$LEAK_PATTERNS_MEDIUM"; then
                            CONTENT_CHECK="CONFIG_DATA"
                        fi
                        
                        # Check content length
                        CONTENT_LEN=$(echo "$CONTENT" | wc -c)
                    else
                        CONTENT_LEN="0"
                    fi
                    
                    # Write to CSV
                    echo "$IP,$URL,$RESPONSE,$SEVERITY,$CONTENT_CHECK,$CONTENT_LEN,$(date '+%Y-%m-%d %H:%M:%S')" >> "$LEAK_CSV"
                    ;;
            esac
        done
    done
    
    # Banner grabbing on common ports (if enabled)
    if [ "$LEAK_CHECK_BANNERS" -eq 1 ]; then
        for PORT in $(echo "$LEAK_PORTS" | tr ',' ' '); do
            # Try to grab banner with timeout
            BANNER=$(timeout "$LEAK_TIMEOUT" sh -c "echo '' | nc -w 2 $IP $PORT 2>/dev/null" | head -n 10 | tr -d '\0')
            
            if [ -n "$BANNER" ]; then
                # Check for sensitive info in banner
                BANNER_ISSUE=""
                if echo "$BANNER" | grep -Eiq "$LEAK_PATTERNS_CRITICAL"; then
                    BANNER_ISSUE="CREDENTIALS_IN_BANNER"
                    CRITICAL_FINDINGS=$((CRITICAL_FINDINGS + 1))
                elif echo "$BANNER" | grep -Eiq "version|server|user|admin"; then
                    BANNER_ISSUE="VERSION_INFO"
                fi
                
                if [ -n "$BANNER_ISSUE" ]; then
                    FINDINGS=$((FINDINGS + 1))
                    BANNER_SAFE=$(echo "$BANNER" | head -n 3 | tr '\n' ' ' | cut -c1-200)
                    echo "$IP,banner://$IP:$PORT,BANNER,$BANNER_ISSUE,$BANNER_SAFE,-,$(date '+%Y-%m-%d %H:%M:%S')" >> "$LEAK_CSV"
                fi
            fi
        done
    fi
    
    # Return counts
    echo "$FINDINGS,$CRITICAL_FINDINGS"
}

# =============================
# Build leak scan target list
# =============================
build_leak_targets() {
    rm -f "$LEAK_TARGETS"
    
    case "$LEAK_MODE" in
        ptr)
            if [ -s "$PTR_FILE" ]; then
                cut -d, -f1 "$PTR_FILE" > "$LEAK_TARGETS"
            fi
            ;;
        gateway)
            while read PREF; do
                case "$PREF" in
                    *.*)
                        BLOCK=$(echo "$PREF" | cut -d/ -f1 | cut -d. -f1-3)
                        echo "$BLOCK.1" >> "$LEAK_TARGETS"
                        echo "$BLOCK.254" >> "$LEAK_TARGETS"
                        ;;
                esac
            done < "$PREFIX_FILE"
            ;;
        all)
            while read PREF; do
                case "$PREF" in
                    *.*)
                        BLOCK=$(echo "$PREF" | cut -d/ -f1 | cut -d. -f1-3)
                        for i in $(seq $SWEEP_START $SWEEP_END); do
                            filter_octet "$i" && echo "$BLOCK.$i" >> "$LEAK_TARGETS"
                        done
                        ;;
                esac
            done < "$PREFIX_FILE"
            ;;
    esac
    
    if [ -s "$LEAK_TARGETS" ]; then
        sort -u "$LEAK_TARGETS" -o "$LEAK_TARGETS"
    fi
}

# =============================
# Main leak detection phase
# =============================
run_leak_detection_phase() {
    [ "$DO_LEAK_SCAN" -eq 0 ] && return
    
    log_header "Security Leak Detection"
    
    build_leak_targets
    
    if [ ! -s "$LEAK_TARGETS" ]; then
        log_warning "No targets for leak detection (empty target list)"
        return
    fi
    
    TARGET_COUNT=$(wc -l < "$LEAK_TARGETS")
    log_info "Mode: $LEAK_MODE"
    log_info "Targets: $TARGET_COUNT"
    log_info "Timeout: ${LEAK_TIMEOUT}s per request"
    log_info "Ports: $LEAK_PORTS"
    log_info "Banner scanning: $([ "$LEAK_CHECK_BANNERS" -eq 1 ] && echo 'Enabled' || echo 'Disabled')"
    echo
    

    # Initialize CSV
    echo "ip,url,status_code,severity,content_type,size,timestamp" > "$LEAK_CSV"
    
    # Export variables for parallel execution
    export LEAK_TIMEOUT LEAK_CHECK_BANNERS LEAK_PORTS LEAK_CSV
    export LEAK_PATHS_COMMON LEAK_PATHS_BACKUP LEAK_PATHS_CONFIG LEAK_PATHS_LOGS
    export LEAK_PATHS_IDE LEAK_PATHS_ENV LEAK_PATHS_CREDS LEAK_PATHS_SERVER
    export LEAK_SEVERITY_CRITICAL LEAK_SEVERITY_HIGH LEAK_SEVERITY_MEDIUM LEAK_SEVERITY_LOW
    export LEAK_PATTERNS_CRITICAL LEAK_PATTERNS_HIGH LEAK_PATTERNS_MEDIUM
    
    if [ "$LEAK_PARALLEL" -le 1 ]; then
        # Sequential scanning
        COUNT=0
        TOTAL_FINDINGS=0
        TOTAL_CRITICAL=0
        
        while read IP; do
            COUNT=$((COUNT + 1))
            printf "\r[*] Scanning: $COUNT/$TARGET_COUNT - $IP          "
            
            RESULT=$(scan_ip_for_leaks "$IP")
            FINDINGS=$(echo "$RESULT" | cut -d, -f1)
            CRITICAL=$(echo "$RESULT" | cut -d, -f2)
            
            TOTAL_FINDINGS=$((TOTAL_FINDINGS + FINDINGS))
            TOTAL_CRITICAL=$((TOTAL_CRITICAL + CRITICAL))
        done < "$LEAK_TARGETS"
        echo
    else
        # Parallel scanning
        log_info "Scanning in parallel (dots = progress)..."
        
        cat "$LEAK_TARGETS" | xargs -P "$LEAK_PARALLEL" -I{} sh -c '
            IP="{}"
            
            # Full scan function inlined for parallel execution
            FINDINGS=0
            CRITICAL_FINDINGS=0
            
            ALL_PATHS="'"$LEAK_PATHS_COMMON $LEAK_PATHS_BACKUP $LEAK_PATHS_CONFIG $LEAK_PATHS_LOGS $LEAK_PATHS_IDE $LEAK_PATHS_ENV $LEAK_PATHS_CREDS $LEAK_PATHS_SERVER"'"
            
            for PROTOCOL in http https; do
                for PATH in $ALL_PATHS; do
                    URL="${PROTOCOL}://${IP}/${PATH}"
                    RESPONSE=$(curl -o /dev/null -s -w "%{http_code}" --max-time "'"$LEAK_TIMEOUT"'" -k "$URL" 2>/dev/null)
                    
                    case "$RESPONSE" in
                        200|403|401)
                            FINDINGS=$((FINDINGS + 1))
                            
                            SEVERITY="LOW"
                            echo "'"$LEAK_SEVERITY_CRITICAL"'" | grep -q "$PATH" && SEVERITY="CRITICAL"
                            echo "'"$LEAK_SEVERITY_HIGH"'" | grep -q "$PATH" && SEVERITY="HIGH"
                            echo "'"$LEAK_SEVERITY_MEDIUM"'" | grep -q "$PATH" && SEVERITY="MEDIUM"
                            
                            [ "$SEVERITY" = "CRITICAL" ] && CRITICAL_FINDINGS=$((CRITICAL_FINDINGS + 1))
                            
                            CONTENT_CHECK=""
                            CONTENT_LEN="0"
                            if [ "$RESPONSE" = "200" ]; then
                                CONTENT=$(curl -s --max-time "'"$LEAK_TIMEOUT"'" -k "$URL" 2>/dev/null | head -n 100)
                                
                                if echo "$CONTENT" | grep -Eiq "'"$LEAK_PATTERNS_CRITICAL"'"; then
                                    CONTENT_CHECK="CREDENTIALS_DETECTED"
                                    CRITICAL_FINDINGS=$((CRITICAL_FINDINGS + 1))
                                elif echo "$CONTENT" | grep -Eiq "'"$LEAK_PATTERNS_HIGH"'"; then
                                    CONTENT_CHECK="SENSITIVE_DATA"
                                elif echo "$CONTENT" | grep -Eiq "'"$LEAK_PATTERNS_MEDIUM"'"; then
                                    CONTENT_CHECK="CONFIG_DATA"
                                fi
                                
                                CONTENT_LEN=$(echo "$CONTENT" | wc -c)
                            fi
                            
                            (
                                flock -x 200
                                echo "$IP,$URL,$RESPONSE,$SEVERITY,$CONTENT_CHECK,$CONTENT_LEN,$(date "+%Y-%m-%d %H:%M:%S")" >> "'"$LEAK_CSV"'"
                            ) 200>"'"$LEAK_CSV"'.lock"
                            ;;
                    esac
                done
            done
            
            printf "."
        ' 2>/dev/null
        echo
        echo
    fi
    
    log_success "Leak detection complete"
    
    # Generate summary
    generate_leak_summary
}

# =============================
# Generate leak detection summary
# =============================
generate_leak_summary() {
    [ ! -s "$LEAK_CSV" ] && return
    
    log_info "Generating leak detection summary..."
    
    LEAK_SUMMARY="$OUTDIR/leak_summary.txt"
    
    TOTAL=$(awk 'NR>1' "$LEAK_CSV" | wc -l)
    CRITICAL=$(awk -F, 'NR>1 && $4=="CRITICAL"' "$LEAK_CSV" | wc -l)
    HIGH=$(awk -F, 'NR>1 && $4=="HIGH"' "$LEAK_CSV" | wc -l)
    MEDIUM=$(awk -F, 'NR>1 && $4=="MEDIUM"' "$LEAK_CSV" | wc -l)
    LOW=$(awk -F, 'NR>1 && $4=="LOW"' "$LEAK_CSV" | wc -l)
    
    CREDS=$(awk -F, 'NR>1 && $5=="CREDENTIALS_DETECTED"' "$LEAK_CSV" | wc -l)
    SENSITIVE=$(awk -F, 'NR>1 && $5=="SENSITIVE_DATA"' "$LEAK_CSV" | wc -l)
    
    {
        echo "==================================="
        echo "Security Leak Detection Summary"
        echo "==================================="
        echo
        echo "Total exposures found:    $TOTAL"
        echo
        echo "By Severity:"
        echo "  CRITICAL:               $CRITICAL"
        echo "  HIGH:                   $HIGH"
        echo "  MEDIUM:                 $MEDIUM"
        echo "  LOW:                    $LOW"
        echo
        echo "Content Analysis:"
        echo "  Credentials detected:   $CREDS"
        echo "  Sensitive data:         $SENSITIVE"
        echo
        
        if [ "$CRITICAL" -gt 0 ]; then
            echo "==================================="
            echo "CRITICAL FINDINGS (Top 10):"
            echo "==================================="
            awk -F, 'NR>1 && $4=="CRITICAL" {print "  " $2 " [" $5 "]"}' "$LEAK_CSV" | head -10
            echo
        fi
        
        if [ "$CREDS" -gt 0 ]; then
            echo "==================================="
            echo "CREDENTIAL EXPOSURES (Top 10):"
            echo "==================================="
            awk -F, 'NR>1 && $5=="CREDENTIALS_DETECTED" {print "  " $1 " - " $2}' "$LEAK_CSV" | head -10
            echo
        fi
        
        echo "==================================="
        echo "Top Exposed Paths:"
        echo "==================================="
        awk -F, 'NR>1 {
            split($2, parts, "/")
            path = parts[length(parts)]
            count[path]++
        }
        END {
            for (p in count) print count[p], p
        }' "$LEAK_CSV" | sort -rn | head -10 | awk '{printf "  %3d - %s\n", $1, $2}'
        echo
        
        echo "==================================="
        echo "Recommendations:"
        echo "==================================="
        if [ "$CRITICAL" -gt 0 ]; then
            echo "  ÃƒÆ’Ã‚Â°Ãƒâ€¦Ã‚Â¸ÃƒÂ¢Ã¢â€šÂ¬Ã‚ÂÃƒâ€šÃ‚Â´ URGENT: $CRITICAL critical exposures require immediate remediation"
        fi
        if [ "$CREDS" -gt 0 ]; then
            echo "  ÃƒÆ’Ã‚Â°Ãƒâ€¦Ã‚Â¸ÃƒÂ¢Ã¢â€šÂ¬Ã‚ÂÃƒâ€šÃ‚Â´ URGENT: Rotate all exposed credentials immediately"
        fi
        if [ "$HIGH" -gt 0 ]; then
            echo "  ÃƒÆ’Ã‚Â¢Ãƒâ€¦Ã‚Â¡Ãƒâ€šÃ‚Â ÃƒÆ’Ã‚Â¯Ãƒâ€šÃ‚Â¸Ãƒâ€šÃ‚Â  Address $HIGH high-severity exposures within 24-48 hours"
        fi
        echo "  ÃƒÆ’Ã‚Â¢Ãƒâ€¦Ã¢â‚¬Å“ÃƒÂ¢Ã¢â€šÂ¬Ã…â€œ  Review all findings in: $LEAK_CSV"
        echo "  ÃƒÆ’Ã‚Â¢Ãƒâ€¦Ã¢â‚¬Å“ÃƒÂ¢Ã¢â€šÂ¬Ã…â€œ  Add .gitignore rules to prevent config file commits"
        echo "  ÃƒÆ’Ã‚Â¢Ãƒâ€¦Ã¢â‚¬Å“ÃƒÂ¢Ã¢â€šÂ¬Ã…â€œ  Implement proper access controls on web servers"
        echo "  ÃƒÆ’Ã‚Â¢Ãƒâ€¦Ã¢â‚¬Å“ÃƒÂ¢Ã¢â€šÂ¬Ã…â€œ  Remove debug/development files from production"
        echo
    } | tee "$LEAK_SUMMARY"
    echo
}

# =============================
# Sensitive Data Sanitization Module
# =============================
# Implements compliance controls for credential/sensitive data handling

# Sanitize URL - remove query params and potential sensitive data
sanitize_url() {
    URL="$1"
    # Remove query parameters (everything after ?)
    BASE_URL=$(echo "$URL" | cut -d'?' -f1)
    # Remove fragments (everything after #)
    BASE_URL=$(echo "$BASE_URL" | cut -d'#' -f1)
    echo "$BASE_URL"
}

# Generate hash of sensitive value (SHA-256)
hash_sensitive_value() {
    VALUE="$1"
    # Use sha256sum if available, fallback to md5
    if command -v sha256sum >/dev/null 2>&1; then
        echo "$VALUE" | sha256sum | cut -d' ' -f1
    else
        echo "$VALUE" | md5sum | cut -d' ' -f1
    fi
}

# Check if full indicator export is allowed
check_export_authorization() {
    [ "$EXPORT_FULL_INDICATORS" -eq 0 ] && return 1
    return 0
}

# Prompt for full indicator export authorization
prompt_full_indicator_export() {
    [ "$EXPORT_FULL_INDICATORS" -eq 0 ] && return 0
    
    # Skip prompt in non-interactive mode or if auto-confirm is set
    if ! is_interactive || [ "$AUTO_CONFIRM" -eq 1 ]; then
        log_warning "Full indicator export enabled in non-interactive mode"
        log_warning "User is responsible for downstream data handling"
        return 0
    fi
    
    echo
    printf "${BOLD}${YELLOW}###############################################################################${NC}\n"
    printf "${BOLD}${YELLOW}FULL INDICATOR EXPORT AUTHORIZATION${NC}\n"
    printf "${BOLD}${YELLOW}###############################################################################${NC}\n"
    echo
    printf "You have enabled ${BOLD}--export-full-indicators${NC}\n"
    echo
    printf "${BOLD}LEGAL/COMPLIANCE NOTICE:${NC}\n"
    echo "  * Full indicator export transmits complete security artifacts"
    echo "  * This includes: full URLs (with query params), detailed findings"
    echo "  * Credentials: HASHED by default (SHA-256)"
    echo "  * Raw credentials require separate --export-raw-credentials flag"
    echo
    printf "${BOLD}YOUR RESPONSIBILITIES:${NC}\n"
    echo "  * Ensure appropriate access controls in destination systems (SIEM/database)"
    echo "  * Implement secure storage and transmission"
    echo "  * Comply with applicable data protection regulations"
    echo "  * Configure retention policies in downstream systems"
    echo
    printf "${BOLD}DATA CLASSIFICATION:${NC}\n"
    echo "  * Exported artifacts: Customer-directed security processing"
    echo "  * ASNSPY does not retain exported data beyond scan directory"
    echo "  * Default retention: $EXPORT_RETENTION_DAYS days (configurable)"
    echo
    printf "${BOLD}ALTERNATIVE:${NC}\n"
    echo "  * Use default sanitized export (removes query params, hashes indicators)"
    echo "  * Provides security context without exposing sensitive details"
    echo
    printf "${BOLD}Do you acknowledge responsibility for downstream data handling? (yes/no): ${NC}"
    read -r RESPONSE
    
    case "$RESPONSE" in
        yes|YES|y|Y)
            log_success "Authorization confirmed - full indicator export enabled"
            echo
            printf "${BOLD}${YELLOW}REMINDER:${NC} Configure appropriate controls in your SIEM/database\n"
            sleep 2
            return 0
            ;;
        *)
            log_error "Authorization not confirmed"
            echo
            printf "Full indicator export has been ${BOLD}DISABLED${NC}.\n"
            echo "Scan will use sanitized export (recommended)."
            echo
            EXPORT_FULL_INDICATORS=0
            return 1
            ;;
    esac
}

# Prompt for raw credential export authorization (separate and explicit)
prompt_raw_credential_export() {
    [ "$EXPORT_RAW_CREDENTIALS" -eq 0 ] && return 0
    
    # Skip prompt in non-interactive mode or if auto-confirm is set
    if ! is_interactive || [ "$AUTO_CONFIRM" -eq 1 ]; then
        log_warning "Raw credential export enabled in non-interactive mode"
        log_warning "CRITICAL: User is responsible for secure handling"
        return 0
    fi
    
    echo
    printf "${BOLD}${RED}###############################################################################${NC}\n"
    printf "${BOLD}${RED}RAW CREDENTIAL EXPORT - EXPLICIT AUTHORIZATION REQUIRED${NC}\n"
    printf "${BOLD}${RED}###############################################################################${NC}\n"
    echo
    printf "${BOLD}${RED}WARNING: You have enabled --export-raw-credentials${NC}\n"
    echo
    printf "${BOLD}CRITICAL SECURITY NOTICE:${NC}\n"
    echo "  * Raw credentials will be exported AS-FOUND (NOT hashed)"
    echo "  * This includes: passwords, API keys, tokens, secrets"
    echo "  * Exported data will contain PLAINTEXT sensitive information"
    echo "  * This mode is ONLY for controlled, isolated analysis environments"
    echo
    printf "${BOLD}LEGAL/COMPLIANCE IMPACT:${NC}\n"
    echo "  * May violate data protection regulations if mishandled"
    echo "  * Requires strict access controls and audit logging"
    echo "  * Must implement encryption at rest and in transit"
    echo "  * Requires data classification as 'Highly Confidential'"
    echo "  * May require breach notification if exposed"
    echo
    printf "${BOLD}YOUR EXPLICIT RESPONSIBILITIES:${NC}\n"
    echo "  * Encrypt destination storage (SIEM/database)"
    echo "  * Implement strict RBAC (role-based access control)"
    echo "  * Enable audit logging of all access"
    echo "  * Automatic expiration/rotation of exported data"
    echo "  * Incident response plan for potential exposure"
    echo "  * Compliance with GDPR/CCPA/SOC2/ISO27001 requirements"
    echo
    printf "${BOLD}RECOMMENDED ALTERNATIVE:${NC}\n"
    echo "  * Use default mode: Credentials are SHA-256 hashed"
    echo "  * Provides security context without exposure risk"
    echo "  * Meets compliance requirements for most use cases"
    echo
    printf "${BOLD}${RED}Do you explicitly authorize RAW credential export? (type 'YES' in all caps): ${NC}"
    read -r RESPONSE
    
    if [ "$RESPONSE" = "YES" ]; then
        log_warning "RAW CREDENTIAL EXPORT AUTHORIZED"
        echo
        printf "${BOLD}${RED}CRITICAL REMINDER:${NC} Secure all downstream systems NOW\n"
        sleep 3
        return 0
    else
        log_error "Raw credential export NOT authorized (must type 'YES' exactly)"
        echo
        printf "Raw credential export has been ${BOLD}DISABLED${NC}.\n"
        echo "Credentials will be SHA-256 hashed (secure default)."
        echo
        EXPORT_RAW_CREDENTIALS=0
        return 1
    fi
}

# Enhanced SIEM send for leak with sanitization
siem_send_leak_sanitized() {
    IP="$1"
    URL="$2"
    LEAK_TYPE="$3"
    SEVERITY="$4"
    
    # Check export mode
    if check_export_authorization; then
        # Full mode - send URL as-is (but document it)
        EXPORT_URL="$URL"
        SANITIZED="false"
    else
        # Sanitized mode - clean URL
        EXPORT_URL=$(sanitize_url "$URL")
        SANITIZED="true"
    fi
    
    # Generate exposure hash
    EXPOSURE_HASH=$(echo "${IP}${EXPORT_URL}${LEAK_TYPE}" | hash_sensitive_value)
    
    DATA=$(cat << LEAKDATA
{
  "finding_type": "credential_leak",
  "ip": "$IP",
  "url": "$(siem_json_escape "$EXPORT_URL")",
  "leak_type": "$LEAK_TYPE",
  "exposure_hash": "$EXPOSURE_HASH",
  "sanitized": $SANITIZED,
  "note": "Raw credentials never exported per security policy"
}
LEAKDATA
)
    
    send_to_siem "credential_leak" "$SCAN_HASH" "$ASN" "$SEVERITY" "$DATA" "$IP" "" "Credential leak detected"
}

# Cleanup old scans based on retention policy
cleanup_old_scans() {
    [ -z "$EXPORT_RETENTION_DAYS" ] || [ "$EXPORT_RETENTION_DAYS" -eq 0 ] && return
    
    log_info "Checking for scans older than $EXPORT_RETENTION_DAYS days..."
    
    CUTOFF_DATE=$(date -d "$EXPORT_RETENTION_DAYS days ago" +%Y-%m-%d 2>/dev/null || date -v-${EXPORT_RETENTION_DAYS}d +%Y-%m-%d 2>/dev/null)
    
    if [ -z "$CUTOFF_DATE" ]; then
        log_warning "Unable to calculate cutoff date for retention cleanup"
        return
    fi
    
    DELETED=0
    find "$SCANS_DIR" -maxdepth 1 -type d -name "${ASN}_*" 2>/dev/null | while read SCAN_DIR; do
        if [ -f "$SCAN_DIR/scan_metadata.txt" ]; then
            SCAN_DATE=$(grep "Start Time:" "$SCAN_DIR/scan_metadata.txt" 2>/dev/null | cut -d: -f2- | xargs | cut -d' ' -f1)
            
            if [ -n "$SCAN_DATE" ] && [ "$SCAN_DATE" \< "$CUTOFF_DATE" ]; then
                log_info "Removing old scan: $SCAN_DIR (from $SCAN_DATE)"
                rm -rf "$SCAN_DIR"
                DELETED=$((DELETED + 1))
            fi
        fi
    done
    
    [ "$DELETED" -gt 0 ] && log_success "Removed $DELETED old scan(s)"
}

# Enhanced JSON export for leak findings with sanitization
export_leak_findings_json() {
    [ ! -f "$LEAK_CSV" ] || [ $(wc -l < "$LEAK_CSV") -le 1 ] && return
    
    log_info "Exporting leak findings to JSON..."
    
    # Determine export mode
    if [ "$EXPORT_RAW_CREDENTIALS" -eq 1 ]; then
        EXPORT_MODE="RAW_CREDENTIALS"
        CRED_HANDLING="raw"
        log_warning "Using RAW CREDENTIALS export mode (sensitive data unmasked)"
    elif check_export_authorization; then
        EXPORT_MODE="FULL_INDICATORS"
        CRED_HANDLING="hashed"
        log_debug "Using FULL INDICATORS export mode (credentials hashed)"
    else
        EXPORT_MODE="SANITIZED"
        CRED_HANDLING="hashed"
        log_debug "Using SANITIZED export mode (default, credentials hashed)"
    fi
    
    {
        echo "{"
        echo "  \"asn\": \"$ASN\","
        echo "  \"timestamp\": \"$(date -u '+%Y-%m-%dT%H:%M:%SZ')\","
        echo "  \"export_mode\": \"$EXPORT_MODE\","
        echo "  \"compliance\": {"
        echo "    \"credential_handling\": \"$CRED_HANDLING\","
        echo "    \"url_sanitization\": $([ "$EXPORT_MODE" = "SANITIZED" ] && echo "true" || echo "false"),"
        echo "    \"retention_policy_days\": $EXPORT_RETENTION_DAYS,"
        echo "    \"data_classification\": \"$([ "$EXPORT_MODE" = "RAW_CREDENTIALS" ] && echo "Highly Confidential" || echo "Customer-directed security processing")\","
        echo "    \"downstream_requirements\": \"$([ "$EXPORT_MODE" = "RAW_CREDENTIALS" ] && echo "Encryption required, strict RBAC, audit logging mandatory" || echo "Standard security controls")\""
        echo "  },"
        echo "  \"leak_findings\": ["
        
        awk -F, 'NR>1 {
            if (NR>2) printf ",\n"
            printf "    {\n"
            printf "      \"ip\": \"%s\",\n", $1
            
            # URL handling based on mode
            url = $2
            if ("'"$EXPORT_MODE"'" == "SANITIZED") {
                # Remove query params for sanitized mode
                gsub(/\?.*$/, "", url)
                gsub(/#.*$/, "", url)
            }
            printf "      \"url\": \"%s\",\n", url
            
            printf "      \"status_code\": \"%s\",\n", $3
            printf "      \"severity\": \"%s\",\n", $4
            printf "      \"content_type\": \"%s\",\n", $5
            printf "      \"size\": %s,\n", $6
            printf "      \"timestamp\": \"%s\",\n", $7
            
            # Generate exposure hash for correlation
            hash_input = $1 url $5
            hash_cmd = "echo \"" hash_input "\" | sha256sum 2>/dev/null || echo \"" hash_input "\" | md5sum 2>/dev/null"
            hash_cmd | getline exposure_hash
            close(hash_cmd)
            split(exposure_hash, hash_parts, " ")
            printf "      \"exposure_hash\": \"%s\"\n", hash_parts[1]
            
            printf "    }"
        }' "$LEAK_CSV"
        
        echo
        echo "  ],"
        echo "  \"summary\": {"
        TOTAL=$(awk 'NR>1' "$LEAK_CSV" | wc -l)
        CRITICAL=$(awk -F, 'NR>1 && $4=="CRITICAL"' "$LEAK_CSV" | wc -l)
        HIGH=$(awk -F, 'NR>1 && $4=="HIGH"' "$LEAK_CSV" | wc -l)
        echo "    \"total_findings\": $TOTAL,"
        echo "    \"critical\": $CRITICAL,"
        echo "    \"high\": $HIGH"
        echo "  }"
        echo "}"
    } > "$JSON_DIR/leak_findings.json"
    
    log_success "Leak findings exported (mode: $EXPORT_MODE)"
}

generate_example_config() {
    cat > ".asnspyrc.example" << 'CONFIGEOF'
# ASNSPY Configuration File
# Place in: ~/.asnspyrc or .asnspyrc (current directory)

PARALLEL=50
TRACE_PARALLEL=10
TLS_PARALLEL=20
VERSION_PARALLEL=20

DO_TRACE=1
DO_TLS=1
DO_VERSION=1
DO_CVE=1
DO_CLOUD_DETECT=1
DO_HTTP_SECURITY=1
DO_JSON=1

MODE_INTERNET_ONLY=1
CVE_MIN_SEVERITY=MEDIUM
CONFIGEOF
    echo "[+] Generated: .asnspyrc.example"
    log_info "Copy to ~/.asnspyrc to use"
}

# =============================
# Build version detection target list
# =============================
build_version_targets() {
    rm -f "$VERSION_TARGETS"
    
    case "$VERSION_MODE" in
        ptr)
            if [ -s "$PTR_FILE" ]; then
                cut -d, -f1 "$PTR_FILE" > "$VERSION_TARGETS"
            fi
            ;;
        gateway)
            while read PREF; do
                case "$PREF" in
                    *.*)
                        BLOCK=$(echo "$PREF" | cut -d/ -f1 | cut -d. -f1-3)
                        echo "$BLOCK.1" >> "$VERSION_TARGETS"
                        echo "$BLOCK.254" >> "$VERSION_TARGETS"
                        ;;
                esac
            done < "$PREFIX_FILE"
            ;;
        all)
            while read PREF; do
                case "$PREF" in
                    *.*)
                        BLOCK=$(echo "$PREF" | cut -d/ -f1 | cut -d. -f1-3)
                        for i in $(seq $SWEEP_START $SWEEP_END); do
                            filter_octet "$i" && echo "$BLOCK.$i" >> "$VERSION_TARGETS"
                        done
                        ;;
                esac
            done < "$PREFIX_FILE"
            ;;
    esac
    
    if [ -s "$VERSION_TARGETS" ]; then
        sort -u "$VERSION_TARGETS" -o "$VERSION_TARGETS"
    fi
}

# =============================
# Detect server versions on single IP/port
# =============================
detect_server_version() {
    IP="$1"
    PORT="$2"
    TIMEOUT="$3"
    
    # Try HTTP request to get headers
    if [ "$PORT" = "443" ] || [ "$PORT" = "8443" ]; then
        PROTO="https"
    else
        PROTO="http"
    fi
    
    # Get headers with curl
    HEADERS=$(curl -sI --max-time "$TIMEOUT" --connect-timeout "$TIMEOUT" "${PROTO}://${IP}:${PORT}/" 2>/dev/null)
    
    if [ -z "$HEADERS" ]; then
        echo "$IP,$PORT,no_response,-,-,-,-"
        return
    fi
    
    # Extract server header
    SERVER=$(echo "$HEADERS" | grep -i "^Server:" | sed 's/^[Ss]erver: *//;s/\r$//' | head -1)
    [ -z "$SERVER" ] && SERVER="-"
    
    # Extract X-Powered-By
    POWERED_BY=$(echo "$HEADERS" | grep -i "^X-Powered-By:" | sed 's/^[Xx]-[Pp]owered-[Bb]y: *//;s/\r$//' | head -1)
    [ -z "$POWERED_BY" ] && POWERED_BY="-"
    
    # Extract other version headers
    ASPNET=$(echo "$HEADERS" | grep -i "^X-AspNet-Version:" | sed 's/^[Xx]-[Aa]sp[Nn]et-[Vv]ersion: *//;s/\r$//' | head -1)
    [ -z "$ASPNET" ] && ASPNET="-"
    
    # Parse server string to extract product and version
    PRODUCT=$(echo "$SERVER" | awk '{print $1}' | cut -d/ -f1)
    VERSION=$(echo "$SERVER" | awk '{print $1}' | cut -d/ -f2)
    [ -z "$PRODUCT" ] && PRODUCT="-"
    [ -z "$VERSION" ] && VERSION="-"
    
    # Output CSV line
    echo "$IP,$PORT,success,$PRODUCT,$VERSION,$POWERED_BY,$ASPNET"
}

# =============================
# Version detection phase
# =============================
run_version_phase() {
    [ "$DO_VERSION" -eq 0 ] && return
    
    
    log_header "Server Version Detection"
    
    build_version_targets
    
    if [ ! -s "$VERSION_TARGETS" ]; then
        log_warning "No targets for version detection"
        return
    fi
    
    TARGET_COUNT=$(wc -l < "$VERSION_TARGETS")
    log_info "Version detection mode: $VERSION_MODE"
    log_info "Targets to scan: $TARGET_COUNT"
    log_info "Ports to check: $VERSION_PORTS"
    log_info "Timeout: ${VERSION_TIMEOUT}s"
    log_info "Parallel: $VERSION_PARALLEL"
    echo
    
    # Initialize CSV
    echo "ip,port,status,product,version,powered_by,aspnet_version" > "$VERSION_CSV"
    
    # Scan each target on each port
    COUNT=0
    PORT_COUNT=$(echo "$VERSION_PORTS" | tr ',' '\n' | wc -l)
    TOTAL=$((TARGET_COUNT * PORT_COUNT))
    
    while read IP; do
        for PORT in $(echo "$VERSION_PORTS" | tr ',' ' '); do
            COUNT=$((COUNT + 1))
            printf "\r[*] Version scan: %d/%d - %s:%s          " "$COUNT" "$TOTAL" "$IP" "$PORT"
            detect_server_version "$IP" "$PORT" "$VERSION_TIMEOUT" >> "$VERSION_CSV"
        done
    done < "$VERSION_TARGETS"
    echo
    
    echo "[+] Version detection complete"
    generate_version_summary
}

# =============================
# Generate version summary
# =============================
generate_version_summary() {
    [ ! -s "$VERSION_CSV" ] || [ $(wc -l < "$VERSION_CSV") -le 1 ] && return
    
    log_info "Generating version summary..."
    
    {
        echo "==================================="
        echo "Server Version Detection Summary"
        echo "==================================="
        echo
        
        TOTAL=$(awk 'NR>1' "$VERSION_CSV" | wc -l)
        SUCCESS=$(awk -F, 'NR>1 && $3=="success"' "$VERSION_CSV" | wc -l)
        NO_RESPONSE=$(awk -F, 'NR>1 && $3=="no_response"' "$VERSION_CSV" | wc -l)
        
        echo "Total scans:        $TOTAL"
        echo "Successful:         $SUCCESS"
        echo "No response:        $NO_RESPONSE"
        echo
        
        echo "Detected Server Products:"
        awk -F, 'NR>1 && $4!="-" {count[$4]++} 
                 END {for(prod in count) print count[prod], prod}' "$VERSION_CSV" | \
            sort -rn | head -10 | awk '{printf "  %3d - %s\n", $1, $2}'
        echo
        
        echo "Server Versions Found:"
        awk -F, 'NR>1 && $4!="-" && $5!="-" {print $4"/"$5}' "$VERSION_CSV" | \
            sort -u | head -20
        echo
    } > "$VERSION_SUMMARY"
    
    cat "$VERSION_SUMMARY"
}

# =============================
# Query NVD (NIST) for CVEs
# =============================
query_nvd_api() {
    PRODUCT="$1"
    VERSION="$2"
    
    # NVD API v2.0
    QUERY="${PRODUCT}"
    if [ "$VERSION" != "-" ]; then
        QUERY="${QUERY} ${VERSION}"
    fi
    
    URL="https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=$(echo "$QUERY" | sed 's/ /%20/g')"
    
    RESULT=$(curl -s --max-time "$CVE_TIMEOUT" "$URL" 2>/dev/null)
    
    if [ -z "$RESULT" ]; then
        return 1
    fi
    
    # Parse results
    echo "$RESULT" | jq -r '.vulnerabilities[]? | .cve | "\(.id),\(.metrics.cvssMetricV31[0].cvssData.baseSeverity // .metrics.cvssMetricV2[0].baseSeverity // "UNKNOWN"),\(.descriptions[0].value)"' 2>/dev/null
}

# =============================
# Query Vulners.com for CVEs
# =============================
query_vulners_api() {
    PRODUCT="$1"
    VERSION="$2"
    
    QUERY="${PRODUCT}"
    if [ "$VERSION" != "-" ]; then
        QUERY="${QUERY} ${VERSION}"
    fi
    
    URL="https://vulners.com/api/v3/search/lucene/?query=$(echo "$QUERY" | sed 's/ /%20/g')"
    
    RESULT=$(curl -s --max-time "$CVE_TIMEOUT" "$URL" 2>/dev/null)
    
    if [ -z "$RESULT" ]; then
        return 1
    fi
    
    # Parse results
    echo "$RESULT" | jq -r '.data.search[]? | select(.type == "cve") | "\(.id),\(.cvss.score // "N/A"),\(.description)"' 2>/dev/null
}

# =============================
# Lookup CVEs for a product/version
# =============================
lookup_cve() {
    IP="$1"
    PORT="$2"
    PRODUCT="$3"
    VERSION="$4"
    
    # Skip if product is unknown
    if [ "$PRODUCT" = "-" ]; then
        return
    fi
    
    # Skip generic/unhelpful product names
    case "$PRODUCT" in
        cloudflare|envoy|unknown|-)
            # These are too generic or won't have CVEs
            return
            ;;
    esac
    
    # Skip if version is same as product (malformed data)
    if [ "$VERSION" = "$PRODUCT" ]; then
        return
    fi
    
    # Try NVD first with timeout wrapper
    if [ "$CVE_API" = "nvd" ] || [ "$CVE_API" = "all" ]; then
        CVES=$(timeout 15 sh -c "$(cat << 'INNER_EOF'
query_nvd_api() {
    PRODUCT="$1"
    VERSION="$2"
    QUERY="${PRODUCT}"
    if [ "$VERSION" != "-" ]; then
        QUERY="${QUERY} ${VERSION}"
    fi
    URL="https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=$(echo "$QUERY" | sed 's/ /%20/g')"
    RESULT=$(curl -s --max-time 10 "$URL" 2>/dev/null)
    if [ -z "$RESULT" ]; then
        return 1
    fi
    echo "$RESULT" | jq -r '.vulnerabilities[]? | .cve | "\(.id),\(.metrics.cvssMetricV31[0].cvssData.baseSeverity // .metrics.cvssMetricV2[0].baseSeverity // "UNKNOWN"),\(.descriptions[0].value)"' 2>/dev/null
}
query_nvd_api "$1" "$2"
INNER_EOF
)" "$PRODUCT" "$VERSION" 2>/dev/null)
        
        if [ -n "$CVES" ]; then
            echo "$CVES" | while IFS=',' read CVE_ID SEVERITY DESCRIPTION; do
                # Filter by severity
                case "$CVE_MIN_SEVERITY" in
                    CRITICAL)
                        echo "$SEVERITY" | grep -q "CRITICAL" || continue
                        ;;
                    HIGH)
                        echo "$SEVERITY" | grep -qE "CRITICAL|HIGH" || continue
                        ;;
                    MEDIUM)
                        echo "$SEVERITY" | grep -qE "CRITICAL|HIGH|MEDIUM" || continue
                        ;;
                esac
                
                # Clean description
                DESC=$(echo "$DESCRIPTION" | tr '\n' ' ' | cut -c1-200)
                echo "$IP,$PORT,$PRODUCT,$VERSION,$CVE_ID,$SEVERITY,\"$DESC\""
                
                # Send to SIEM if enabled
                siem_send_vulnerability "$IP" "$PORT" "$CVE_ID" "$SEVERITY" "$DESC"
                
                # Send webhook notification for CRITICAL findings
                if [ "$SEVERITY" = "CRITICAL" ]; then
                    webhook_critical_finding "CVE-$CVE_ID detected on $IP:$PORT" "product=$PRODUCT version=$VERSION"
                fi
            done
        fi
    fi
    
    # Rate limiting for NVD
    if [ "$CVE_API" = "nvd" ] || [ "$CVE_API" = "all" ]; then
        sleep 6  # NVD allows 5 requests per 30 seconds
    fi
}

# =============================
# CVE Detection Phase
# =============================
run_cve_phase() {
    [ "$DO_CVE" -eq 0 ] && return
    [ ! -f "$VERSION_CSV" ] && log_warning "No version data available for CVE lookup" && return
    
    echo
    log_header "CVE Vulnerability Detection"
    
    # Check if version file has data
    VERSION_COUNT=$(awk 'NR>1 && $4!="-"' "$VERSION_CSV" | wc -l)
    if [ "$VERSION_COUNT" -eq 0 ]; then
        log_warning "No server versions detected - skipping CVE lookup"
        return
    fi
    
    log_info "CVE API: $CVE_API"
    log_info "Minimum severity: $CVE_MIN_SEVERITY"
    if [ "$CVE_TOTAL_TIMEOUT" -gt 0 ]; then
        log_info "Total timeout: ${CVE_TOTAL_TIMEOUT}s"
    fi
    log_info "Note: This may take several minutes due to API rate limits (6s per product)"
    echo
    
    # Get unique product/version combinations and filter skippable ones
    ALL_PRODUCTS=$(awk -F, 'NR>1 && $4!="-" {print $4","$5}' "$VERSION_CSV" | sort -u)
    SKIPPED=""
    VALID_PRODUCTS=""
    
    echo "$ALL_PRODUCTS" | while IFS=',' read PRODUCT VERSION; do
        # Check if should skip
        case "$PRODUCT" in
            cloudflare|envoy|unknown|-)
                SKIPPED="${SKIPPED}${PRODUCT}/${VERSION} "
                ;;
            *)
                # Skip if version same as product
                if [ "$VERSION" != "$PRODUCT" ]; then
                    VALID_PRODUCTS="${VALID_PRODUCTS}${PRODUCT},${VERSION}
"
                else
                    SKIPPED="${SKIPPED}${PRODUCT}/${VERSION} "
                fi
                ;;
        esac
    done
    
    # Show what we're skipping
    if [ -n "$(echo "$ALL_PRODUCTS" | grep -E "cloudflare|envoy")" ]; then
        log_info "Skipping generic products: cloudflare, envoy (too generic for CVE lookup)"
    fi
    
    # Count valid products
    VALID_PRODUCTS=$(echo "$ALL_PRODUCTS" | while IFS=',' read PRODUCT VERSION; do
        case "$PRODUCT" in
            cloudflare|envoy|unknown|-) ;;
            *)
                if [ "$VERSION" != "$PRODUCT" ]; then
                    echo "$PRODUCT,$VERSION"
                fi
                ;;
        esac
    done)
    
    TOTAL=$(echo "$VALID_PRODUCTS" | grep -c .)
    
    if [ "$TOTAL" -eq 0 ]; then
        log_warning "No valid products to check (all products are generic/unsupported)"
        echo "    Supported: nginx, apache, iis, php, openssh, mysql, etc."
        return
    fi
    
    log_info "Products to check: $TOTAL"
    echo
    
    # Initialize CVE files
    echo "ip,port,product,version,cve_id,severity,description" > "$CVE_CSV"
    
    COUNT=0
    
    echo "$VALID_PRODUCTS" | while IFS=',' read PRODUCT VERSION; do
        COUNT=$((COUNT + 1))
        printf "\r[*] CVE lookup: %d/%d - %s/%s          " "$COUNT" "$TOTAL" "$PRODUCT" "$VERSION"
        
        # Find all IPs with this product/version
        awk -F, -v prod="$PRODUCT" -v ver="$VERSION" \
            'NR>1 && $4==prod && $5==ver {print $1","$2}' "$VERSION_CSV" | \
        while IFS=',' read IP PORT; do
            lookup_cve "$IP" "$PORT" "$PRODUCT" "$VERSION" >> "$CVE_CSV"
        done
    done
    echo
    echo
    
    echo "[+] CVE detection complete"
    generate_cve_summary
}

# =============================
# Generate CVE Summary
# =============================
generate_cve_summary() {
    [ ! -s "$CVE_CSV" ] || [ $(wc -l < "$CVE_CSV") -le 1 ] && {
        log_info "No CVEs found matching criteria"
        echo "==================================="  > "$CVE_SUMMARY"
        echo "CVE Vulnerability Summary" >> "$CVE_SUMMARY"
        echo "===================================" >> "$CVE_SUMMARY"
        echo >> "$CVE_SUMMARY"
        echo "No vulnerabilities found or no data matched severity threshold." >> "$CVE_SUMMARY"
        return
    }
    
    log_info "Generating CVE summary..."
    
    {
        echo "==================================="
        echo "CVE Vulnerability Summary"
        echo "==================================="
        echo
        
        TOTAL=$(awk 'NR>1' "$CVE_CSV" | wc -l)
        CRITICAL=$(awk -F, 'NR>1 && $6=="CRITICAL"' "$CVE_CSV" | wc -l)
        HIGH=$(awk -F, 'NR>1 && $6=="HIGH"' "$CVE_CSV" | wc -l)
        MEDIUM=$(awk -F, 'NR>1 && $6=="MEDIUM"' "$CVE_CSV" | wc -l)
        LOW=$(awk -F, 'NR>1 && $6=="LOW"' "$CVE_CSV" | wc -l)
        
        echo "Total Vulnerabilities: $TOTAL"
        echo ""
        echo "By Severity:"
        echo "  CRITICAL: $CRITICAL"
        echo "  HIGH:     $HIGH"
        echo "  MEDIUM:   $MEDIUM"
        echo "  LOW:      $LOW"
        echo
        
        if [ "$CRITICAL" -gt 0 ] || [ "$HIGH" -gt 0 ]; then
            echo "ÃƒÆ’Ã‚Â¢Ãƒâ€¦Ã‚Â¡Ãƒâ€šÃ‚Â ÃƒÆ’Ã‚Â¯Ãƒâ€šÃ‚Â¸Ãƒâ€šÃ‚Â  HIGH PRIORITY ISSUES FOUND ÃƒÆ’Ã‚Â¢Ãƒâ€¦Ã‚Â¡Ãƒâ€šÃ‚Â ÃƒÆ’Ã‚Â¯Ãƒâ€šÃ‚Â¸Ãƒâ€šÃ‚Â"
            echo
        fi
        
        echo "Affected Products:"
        awk -F, 'NR>1 {print $3"/"$4}' "$CVE_CSV" | sort -u | \
            while read PROD; do
                CVE_COUNT=$(awk -F, -v prod="$PROD" 'NR>1 && $3"/"$4==prod' "$CVE_CSV" | wc -l)
                printf "  %s - %d CVEs\n" "$PROD" "$CVE_COUNT"
            done
        echo
        
        if [ "$CRITICAL" -gt 0 ]; then
            echo "CRITICAL Vulnerabilities:"
            awk -F, 'NR>1 && $6=="CRITICAL" {printf "  %s - %s (%s/%s)\n", $5, substr($7,1,60), $3, $4}' "$CVE_CSV" | head -10
            echo
        fi
        
        if [ "$HIGH" -gt 0 ]; then
            echo "HIGH Severity Vulnerabilities:"
            awk -F, 'NR>1 && $6=="HIGH" {printf "  %s - %s (%s/%s)\n", $5, substr($7,1,60), $3, $4}' "$CVE_CSV" | head -10
            echo
        fi
        
        echo "Full details in: $CVE_CSV"
    } > "$CVE_SUMMARY"
    
    cat "$CVE_SUMMARY"
}

# =============================
# JSON Export Phase
# =============================
export_json() {
    [ "$DO_JSON" -eq 0 ] && return
    
    
    log_header "JSON Export (Final)"
    
    JSON_DIR="$OUTDIR/json"
    mkdir -p "$JSON_DIR"
    
    log_info "Exporting data to JSON format..."
    log_info "Output directory: $JSON_DIR"
    echo
    
    # Export prefixes
    if [ -f "$PREFIX_FILE" ] && [ -s "$PREFIX_FILE" ]; then
        log_info "Exporting prefixes..."
        {
            echo "{"
            echo "  \"asn\": \"$ASN\","
            echo "  \"timestamp\": \"$(date -u '+%Y-%m-%dT%H:%M:%SZ')\","
            echo "  \"prefixes\": ["
            awk 'NR>1{printf ",\n"} {printf "    \"%s\"", $0}' "$PREFIX_FILE"
            echo
            echo "  ]"
            echo "}"
        } > "$JSON_DIR/prefixes.json"
    fi
    
    # Export PTR records
    if [ -f "$PTR_FILE" ] && [ -s "$PTR_FILE" ]; then
        log_info "Exporting PTR records..."
        {
            echo "{"
            echo "  \"asn\": \"$ASN\","
            echo "  \"timestamp\": \"$(date -u '+%Y-%m-%dT%H:%M:%SZ')\","
            echo "  \"ptr_records\": ["
            awk -F, 'NR>1{printf ",\n"} {printf "    {\"ip\": \"%s\", \"hostname\": \"%s\"}", $1, $2}' "$PTR_FILE"
            echo
            echo "  ]"
            echo "}"
        } > "$JSON_DIR/ptr_records.json"
    fi
    
    # Export domains
    if [ -f "$DOMAIN_FILE" ] && [ -s "$DOMAIN_FILE" ]; then
        log_info "Exporting domains..."
        {
            echo "{"
            echo "  \"asn\": \"$ASN\","
            echo "  \"timestamp\": \"$(date -u '+%Y-%m-%dT%H:%M:%SZ')\","
            echo "  \"domains\": ["
            awk 'NR>1{printf ",\n"} {printf "    \"%s\"", $0}' "$DOMAIN_FILE"
            echo
            echo "  ]"
            echo "}"
        } > "$JSON_DIR/domains.json"
    fi
    
    # Export TLS certificates
    if [ -f "$TLS_CSV" ] && [ -s "$TLS_CSV" ] && [ $(wc -l < "$TLS_CSV") -gt 1 ]; then
        log_info "Exporting TLS certificates..."
        {
            echo "{"
            echo "  \"asn\": \"$ASN\","
            echo "  \"timestamp\": \"$(date -u '+%Y-%m-%dT%H:%M:%SZ')\","
            echo "  \"certificates\": ["
            awk -F, 'NR>1 {
                if (NR>2) printf ",\n"
                gsub(/"/, "\\\"", $3); gsub(/"/, "\\\"", $5); gsub(/"/, "\\\"", $6)
                gsub(/"/, "\\\"", $8); gsub(/"/, "\\\"", $9)
                printf "    {\n"
                printf "      \"ip\": \"%s\",\n", $1
                printf "      \"port\": %s,\n", $2
                printf "      \"cn\": %s,\n", $3
                printf "      \"san_count\": %s,\n", $4
                printf "      \"sans\": %s,\n", $5
                printf "      \"organization\": %s,\n", $6
                printf "      \"country\": \"%s\",\n", $7
                printf "      \"issuer\": %s,\n", $8
                printf "      \"issuer_org\": %s,\n", $9
                printf "      \"valid_from\": \"%s\",\n", $10
                printf "      \"valid_to\": \"%s\",\n", $11
                printf "      \"days_remaining\": %s,\n", $12
                printf "      \"status\": \"%s\",\n", $13
                printf "      \"key_type\": \"%s\",\n", $14
                printf "      \"key_bits\": \"%s\",\n", $15
                printf "      \"signature_algorithm\": \"%s\",\n", $16
                printf "      \"serial_number\": \"%s\",\n", $17
                printf "      \"tls_version\": \"%s\",\n", $18
                printf "      \"cipher\": \"%s\",\n", $19
                printf "      \"is_wildcard\": \"%s\",\n", $20
                printf "      \"is_self_signed\": \"%s\",\n", $21
                printf "      \"is_weak_key\": \"%s\",\n", $22
                printf "      \"is_deprecated_tls\": \"%s\",\n", $23
                printf "      \"sct_count\": %s\n", $24
                printf "    }"
            }' "$TLS_CSV"
            echo
            echo "  ]"
            echo "}"
        } > "$JSON_DIR/tls_certificates.json"
    fi
    
    # Export server versions
    if [ -f "$VERSION_CSV" ] && [ -s "$VERSION_CSV" ] && [ $(wc -l < "$VERSION_CSV") -gt 1 ]; then
        log_info "Exporting server versions..."
        {
            echo "{"
            echo "  \"asn\": \"$ASN\","
            echo "  \"timestamp\": \"$(date -u '+%Y-%m-%dT%H:%M:%SZ')\","
            echo "  \"servers\": ["
            awk -F, 'NR>1 {
                if (NR>2) printf ",\n"
                printf "    {\n"
                printf "      \"ip\": \"%s\",\n", $1
                printf "      \"port\": %s,\n", $2
                printf "      \"status\": \"%s\",\n", $3
                printf "      \"product\": \"%s\",\n", $4
                printf "      \"version\": \"%s\",\n", $5
                printf "      \"powered_by\": \"%s\",\n", $6
                printf "      \"aspnet_version\": \"%s\"\n", $7
                printf "    }"
            }' "$VERSION_CSV"
            echo
            echo "  ]"
            echo "}"
        } > "$JSON_DIR/server_versions.json"
    fi
    
    # Export CVE vulnerabilities
    if [ -f "$CVE_CSV" ] && [ -s "$CVE_CSV" ] && [ $(wc -l < "$CVE_CSV") -gt 1 ]; then
        log_info "Exporting vulnerabilities..."
        {
            echo "{"
            echo "  \"asn\": \"$ASN\","
            echo "  \"timestamp\": \"$(date -u '+%Y-%m-%dT%H:%M:%SZ')\","
            echo "  \"vulnerabilities\": ["
            awk -F, 'NR>1 {
                if (NR>2) printf ",\n"
                gsub(/"/, "\\\"", $7)
                printf "    {\n"
                printf "      \"ip\": \"%s\",\n", $1
                printf "      \"port\": %s,\n", $2
                printf "      \"product\": \"%s\",\n", $3
                printf "      \"version\": \"%s\",\n", $4
                printf "      \"cve_id\": \"%s\",\n", $5
                printf "      \"severity\": \"%s\",\n", $6
                printf "      \"description\": %s\n", $7
                printf "    }"
            }' "$CVE_CSV"
            echo
            echo "  ]"
            echo "}"
        } > "$JSON_DIR/vulnerabilities.json"
    fi
    
    # Export traceroute data
    if [ -f "$TRACE_FILE" ] && [ -s "$TRACE_FILE" ] && [ $(wc -l < "$TRACE_FILE") -gt 1 ]; then
        log_info "Exporting traceroute data..."
        {
            echo "{"
            echo "  \"asn\": \"$ASN\","
            echo "  \"timestamp\": \"$(date -u '+%Y-%m-%dT%H:%M:%SZ')\","
            echo "  \"traces\": ["
            awk -F, 'NR>1 {
                if (NR>2) printf ",\n"
                printf "    {\n"
                printf "      \"target_ip\": \"%s\",\n", $1
                printf "      \"hop_number\": %s,\n", $2
                printf "      \"hop_ip\": \"%s\",\n", $3
                printf "      \"hop_hostname\": \"%s\",\n", $4
                printf "      \"rtt_ms\": \"%s\",\n", $5
                printf "      \"hop_asn\": \"%s\",\n", $6
                printf "      \"hop_org\": \"%s\"\n", $7
                printf "    }"
            }' "$TRACE_FILE"
            echo
            echo "  ]"
            echo "}"
        } > "$JSON_DIR/traceroute.json"
    fi
    
    # Export CT log results
    if [ -f "$CT_FILE" ] && [ -s "$CT_FILE" ]; then
        log_info "Exporting CT log subdomains..."
        {
            echo "{"
            echo "  \"asn\": \"$ASN\","
            echo "  \"timestamp\": \"$(date -u '+%Y-%m-%dT%H:%M:%SZ')\","
            echo "  \"subdomains\": ["
            awk 'NR>1{printf ",\n"} {printf "    \"%s\"", $0}' "$CT_FILE"
            echo
            echo "  ]"
            echo "}"
        } > "$JSON_DIR/ct_subdomains.json"
    fi
    
    # Export TLS issues
    if [ -f "$TLS_ISSUES" ] && [ -s "$TLS_ISSUES" ]; then
        log_info "Exporting TLS issues..."
        {
            echo "{"
            echo "  \"asn\": \"$ASN\","
            echo "  \"timestamp\": \"$(date -u '+%Y-%m-%dT%H:%M:%SZ')\","
            echo "  \"issues\": ["
            awk -F, 'NR>1 {
                if (NR>2) printf ",\n"
                printf "    {\n"
                printf "      \"ip\": \"%s\",\n", $1
                printf "      \"cn\": \"%s\",\n", $2
                printf "      \"issue_type\": \"%s\",\n", $3
                printf "      \"details\": \"%s\"\n", $4
                printf "    }"
            }' "$TLS_ISSUES"
            echo
            echo "  ]"
            echo "}"
        } > "$JSON_DIR/tls_issues.json"
    fi
    
    # Export TLS statistics
    if [ -f "$TLS_STATS" ] && [ -s "$TLS_STATS" ]; then
        log_info "Exporting TLS statistics..."
        # Parse the statistics file and convert to JSON
        {
            echo "{"
            echo "  \"asn\": \"$ASN\","
            echo "  \"timestamp\": \"$(date -u '+%Y-%m-%dT%H:%M:%SZ')\","
            echo "  \"statistics\": {"
            
            # Extract stats with sed/awk
            awk '
            BEGIN { first=1 }
            /Total certificates:/ { if (!first) printf ",\n"; first=0; printf "    \"total_certificates\": %d", $3 }
            /Key types:/ { in_keys=1; printf ",\n    \"key_types\": {"; key_first=1; next }
            /Key sizes:/ { in_keys=0; in_sizes=1; printf "\n    },\n    \"key_sizes\": {"; size_first=1; next }
            /TLS versions:/ { in_sizes=0; in_tls=1; printf "\n    },\n    \"tls_versions\": {"; tls_first=1; next }
            /^$/ { in_keys=0; in_sizes=0; in_tls=0 }
            in_keys && /^  / { 
                if (!key_first) printf ","; key_first=0
                gsub(/^ +/, ""); gsub(/:/, "\":")
                printf "\n      \"%s", $0
            }
            in_sizes && /^  / {
                if (!size_first) printf ","; size_first=0
                gsub(/^ +/, ""); gsub(/:/, "\":")
                printf "\n      \"%s", $0
            }
            in_tls && /^  / {
                if (!tls_first) printf ","; tls_first=0
                gsub(/^ +/, ""); gsub(/:/, "\":")
                printf "\n      \"%s", $0
            }
            ' "$TLS_STATS"
            
            echo
            echo "    }"
            echo "  }"
            echo "}"
        } > "$JSON_DIR/tls_statistics.json"
    fi
    
    # Export traceroute summary
    if [ -f "$TRACE_SUMMARY" ] && [ -s "$TRACE_SUMMARY" ]; then
        log_info "Exporting traceroute summary..."
        {
            echo "{"
            echo "  \"asn\": \"$ASN\","
            echo "  \"timestamp\": \"$(date -u '+%Y-%m-%dT%H:%M:%SZ')\","
            echo "  \"summary\": {"
            
            TARGETS=$(grep "Targets traced:" "$TRACE_SUMMARY" | awk '{print $3}')
            UNIQUE_ASNS=$(grep "Unique ASNs discovered:" "$TRACE_SUMMARY" | awk '{print $4}')
            
            echo "    \"targets_traced\": $TARGETS,"
            echo "    \"unique_asns\": $UNIQUE_ASNS,"
            echo "    \"top_asns\": ["
            
            # Extract top ASNs
            sed -n '/Top 10 ASNs/,/^$/p' "$TRACE_SUMMARY" | tail -n +2 | grep "AS" | head -10 | \
            awk 'NR>1{printf ",\n"} {
                count=$1; asn=$3; 
                org=substr($0, index($0,$4));
                printf "      {\"asn\": \"%s\", \"hop_count\": %d, \"organization\": \"%s\"}", asn, count, org
            }'
            
            echo
            echo "    ]"
            echo "  }"
            echo "}"
        } > "$JSON_DIR/traceroute_summary.json"
    fi
    
    # Export WHOIS data
    if [ -f "$OUTDIR/asn_whois.txt" ] && [ -s "$OUTDIR/asn_whois.txt" ]; then
        log_info "Exporting WHOIS data..."
        {
            echo "{"
            echo "  \"asn\": \"$ASN\","
            echo "  \"timestamp\": \"$(date -u '+%Y-%m-%dT%H:%M:%SZ')\","
            echo "  \"whois\": $(jq -Rs '.' "$OUTDIR/asn_whois.txt")
            echo "}"
        } > "$JSON_DIR/asn_whois.json"
    fi
    
    # Export scan metadata
    if [ -f "$OUTDIR/scan_metadata.txt" ]; then
        log_info "Exporting scan metadata..."
        {
            echo "{"
            echo "  \"asn\": \"$ASN\","
            echo "  \"scan_hash\": \"$SCAN_HASH\","
            echo "  \"timestamp\": \"$(date -u '+%Y-%m-%dT%H:%M:%SZ')\","
            echo "  \"metadata\": $(jq -Rs '.' "$OUTDIR/scan_metadata.txt")
            echo "}"
        } > "$JSON_DIR/scan_metadata.json"
    fi
    
    # Create comprehensive summary export
    log_info "Creating comprehensive summary..."
    {
        echo "{"
        echo "  \"scan_info\": {"
        echo "    \"asn\": \"$ASN\","
        echo "    \"scan_hash\": \"$SCAN_HASH\","
        echo "    \"timestamp\": \"$(date -u '+%Y-%m-%dT%H:%M:%SZ')\","
        echo "    \"version\": \"$VERSION\""
        echo "  },"
        echo "  \"statistics\": {"
        
        # Count all data
        PREFIX_COUNT=0
        PTR_COUNT=0
        DOMAIN_COUNT=0
        CT_COUNT=0
        TLS_COUNT=0
        VERSION_COUNT=0
        CVE_COUNT=0
        TRACE_COUNT=0
        
        [ -f "$PREFIX_FILE" ] && PREFIX_COUNT=$(wc -l < "$PREFIX_FILE")
        [ -f "$PTR_FILE" ] && PTR_COUNT=$(wc -l < "$PTR_FILE")
        [ -f "$DOMAIN_FILE" ] && DOMAIN_COUNT=$(wc -l < "$DOMAIN_FILE")
        [ -f "$CT_FILE" ] && CT_COUNT=$(wc -l < "$CT_FILE")
        [ -f "$TLS_CSV" ] && TLS_COUNT=$(($(wc -l < "$TLS_CSV") - 1))
        [ -f "$VERSION_CSV" ] && VERSION_COUNT=$(($(wc -l < "$VERSION_CSV") - 1))
        [ -f "$CVE_CSV" ] && CVE_COUNT=$(($(wc -l < "$CVE_CSV") - 1))
        [ -f "$TRACE_FILE" ] && TRACE_COUNT=$(($(wc -l < "$TRACE_FILE") - 1))
        
        [ "$TLS_COUNT" -lt 0 ] && TLS_COUNT=0
        [ "$VERSION_COUNT" -lt 0 ] && VERSION_COUNT=0
        [ "$CVE_COUNT" -lt 0 ] && CVE_COUNT=0
        [ "$TRACE_COUNT" -lt 0 ] && TRACE_COUNT=0
        
        echo "    \"prefixes\": $PREFIX_COUNT,"
        echo "    \"ptr_records\": $PTR_COUNT,"
        echo "    \"domains\": $DOMAIN_COUNT,"
        echo "    \"ct_subdomains\": $CT_COUNT,"
        echo "    \"tls_certificates\": $TLS_COUNT,"
        echo "    \"server_versions\": $VERSION_COUNT,"
        echo "    \"vulnerabilities\": $CVE_COUNT,"
        echo "    \"traceroute_hops\": $TRACE_COUNT"
        echo "  },"
        
        # Add text summaries
        echo "  \"summaries\": {"
        
        FIRST=1
        
        if [ -f "$TLS_SUMMARY" ] && [ -s "$TLS_SUMMARY" ]; then
            [ "$FIRST" -eq 0 ] && echo ","
            FIRST=0
            printf "    \"tls\": %s" "$(jq -Rs '.' "$TLS_SUMMARY")"
        fi
        
        if [ -f "$VERSION_SUMMARY" ] && [ -s "$VERSION_SUMMARY" ]; then
            [ "$FIRST" -eq 0 ] && echo ","
            FIRST=0
            printf "    \"version\": %s" "$(jq -Rs '.' "$VERSION_SUMMARY")"
        fi
        
        if [ -f "$CVE_SUMMARY" ] && [ -s "$CVE_SUMMARY" ]; then
            [ "$FIRST" -eq 0 ] && echo ","
            FIRST=0
            printf "    \"cve\": %s" "$(jq -Rs '.' "$CVE_SUMMARY")"
        fi
        
        if [ -f "$TRACE_SUMMARY" ] && [ -s "$TRACE_SUMMARY" ]; then
            [ "$FIRST" -eq 0 ] && echo ","
            FIRST=0
            printf "    \"traceroute\": %s" "$(jq -Rs '.' "$TRACE_SUMMARY")"
        fi
        
        echo
        echo "  }"
        echo "}"
    } > "$JSON_DIR/summary.json"
    
    # Create master index file
    log_info "Creating index..."
    {
        echo "{"
        echo "  \"scan_info\": {"
        echo "    \"asn\": \"$ASN\","
        echo "    \"scan_hash\": \"$SCAN_HASH\","
        echo "    \"timestamp\": \"$(date -u '+%Y-%m-%dT%H:%M:%SZ')\","
        echo "    \"version\": \"$VERSION\""
        echo "  },"
        echo "  \"available_exports\": ["
        FIRST=1
        for file in "$JSON_DIR"/*.json; do
            [ "$file" = "$JSON_DIR/index.json" ] && continue
            [ -f "$file" ] || continue
            [ "$FIRST" -eq 0 ] && echo ","
            FIRST=0
            BASENAME=$(basename "$file")
            printf "    \"%s\"" "$BASENAME"
        done
        echo
        echo "  ]"
        echo "}"
    } > "$JSON_DIR/index.json"
    
    # Export leak findings with compliance controls
    export_leak_findings_json
    
    echo
    echo "[+] JSON export complete"
    echo "    Location: $JSON_DIR/"
    
    # List exported files
    echo "    Files:"
    ls -1 "$JSON_DIR"/*.json 2>/dev/null | while read f; do
        SIZE=$(du -h "$f" | awk '{print $1}')
        echo "      $(basename "$f") ($SIZE)"
    done
    echo
}

# =============================
# ASN Range Scanning Functions
# =============================

# Lookup single ASN metadata
lookup_asn_metadata() {
    # Enterprise feature - removed from OSS
    return 0
}


# Fetch prefixes for an ASN
fetch_asn_prefixes() {
    # Enterprise feature - removed from OSS
    return 0
}


# Main ASN range scanner
run_asn_range_scan() {
    [ "$ASN_RANGE_MODE" -eq 0 ] && return
    
    echo
    echo "========================================"
    echo "ASN RANGE SCAN MODE"
    echo "========================================"
    
    # Create output structure
    RANGE_DIR="$OUTDIR/asn_details"
    mkdir -p "$RANGE_DIR"
    
    ASN_LIST_FILE="$OUTDIR/asn_list.txt"
    ASN_SUMMARY_FILE="$OUTDIR/asn_summary.csv"
    RANGE_SUMMARY_FILE="$OUTDIR/range_summary.txt"
    
    TOTAL_ASNS=$((ASN_END - ASN_START + 1))
    
    log_info "Scanning ASN range: AS${ASN_START} to AS${ASN_END}"
    log_info "Total ASNs: $TOTAL_ASNS"
    log_info "Parallel lookups: $ASN_PARALLEL"
    [ "$FETCH_PREFIXES" -eq 1 ] && log_info "Fetching prefix lists: enabled"
    echo
    
    # Create ASN list
    seq "$ASN_START" "$ASN_END" | while read num; do echo "AS${num}"; done > "$ASN_LIST_FILE"
    
    # Initialize summary CSV
    echo "asn,organization,prefix_count,country,status" > "$ASN_SUMMARY_FILE"
    
    # Perform lookups
    if [ "$ASN_PARALLEL" -le 1 ]; then
        # Serial mode
        COUNT=0
        for asn_num in $(seq "$ASN_START" "$ASN_END"); do
            COUNT=$((COUNT + 1))
            
            # Clear screen and show current scan
            clear
            echo "========================================"
            echo "ASN RANGE SCAN: AS${ASN_START} - AS${ASN_END}"
            echo "========================================"
            echo
            echo "Progress: [$COUNT/$TOTAL_ASNS] Currently scanning: AS$asn_num"
            echo
            echo "==================================="
            echo "WHOIS Data for AS$asn_num"
            echo "==================================="
            
            # Fetch and display WHOIS
            WHOIS_FILE="$RANGE_DIR/AS${asn_num}_info.txt"
            WHOIS_DATA=$(whois "AS${asn_num}" 2>/dev/null)
            
            if [ -n "$WHOIS_DATA" ]; then
                echo "$WHOIS_DATA"
                echo "$WHOIS_DATA" > "$WHOIS_FILE"
            else
                log_warning "No WHOIS data returned for AS$asn_num"
                echo "No WHOIS data available" > "$WHOIS_FILE"
            fi
            
            # Lookup metadata (extract from WHOIS data we already have)
            if [ -n "$WHOIS_DATA" ]; then
                # Try multiple patterns for organization (different WHOIS formats)
                ORG=$(echo "$WHOIS_DATA" | grep -iE "^org-name:|^orgname:|^organisation:|^org:" | head -1 | cut -d: -f2- | sed 's/^ *//;s/ *$//')
                
                # JPNIC format (Japan): "g. [Organization]"
                if [ -z "$ORG" ] || [ "$ORG" = "" ]; then
                    ORG=$(echo "$WHOIS_DATA" | grep -E "^\[Organization\]|^g\. \[Organization\]" | head -1 | sed 's/.*\[Organization\]//' | sed 's/^ *//;s/ *$//')
                fi
                
                # KRNIC format (Korea): "Organization Name:"
                if [ -z "$ORG" ] || [ "$ORG" = "" ]; then
                    ORG=$(echo "$WHOIS_DATA" | grep -E "^Organization Name:" | head -1 | cut -d: -f2- | sed 's/^ *//;s/ *$//')
                fi
                
                # TWNIC format (Taiwan): "organization:" or "netname:"
                if [ -z "$ORG" ] || [ "$ORG" = "" ]; then
                    ORG=$(echo "$WHOIS_DATA" | grep -iE "^organization:" | head -1 | cut -d: -f2- | sed 's/^ *//;s/ *$//')
                fi
                
                if [ -z "$ORG" ] || [ "$ORG" = "" ]; then
                    ORG=$(echo "$WHOIS_DATA" | grep -iE "^netname:" | head -1 | cut -d: -f2- | sed 's/^ *//;s/ *$//')
                fi
                
                # If not found, try descr field (CNNIC/APNIC often use this)
                if [ -z "$ORG" ] || [ "$ORG" = "" ]; then
                    ORG=$(echo "$WHOIS_DATA" | grep -iE "^descr:" | head -1 | cut -d: -f2- | sed 's/^ *//;s/ *$//')
                fi
                
                # If still not found, try as-name
                if [ -z "$ORG" ] || [ "$ORG" = "" ]; then
                    ORG=$(echo "$WHOIS_DATA" | grep -iE "^as-name:|^asname:|^b\. \[AS Name\]" | head -1 | sed 's/.*\[AS Name\]//' | cut -d: -f2- | sed 's/^ *//;s/ *$//')
                fi
                
                # NIC.br (Brazil): "owner:" or "responsible:"
                if [ -z "$ORG" ] || [ "$ORG" = "" ]; then
                    ORG=$(echo "$WHOIS_DATA" | grep -iE "^owner:" | head -1 | cut -d: -f2- | sed 's/^ *//;s/ *$//')
                fi
                
                if [ -z "$ORG" ] || [ "$ORG" = "" ]; then
                    ORG=$(echo "$WHOIS_DATA" | grep -iE "^responsible:" | head -1 | cut -d: -f2- | sed 's/^ *//;s/ *$//')
                fi
                
                # Last resort: mnt-by
                if [ -z "$ORG" ] || [ "$ORG" = "" ]; then
                    ORG=$(echo "$WHOIS_DATA" | grep -iE "^mnt-by:" | head -1 | cut -d: -f2- | sed 's/^ *//;s/ *$//')
                fi
                
                # Clean up organization name
                ORG=$(echo "$ORG" | sed 's/^"//;s/"$//;s/  */ /g')
                [ -z "$ORG" ] && ORG="Unknown"
                
                # Try multiple patterns for country
                COUNTRY=$(echo "$WHOIS_DATA" | grep -iE "^country:" | head -1 | cut -d: -f2- | sed 's/^ *//;s/ *$//;s/  */ /g')
                
                # JPNIC format: Detect JPNIC and assume JP
                if [ -z "$COUNTRY" ] || [ "$COUNTRY" = "" ]; then
                    if echo "$WHOIS_DATA" | grep -q "JPNIC database"; then
                        COUNTRY="JP"
                    fi
                fi
                
                # KRNIC format: Detect KRNIC and assume KR
                if [ -z "$COUNTRY" ] || [ "$COUNTRY" = "" ]; then
                    if echo "$WHOIS_DATA" | grep -q "KRNIC"; then
                        COUNTRY="KR"
                    fi
                fi
                
                # TWNIC format: Detect TWNIC and assume TW
                if [ -z "$COUNTRY" ] || [ "$COUNTRY" = "" ]; then
                    if echo "$WHOIS_DATA" | grep -qi "TWNIC\|Taiwan Network Information"; then
                        COUNTRY="TW"
                    fi
                fi
                
                # CNNIC format: Detect CNNIC and assume CN
                if [ -z "$COUNTRY" ] || [ "$COUNTRY" = "" ]; then
                    if echo "$WHOIS_DATA" | grep -qi "CNNIC\|China Network Information"; then
                        COUNTRY="CN"
                    fi
                fi
                
                # NIC.br format: Detect NIC.br and assume BR
                if [ -z "$COUNTRY" ] || [ "$COUNTRY" = "" ]; then
                    if echo "$WHOIS_DATA" | grep -qi "nic\.br\|Brazil"; then
                        COUNTRY="BR"
                    fi
                fi
                
                # If not found, try address field and extract 2-letter country code
                if [ -z "$COUNTRY" ] || [ "$COUNTRY" = "" ]; then
                    COUNTRY=$(echo "$WHOIS_DATA" | grep -iE "^address:" | tail -1 | sed 's/.*\b([A-Z]{2})\b.*/\1/' | grep -E '^[A-Z]{2}$')
                fi
                
                [ -z "$COUNTRY" ] && COUNTRY="--"
                
                # Get prefix count
                PREFIX_DATA=$(curl -4 -s --max-time 10 "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS${asn_num}" 2>/dev/null)
                PREFIX_COUNT=0
                if [ -n "$PREFIX_DATA" ]; then
                    PREFIX_COUNT=$(echo "$PREFIX_DATA" | jq -r '.data.prefixes | length' 2>/dev/null)
                    [ -z "$PREFIX_COUNT" ] || [ "$PREFIX_COUNT" = "null" ] && PREFIX_COUNT=0
                fi
                
                echo "AS${asn_num},\"$ORG\",$PREFIX_COUNT,$COUNTRY,success" >> "$ASN_SUMMARY_FILE"
                
                echo
                echo "==================================="
                echo "Quick Summary:"
                echo "  Organization: $ORG"
                echo "  Prefixes: $PREFIX_COUNT"
                echo "  Country: $COUNTRY"
                echo "==================================="
            else
                echo "AS${asn_num},Unknown,0,--,error" >> "$ASN_SUMMARY_FILE"
            fi
            
            # Fetch prefixes if requested
            if [ "$FETCH_PREFIXES" -eq 1 ]; then
                echo
                log_info "Fetching prefix list..."
                fetch_asn_prefixes "$asn_num" "$RANGE_DIR/AS${asn_num}_prefixes.txt"
            fi
            
            # Pause briefly so user can see the data
            sleep 1
        done
        
        # Clear and show completion
        clear
        echo "========================================"
        echo "ASN RANGE SCAN COMPLETE"
        echo "========================================"
        echo
        log_info "WHOIS data saved to: $RANGE_DIR/"
    else
        # Parallel mode
        log_info "Running parallel lookups..."
        
        # Create temp file for parallel output
        TEMP_OUTPUT="$OUTDIR/.asn_parallel_temp.csv"
        rm -f "$TEMP_OUTPUT"
        
        seq "$ASN_START" "$ASN_END" | xargs -P "$ASN_PARALLEL" -I{} sh -c '
            asn_num="{}"
            RANGE_DIR="'"$RANGE_DIR"'"
            FETCH_PREFIXES="'"$FETCH_PREFIXES"'"
            TEMP_OUTPUT="'"$TEMP_OUTPUT"'"
            
            # Lookup metadata
            RESULT=$(whois "AS${asn_num}" 2>/dev/null)
            
            if [ -z "$RESULT" ]; then
                LINE="AS${asn_num},Unknown,0,--,error"
            else
                # Try multiple patterns for organization (different WHOIS formats)
                ORG=$(echo "$RESULT" | grep -iE "^org-name:|^orgname:|^organisation:|^org:" | head -1 | cut -d: -f2- | sed "s/^ *//;s/ *$//")
                
                # JPNIC format (Japan): "g. [Organization]"
                if [ -z "$ORG" ] || [ "$ORG" = "" ]; then
                    ORG=$(echo "$RESULT" | grep -E "^\[Organization\]|^g\\. \\[Organization\\]" | head -1 | sed "s/.*\\[Organization\\]//" | sed "s/^ *//;s/ *$//")
                fi
                
                # KRNIC format (Korea): "Organization Name:"
                if [ -z "$ORG" ] || [ "$ORG" = "" ]; then
                    ORG=$(echo "$RESULT" | grep -E "^Organization Name:" | head -1 | cut -d: -f2- | sed "s/^ *//;s/ *$//")
                fi
                
                # TWNIC format (Taiwan): "organization:" or "netname:"
                if [ -z "$ORG" ] || [ "$ORG" = "" ]; then
                    ORG=$(echo "$RESULT" | grep -iE "^organization:" | head -1 | cut -d: -f2- | sed "s/^ *//;s/ *$//")
                fi
                
                if [ -z "$ORG" ] || [ "$ORG" = "" ]; then
                    ORG=$(echo "$RESULT" | grep -iE "^netname:" | head -1 | cut -d: -f2- | sed "s/^ *//;s/ *$//")
                fi
                
                # If not found, try descr field (CNNIC/APNIC)
                if [ -z "$ORG" ] || [ "$ORG" = "" ]; then
                    ORG=$(echo "$RESULT" | grep -iE "^descr:" | head -1 | cut -d: -f2- | sed "s/^ *//;s/ *$//")
                fi
                
                # If still not found, try as-name
                if [ -z "$ORG" ] || [ "$ORG" = "" ]; then
                    ORG=$(echo "$RESULT" | grep -iE "^as-name:|^asname:|^b\\. \\[AS Name\\]" | head -1 | sed "s/.*\\[AS Name\\]//" | cut -d: -f2- | sed "s/^ *//;s/ *$//")
                fi
                
                # NIC.br (Brazil): "owner:" or "responsible:"
                if [ -z "$ORG" ] || [ "$ORG" = "" ]; then
                    ORG=$(echo "$RESULT" | grep -iE "^owner:" | head -1 | cut -d: -f2- | sed "s/^ *//;s/ *$//")
                fi
                
                if [ -z "$ORG" ] || [ "$ORG" = "" ]; then
                    ORG=$(echo "$RESULT" | grep -iE "^responsible:" | head -1 | cut -d: -f2- | sed "s/^ *//;s/ *$//")
                fi
                
                # Last resort: mnt-by
                if [ -z "$ORG" ] || [ "$ORG" = "" ]; then
                    ORG=$(echo "$RESULT" | grep -iE "^mnt-by:" | head -1 | cut -d: -f2- | sed "s/^ *//;s/ *$//")
                fi
                
                # Clean up organization name
                ORG=$(echo "$ORG" | sed "s/^\\"//;s/\\"\$//;s/  */ /g")
                [ -z "$ORG" ] && ORG="Unknown"
                
                # Try multiple patterns for country
                COUNTRY=$(echo "$RESULT" | grep -iE "^country:" | head -1 | cut -d: -f2- | sed "s/^ *//;s/ *$//;s/  */ /g")
                
                # JPNIC format: Detect JPNIC and assume JP
                if [ -z "$COUNTRY" ] || [ "$COUNTRY" = "" ]; then
                    if echo "$RESULT" | grep -q "JPNIC database"; then
                        COUNTRY="JP"
                    fi
                fi
                
                # KRNIC format: Detect KRNIC and assume KR
                if [ -z "$COUNTRY" ] || [ "$COUNTRY" = "" ]; then
                    if echo "$RESULT" | grep -q "KRNIC"; then
                        COUNTRY="KR"
                    fi
                fi
                
                # TWNIC format: Detect TWNIC and assume TW
                if [ -z "$COUNTRY" ] || [ "$COUNTRY" = "" ]; then
                    if echo "$RESULT" | grep -qi "TWNIC\\|Taiwan Network Information"; then
                        COUNTRY="TW"
                    fi
                fi
                
                # CNNIC format: Detect CNNIC and assume CN
                if [ -z "$COUNTRY" ] || [ "$COUNTRY" = "" ]; then
                    if echo "$RESULT" | grep -qi "CNNIC\\|China Network Information"; then
                        COUNTRY="CN"
                    fi
                fi
                
                # NIC.br format: Detect NIC.br and assume BR
                if [ -z "$COUNTRY" ] || [ "$COUNTRY" = "" ]; then
                    if echo "$RESULT" | grep -qi "nic\\.br\\|Brazil"; then
                        COUNTRY="BR"
                    fi
                fi
                
                # If not found, try address field
                if [ -z "$COUNTRY" ] || [ "$COUNTRY" = "" ]; then
                    COUNTRY=$(echo "$RESULT" | grep -iE "^address:" | tail -1 | sed "s/.*\\b([A-Z]{2})\\b.*/\\1/" | grep -E "^[A-Z]{2}\$")
                fi
                
                [ -z "$COUNTRY" ] && COUNTRY="--"
                
                # Get prefix count
                PREFIX_DATA=$(curl -4 -s --max-time 10 "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS${asn_num}" 2>/dev/null)
                PREFIX_COUNT=0
                if [ -n "$PREFIX_DATA" ]; then
                    PREFIX_COUNT=$(echo "$PREFIX_DATA" | jq -r ".data.prefixes | length" 2>/dev/null)
                    [ -z "$PREFIX_COUNT" ] || [ "$PREFIX_COUNT" = "null" ] && PREFIX_COUNT=0
                fi
                
                LINE="AS${asn_num},\"$ORG\",$PREFIX_COUNT,$COUNTRY,success"
                
                # Save WHOIS
                echo "$RESULT" > "$RANGE_DIR/AS${asn_num}_info.txt"
                
                # Fetch prefixes if requested
                if [ "$FETCH_PREFIXES" -eq 1 ]; then
                    curl -4 -s --max-time 10 "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS${asn_num}" \
                        | jq -r ".data.prefixes // [] | .[].prefix" 2>/dev/null \
                        | sort -u > "$RANGE_DIR/AS${asn_num}_prefixes.txt"
                fi
            fi
            
            # Write to temp file with lock
            (
                flock -x 200
                echo "$LINE" >> "$TEMP_OUTPUT"
            ) 200>"$TEMP_OUTPUT.lock"
            
            printf "." >&2
        '
        echo
        echo
        
        # Append temp file to summary
        if [ -f "$TEMP_OUTPUT" ]; then
            cat "$TEMP_OUTPUT" >> "$ASN_SUMMARY_FILE"
            rm -f "$TEMP_OUTPUT" "$TEMP_OUTPUT.lock"
        fi
        
        log_info "WHOIS data saved to: $RANGE_DIR/"
    fi
    
    echo "[+] ASN range scan complete"
    
    # Generate summary
    generate_asn_range_summary
}

# Generate ASN range summary
generate_asn_range_summary() {
    [ ! -f "$ASN_SUMMARY_FILE" ] && return
    
    log_info "Generating range summary..."
    
    {
        echo "==================================="
        echo "ASN Range Scan Summary"
        echo "==================================="
        echo
        echo "Range: AS${ASN_START} - AS${ASN_END}"
        echo "Total ASNs scanned: $TOTAL_ASNS"
        echo
        
        SUCCESS=$(awk -F, 'NR>1 && $5=="success"' "$ASN_SUMMARY_FILE" | wc -l)
        ERRORS=$(awk -F, 'NR>1 && $5=="error"' "$ASN_SUMMARY_FILE" | wc -l)
        TOTAL_PREFIXES=$(awk -F, 'NR>1 && $5=="success" {sum+=$3} END {print sum+0}' "$ASN_SUMMARY_FILE")
        WHOIS_FILES=$(ls -1 "$RANGE_DIR"/AS*_info.txt 2>/dev/null | wc -l)
        
        echo "Successful lookups: $SUCCESS"
        echo "Failed lookups: $ERRORS"
        echo "WHOIS files saved: $WHOIS_FILES"
        echo "Total prefixes: $TOTAL_PREFIXES"
        echo
        
        echo "Top 10 ASNs by prefix count:"
        awk -F, 'NR>1 && $5=="success" && $3>0 {print $3, $1, $2}' "$ASN_SUMMARY_FILE" | \
            sort -rn | head -10 | \
            awk '{printf "  %5d prefixes - %s %s\n", $1, $2, substr($0, index($0,$3))}'
        echo
        
        echo "Organizations found:"
        awk -F, 'NR>1 && $5=="success" && $2!="" && $2!="-" && $2!="Unknown" {
            gsub(/"/, "", $2); orgs[$2]++
        } END {
            for(org in orgs) {
                if (org != "" && org != "-" && org != "Unknown")
                    print "  " org " (" orgs[org] " ASNs)"
            }
        }' "$ASN_SUMMARY_FILE" | sort | head -20
        
        UNKNOWN_ORGS=$(awk -F, 'NR>1 && ($2=="-" || $2=="Unknown" || $2=="\"Unknown\"")' "$ASN_SUMMARY_FILE" | wc -l)
        if [ "$UNKNOWN_ORGS" -gt 0 ]; then
            echo "  (Unknown: $UNKNOWN_ORGS ASNs)"
        fi
        echo
        
        echo "Countries:"
        awk -F, 'NR>1 && $5=="success" && $4!="" && $4!="-" && $4!="--" {count[$4]++} 
                 END {for(c in count) {
                     if (c != "" && c != "-" && c != "--")
                         print count[c], c
                 }}' "$ASN_SUMMARY_FILE" | \
            sort -rn | awk '{printf "  %s: %d ASNs\n", $2, $1}'
        
        UNKNOWN_COUNTRIES=$(awk -F, 'NR>1 && ($4=="-" || $4=="--" || $4=="")' "$ASN_SUMMARY_FILE" | wc -l)
        if [ "$UNKNOWN_COUNTRIES" -gt 0 ]; then
            echo "  (Unknown: $UNKNOWN_COUNTRIES ASNs)"
        fi
        echo
        
        echo "Files generated:"
        echo "  $ASN_LIST_FILE"
        echo "  $ASN_SUMMARY_FILE"
        echo "  $RANGE_DIR/"
        
    } > "$RANGE_SUMMARY_FILE"
    
    cat "$RANGE_SUMMARY_FILE"
    echo
}

# Export ASN range data to JSON
export_asn_range_json() {
    [ "$ASN_RANGE_MODE" -eq 0 ] && return
    [ "$DO_JSON" -eq 0 ] && return
    [ ! -f "$ASN_SUMMARY_FILE" ] && return
    
    log_info "Exporting ASN range data to JSON..."
    
    JSON_DIR="$OUTDIR/json"
    mkdir -p "$JSON_DIR"
    
    # Export ASN range summary
    {
        echo "{"
        echo "  \"range\": {"
        echo "    \"start\": \"AS${ASN_START}\","
        echo "    \"end\": \"AS${ASN_END}\","
        echo "    \"total\": $TOTAL_ASNS"
        echo "  },"
        echo "  \"timestamp\": \"$(date -u '+%Y-%m-%dT%H:%M:%SZ')\","
        echo "  \"asns\": ["
        
        awk -F, 'NR>1 {
            if (NR>2) printf ",\n"
            gsub(/"/, "", $2)
            printf "    {\n"
            printf "      \"asn\": \"%s\",\n", $1
            printf "      \"organization\": \"%s\",\n", $2
            printf "      \"prefix_count\": %s,\n", $3
            printf "      \"country\": \"%s\",\n", $4
            printf "      \"status\": \"%s\"\n", $5
            printf "    }"
        }' "$ASN_SUMMARY_FILE"
        
        echo
        echo "  ]"
        echo "}"
    } > "$JSON_DIR/asn_range_summary.json"
    
    echo "[+] ASN range JSON export complete"
}

# =============================
# ASN WHOIS Lookup
# =============================
asn_whois() {
    if ! command -v whois >/dev/null 2>&1; then
        log_warning "WHOIS not available, skipping..."
        echo "WHOIS tool not installed" > "$OUTDIR/asn_whois.txt"
        return
    fi
    
    log_info "Fetching ASN WHOIS information..."
    rm -f "$OUTDIR/asn_whois.txt"
    WHOIS_OUT=$(whois "$ASN" 2>/dev/null)
    if [ -z "$WHOIS_OUT" ]; then
        echo "    No WHOIS info returned."
        echo "No WHOIS info returned." > "$OUTDIR/asn_whois.txt"
        echo
        return
    fi
    echo "$WHOIS_OUT" > "$OUTDIR/asn_whois.txt"
    
    # Extract key info
    ORG=$(echo "$WHOIS_OUT" | grep -i "orgname\|org-name" | head -1 | cut -d: -f2- | sed 's/^ *//')
    [ -n "$ORG" ] && echo "    Organization: $ORG"
    echo
}

# =============================
# Comprehensive Help
# =============================
show_help() {
echo
print_ascii_banner
echo
printf "${BOLD}Advanced ASN Reconnaissance for Security Professionals${NC}\n"
printf "Complete network intelligence with vulnerability detection\n\n"
printf "${BOLD}USAGE:${NC}\n"
printf "  ./asnspy.sh AS##### [options]\n\n"
printf "${BOLD}═══════════════════════════════════════════════════════════════════════════════${NC}\n"
printf "${BOLD}RECONNAISSANCE FEATURES (Open Source)${NC}\n"
printf "${BOLD}═══════════════════════════════════════════════════════════════════════════════${NC}\n\n"
printf "${BOLD}Core Discovery:${NC}\n"
cat <<'HELPEOF'
  -h, --help             Show this help message
  --skip-ptr             Skip PTR record scanning
  --ipv4/--ipv6          Protocol selection
  --skip-dead            Skip .0, .127, .255 octets
  --internet-only        Skip private/gateway addresses
  --host-range N-M       Scan specific host range (default: 1-255)
  --prefix-range N-M     Filter prefixes by first octet
HELPEOF
printf "\n${BOLD}Performance Control:${NC}\n"
cat <<'HELPEOF'
  --parallel N           Global parallel operations (default: 1)
                         Scales all phases proportionally
  --trace-parallel N     Parallel traceroutes (inherits --parallel)
  --tls-parallel N       Parallel TLS scans (inherits --parallel)
  --version-parallel N   Parallel version detection (inherits --parallel)
  --port-scan-parallel N Parallel port scans (inherits --parallel)
  
  Performance Guide:
    parallel=1    →  ~10 IPs/min  (stealth, minimal impact)
    parallel=20   →  ~100 IPs/min (balanced, recommended)
    parallel=100  →  ~400 IPs/min (aggressive scanning)
HELPEOF
printf "\n${BOLD}Network Intelligence:${NC}\n"
cat <<'HELPEOF'
  --trace                Network path tracing (traceroute with ASN attribution)
  --trace-mode MODE      ptr|all|gateway (default: ptr)
  --hops N               Max hops (default: 30)
  --no-hop-asn           Skip ASN lookup for speed
  
  --ct                   Certificate Transparency subdomain enumeration
  --ct-timeout N         Timeout per domain (0 = unlimited)
  
  --tls                  TLS certificate analysis (expiry, chains, issues)
  --tls-mode MODE        ptr|all|gateway (default: ptr)
  --tls-port N           Port to scan (default: 443)
  
  --cloud-detect         Identify cloud providers (AWS, Azure, GCP, etc.)
HELPEOF
printf "\n${BOLD}Security Assessment:${NC}\n"
cat <<'HELPEOF'
  --port-scan            TCP port scanning (requires authorization)
  --port-scan-mode MODE  ptr|all|gateway (default: ptr)
  --port-scan-top N      Scan top N ports (nmap-style)
  --port-scan-ports "P"  Custom port list
  
  --version-detect       HTTP server version detection
  --version-ports "P"    Ports to check (default: 80,443,8080,8443)
  
  --cve                  CVE vulnerability lookup (NVD API)
  --cve-min-severity LVL Filter: LOW|MEDIUM|HIGH|CRITICAL
  
  --http-security        Security headers analysis with risk scoring
  
  --leak-scan            Exposed config/credential detection (requires authorization)
  --leak-ports "P"       Ports for banner grabbing
HELPEOF
printf "\n${BOLD}Scan Profiles (Quick Presets):${NC}\n"
cat <<'HELPEOF'
  --profile quick        Fast recon: First 50 IPs, essential checks
  --profile standard     Balanced: Default settings (recommended)
  --profile deep         Comprehensive: All features enabled
  --profile stealth      Careful: Slow, low-profile scanning
  --profile security     Security-focused: Vulnerabilities + compliance
HELPEOF
printf "\n${BOLD}Output & Automation:${NC}\n"
cat <<'HELPEOF'
  --json                 Export all data to JSON format
  --quiet                Suppress progress (for scripts/cron)
  --debug                Verbose debugging output
  --no-color             Disable color output
  --generate-config      Create example config file
HELPEOF
printf "\n${BOLD}═══════════════════════════════════════════════════════════════════════════════${NC}\n"
printf "${BOLD}🚀 ENTERPRISE EDITION - Operational Automation${NC}\n"
printf "${BOLD}═══════════════════════════════════════════════════════════════════════════════${NC}\n\n"
printf "Open Source: ${GREEN}Complete reconnaissance${NC} — find every asset, vulnerability, exposure\n"
printf "Enterprise:  ${BOLD}Zero manual work${NC} — automate the toil around scanning\n\n"

printf "${BOLD}Why Teams Upgrade:${NC}\n"
printf "  OSS provides fast scans (15 min with --parallel 100)\n"
printf "  ${RED}BUT${NC} the workflow pain isn't speed — it's everything else:\n"
printf "    • Manually tracking which ASNs to scan and when\n"
printf "    • Importing JSON/CSV into spreadsheets every week\n"
printf "    • Comparing this week vs last week to find changes\n"
printf "    • Manually alerting teams about critical findings\n"
printf "    • Generating executive reports for compliance\n"
printf "    • Maintaining vulnerability inventory across scans\n"
printf "  ${YELLOW}→ This \"glue work\" costs 18+ hours/week (\$117K/year in labor)${NC}\n\n"

printf "${BOLD}Enterprise Eliminates the Toil:${NC}\n\n"

printf "  ${BOLD}⚡ Real-Time Alerting${NC} — Slack/Discord/Teams/PagerDuty webhooks\n"
printf "     ${CYAN}✓${NC} Critical findings notify your team instantly (not next Monday)\n"
printf "     ${CYAN}✓${NC} No more checking scan folders manually\n"
printf "     ${CYAN}✓${NC} Context-aware alerts (only notify on NEW critical issues)\n\n"

printf "  ${BOLD}⚡ SIEM Integration${NC} — Splunk, Elasticsearch, QRadar, ArcSight\n"
printf "     ${CYAN}✓${NC} All findings flow to your SOC automatically\n"
printf "     ${CYAN}✓${NC} Correlate with IDS/SIEM events for investigations\n"
printf "     ${CYAN}✓${NC} Compliance audit trails without manual exports\n\n"

printf "  ${BOLD}⚡ Database Backend${NC} — PostgreSQL, MySQL, SQLite\n"
printf "     ${CYAN}✓${NC} Vulnerability tracking across time (trending, metrics)\n"
printf "     ${CYAN}✓${NC} SQL queries for custom reports and dashboards\n"
printf "     ${CYAN}✓${NC} No more importing CSVs into Excel\n\n"

printf "  ${BOLD}⚡ Change Detection${NC} — Automatic diff mode\n"
printf "     ${CYAN}✓${NC} \"What changed since last scan?\" answered automatically\n"
printf "     ${CYAN}✓${NC} New assets, vulnerabilities, exposures highlighted\n"
printf "     ${CYAN}✓${NC} Alerts on critical deltas requiring immediate action\n\n"

printf "  ${BOLD}⚡ ASN Range Scanning${NC} — Batch operations\n"
printf "     ${CYAN}✓${NC} Scan AS1000-AS2000 in one command (not 1,000 commands)\n"
printf "     ${CYAN}✓${NC} Map entire industries, corporate groups, supply chains\n"
printf "     ${CYAN}✓${NC} Scheduled scans with --cron integration\n\n"

printf "${BOLD}💰 Real Customer ROI:${NC}\n"
printf "  ${DIM}\"Before Enterprise:${NC} Security engineer spent 2+ days/week on scan\n"
printf "   management, tracking, and reporting. Couldn't keep up with our\n"
printf "   50+ ASNs. Missed a critical exposure for 3 weeks.\n\n"
printf "  ${DIM} After Enterprise:${NC} Everything runs automatically. Database tracks\n"
printf "   history. Slack alerts the team on critical findings. SIEM gets all\n"
printf "   data. We eliminated 18 hours/week of toil. ${GREEN}Paid for itself in 6 weeks.${NC}\"\n"
printf "   ${DIM}— Fortune 500 Security Team${NC}\n\n"

printf "${BOLD}📊 Cost Comparison:${NC}\n"
printf "  Manual workflow:  18 hrs/week × \$125/hr × 52 weeks = ${RED}\$117,000/year${NC}\n"
printf "  Enterprise:       \$10,000/year license = ${GREEN}\$107,000 saved${NC}\n"
printf "                    ${BOLD}+ eliminate human error + faster response${NC}\n\n"

printf "${BOLD}📞 Learn More:${NC}\n"
printf "  Website:       https://asnspy.com/enterprise\n"
printf "  Contact:       contact@asnspy.com\n"
printf "  Documentation: https://docs.asnspy.com\n"
printf "  Community:     https://github.com/ASNSPY/asnspy-oss\n"
printf "  Instagram:     @asn_spy\n\n"

printf "${BOLD}═══════════════════════════════════════════════════════════════════════════════${NC}\n"
printf "${BOLD}USAGE EXAMPLES${NC}\n"
printf "${BOLD}═══════════════════════════════════════════════════════════════════════════════${NC}\n\n"
printf "${BOLD}Basic Reconnaissance:${NC}\n"
cat <<'HELPEOF'
  # Quick scan with essential checks
  ./asnspy.sh AS15169 --profile quick
  
  # Standard scan with parallel processing
  ./asnspy.sh AS15169 --parallel 20
  
  # Comprehensive security audit
  ./asnspy.sh AS15169 --profile security --parallel 50
HELPEOF
printf "\n${BOLD}Bug Bounty Hunting:${NC}\n"
cat <<'HELPEOF'
  # Fast subdomain discovery
  ./asnspy.sh AS13335 --ct --tls --parallel 100
  
  # Find vulnerable services
  ./asnspy.sh AS15169 --port-scan --version-detect --cve --parallel 50
  
  # Complete attack surface mapping
  ./asnspy.sh AS1234 --profile deep --json
HELPEOF
printf "\n${BOLD}Penetration Testing:${NC}\n"
cat <<'HELPEOF'
  # Stealth reconnaissance
  ./asnspy.sh AS5678 --profile stealth --trace
  
  # Security exposure assessment
  ./asnspy.sh AS9012 --leak-scan --http-security --tls
HELPEOF
printf "\n${BOLD}Export & Analysis:${NC}\n"
cat <<'HELPEOF'
  # JSON export for processing
  ./asnspy.sh AS15169 --profile deep --json --quiet
  
  # Scan multiple ASNs
  for asn in 15169 13335 16509; do
    ./asnspy.sh AS$asn --profile quick &
  done
  wait
HELPEOF
printf "\n${BOLD}═══════════════════════════════════════════════════════════════════════════════${NC}\n"
printf "${BOLD}AUTHORIZATION & LEGAL${NC}\n"
printf "${BOLD}═══════════════════════════════════════════════════════════════════════════════${NC}\n\n"
cat <<'HELPEOF'
  This tool is for AUTHORIZED security assessments only.
  
  REQUIRES AUTHORIZATION:
  • Port scanning (--port-scan)
  • Leak detection (--leak-scan)  
  • Any network you don't own or have written permission to test
  
  LEGAL COMPLIANCE:
  • Unauthorized use may violate CFAA, Computer Misuse Act, and similar laws
  • "Authorization" = explicit written permission from network owner
  • Bug bounty programs provide authorization within their defined scope
  
  USER RESPONSIBILITY:
  • Obtain proper authorization before scanning
  • Comply with all applicable laws and regulations
  • Follow responsible disclosure practices
  • Handle reports securely
HELPEOF
printf "\n${BOLD}═══════════════════════════════════════════════════════════════════════════════${NC}\n\n"
}
# CLI Parser - Enhanced
# =============================
# Track enterprise flags
ENTERPRISE_FLAGS_USED=""

while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help) show_help; exit 0 ;;
        
        # Enterprise-only flags - track them
        --webhook|--webhook-type|--webhook-events|--webhook-severity)
            ENTERPRISE_FLAGS_USED="$ENTERPRISE_FLAGS_USED $1"
            shift
            [ $# -gt 0 ] && shift  # Skip value if present
            continue
            ;;
        --siem|--siem-type|--siem-host|--siem-token|--siem-index|--siem-protocol)
            ENTERPRISE_FLAGS_USED="$ENTERPRISE_FLAGS_USED $1"
            shift
            [ $# -gt 0 ] && shift
            continue
            ;;
        --database|--db-type|--db-file|--db-host|--db-port|--db-name|--db-user|--db-pass)
            ENTERPRISE_FLAGS_USED="$ENTERPRISE_FLAGS_USED $1"
            shift
            [ $# -gt 0 ] && shift
            continue
            ;;
        --diff|--diff-dir|--diff-no-alert)
            ENTERPRISE_FLAGS_USED="$ENTERPRISE_FLAGS_USED $1"
            shift
            [ $# -gt 0 ] && shift
            continue
            ;;
        --asn-range|--fetch-prefixes|--asn-parallel)
            ENTERPRISE_FLAGS_USED="$ENTERPRISE_FLAGS_USED $1"
            shift
            [ $# -gt 0 ] && shift
            continue
            ;;
        
        # Regular flags
        -y|--yes|--auto-confirm) AUTO_CONFIRM=1 ;;
        --skip-ptr) SKIP_PTR=1 ;;
        --skip-dead) SKIP_DEAD=1 ;;
        --internet-only) MODE_INTERNET_ONLY=1 ;;
        --strict-valid) MODE_STRICT_VALID=1 ;;
        --gateway-only) MODE_GATEWAY_ONLY=1 ;;
        --host-range) SWEEP_START=$(echo "$2"|cut -d- -f1); SWEEP_END=$(echo "$2"|cut -d- -f2); shift;;
        --prefix-range) PREFIX_START=$(echo "$2"|cut -d- -f1); PREFIX_END=$(echo "$2"|cut -d- -f2); shift;;
        --parallel) PARALLEL="$2"; shift;;
        --ipv4) DO_IPV4=1; DO_IPV6=0 ;;
        --ipv6) DO_IPV4=0; DO_IPV6=1 ;;
        --trace) DO_TRACE=1 ;;
        --trace-mode) TRACE_MODE="$2"; shift;;
        --trace-parallel) TRACE_PARALLEL="$2"; shift;;
        --hops) MAX_HOPS="$2"; shift;;
        --trace-timeout) TRACE_TIMEOUT="$2"; shift;;
        --no-hop-asn) DO_HOP_ASN=0 ;;
        --ct) DO_CT=1 ;;
        --ct-timeout) CT_TIMEOUT="$2"; shift;;
        --tls) DO_TLS=1 ;;
        --tls-mode) TLS_MODE="$2"; shift;;
        --tls-port) TLS_PORT="$2"; shift;;
        --tls-timeout) TLS_TIMEOUT="$2"; shift;;
        --tls-parallel) TLS_PARALLEL="$2"; shift;;
        --version-detect) DO_VERSION=1 ;;
        --version-mode) VERSION_MODE="$2"; shift;;
        --version-ports) VERSION_PORTS="$2"; shift;;
        --version-timeout) VERSION_TIMEOUT="$2"; shift;;
        --version-parallel) VERSION_PARALLEL="$2"; shift;;
        --cve) DO_CVE=1 ;;
        --cve-api) CVE_API="$2"; shift;;
        --cve-timeout) CVE_TIMEOUT="$2"; shift;;
        --cve-total-timeout) CVE_TOTAL_TIMEOUT="$2"; shift;;
        --cve-min-severity) CVE_MIN_SEVERITY="$2"; shift;;
        --json) DO_JSON=1 ;;
        --quiet) QUIET_MODE=1 ;;
        --debug) DEBUG_MODE=1 ;;
        --no-color) NO_COLOR=1 ;;
        --profile) SCAN_PROFILE="$2"; shift;;
        --cloud-detect) DO_CLOUD_DETECT=1 ;;
        --http-security) DO_HTTP_SECURITY=1 ;;
        --http-security-mode) HTTP_SECURITY_MODE="$2"; shift;;
        --http-security-ports) HTTP_SECURITY_PORTS="$2"; shift;;
        --http-security-parallel) HTTP_SECURITY_PARALLEL="$2"; shift;;
        --port-scan) DO_PORT_SCAN=1 ;;
        --port-scan-mode) PORT_SCAN_MODE="$2"; shift;;
        --port-scan-parallel) PORT_SCAN_PARALLEL="$2"; shift;;
        --port-scan-timeout) PORT_SCAN_TIMEOUT="$2"; shift;;
        --port-scan-ports) PORT_SCAN_PORTS="$2"; shift;;
        --port-scan-top) PORT_SCAN_TOP_PORTS="$2"; shift;;
        --port-scan-method) PORT_SCAN_METHOD="$2"; shift;;
        --leak-scan) DO_LEAK_SCAN=1 ;;
        --leak-mode) LEAK_MODE="$2"; shift;;
        --leak-parallel) LEAK_PARALLEL="$2"; shift;;
        --leak-timeout) LEAK_TIMEOUT="$2"; shift;;
        --leak-ports) LEAK_PORTS="$2"; shift;;
        --leak-no-banners) LEAK_CHECK_BANNERS=0 ;;
        --export-full-indicators) EXPORT_FULL_INDICATORS=1 ;;
        --export-raw-credentials) EXPORT_RAW_CREDENTIALS=1 ;;
        --export-retention-days) EXPORT_RETENTION_DAYS="$2"; shift;;
        --webhook) DO_WEBHOOKS=1; WEBHOOK_URL="$2"; shift;;
        --webhook-type) WEBHOOK_TYPE="$2"; shift;;
        --webhook-events) WEBHOOK_EVENTS="$2"; shift;;
        --webhook-severity) WEBHOOK_SEVERITY="$2"; shift;;
        --siem) DO_SIEM=1; SIEM_TYPE="$2"; shift;;
        --siem-host) SIEM_HOST="$2"; shift;;
        --siem-token) SIEM_TOKEN="$2"; shift;;
        --siem-index) SIEM_INDEX="$2"; shift;;
        --siem-protocol) SIEM_PROTOCOL="$2"; shift;;
        --database) DO_DATABASE=1;;
        --db-type) DB_TYPE="$2"; shift;;
        --db-file) DB_FILE="$2"; shift;;
        --db-host) DB_HOST="$2"; shift;;
        --db-port) DB_PORT="$2"; shift;;
        --db-name) DB_NAME="$2"; shift;;
        --db-user) DB_USER="$2"; shift;;
        --db-pass) DB_PASS="$2"; shift;;
        --diff) DO_DIFF=1; DIFF_BASELINE="$2"; shift;;
        --diff-dir) DIFF_DIR="$2"; shift;;
        --diff-no-alert) DIFF_ALERT_NEW_CRITICAL=0;;
        --generate-config) generate_example_config; exit 0 ;;
        --asn-range)
            ASN_RANGE_MODE=1
            ASN_START=$(echo "$2" | cut -d- -f1 | sed 's/AS//g')
            ASN_END=$(echo "$2" | cut -d- -f2 | sed 's/AS//g')
            shift
            ;;
        --fetch-prefixes) FETCH_PREFIXES=1 ;;
        --asn-parallel) ASN_PARALLEL="$2"; shift;;
        *) 
            if [ "$ASN_RANGE_MODE" -eq 0 ]; then
                ASN="$1"
            fi
            ;;
    esac
    shift
done

# Load config file (if exists)
load_config_file

# Initialize colors
init_colors

# Apply scan profile if specified (profile overrides config file)
apply_scan_profile

# Validate ASN or ASN range provided
if [ "$ASN_RANGE_MODE" -eq 1 ]; then
    [ -z "$ASN_START" ] || [ -z "$ASN_END" ] && log_error "Invalid ASN range format. Use: --asn-range AS1-AS2" && exit 1
    [ "$ASN_START" -gt "$ASN_END" ] && log_error "ASN range start must be less than end" && exit 1
    log_info "ASN Range Mode: AS$ASN_START to AS$ASN_END"
else
    [ -z "$ASN" ] && log_error "ASN missing. Use -h for help or --asn-range for range scanning." && exit 1
fi

# Validate version mode
case "$VERSION_MODE" in
    ptr|all|gateway) ;;
    *) log_error "Invalid --version-mode. Use: ptr, all, or gateway" && exit 1 ;;
esac

# Validate CVE API
case "$CVE_API" in
    nvd|vulners|cveorg|all) ;;
    *) echo "Error: Invalid --cve-api. Use: nvd, vulners, cveorg, or all" && exit 1 ;;
esac

# Validate severity
case "$CVE_MIN_SEVERITY" in
    LOW|MEDIUM|HIGH|CRITICAL) ;;
    *) echo "Error: Invalid --cve-min-severity. Use: LOW, MEDIUM, HIGH, or CRITICAL" && exit 1 ;;
esac

# Validate trace mode
case "$TRACE_MODE" in
    ptr|all|gateway) ;;
    *) echo "Error: Invalid --trace-mode. Use: ptr, all, or gateway" && exit 1 ;;
esac

# Validate TLS mode
case "$TLS_MODE" in
    ptr|all|gateway) ;;
    *) echo "Error: Invalid --tls-mode. Use: ptr, all, or gateway" && exit 1 ;;
esac

# Show banner with ASCII art
echo
print_ascii_banner
echo

# Check for enterprise flags and warn user
if [ -n "$ENTERPRISE_FLAGS_USED" ]; then
    echo
    echo "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo "${BOLD}${YELLOW}⚠  ENTERPRISE FEATURES DETECTED${NC}"
    echo "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo
    echo "The following flags are only available in Enterprise Edition:"
    echo
    for flag in $ENTERPRISE_FLAGS_USED; do
        echo "  ${RED}✗${NC} $flag"
    done
    echo
    echo "These features are ${BOLD}not available${NC} in the Open Source edition."
    echo
    echo "${BOLD}Available in Enterprise:${NC}"
    echo "  • Webhook notifications (Slack, Discord, Teams, PagerDuty)"
    echo "  • SIEM integration (Splunk, Elasticsearch, QRadar, etc.)"
    echo "  • Database tracking (PostgreSQL, MySQL, SQLite)"
    echo "  • Diff mode (change detection & trending)"
    echo "  • ASN range scanning (batch processing)"
    echo
    echo "${CYAN}Learn more: https://asnspy.com/enterprise${NC}"
    echo
    echo "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo
    
    # Ask user if they want to proceed
    if [ "$AUTO_CONFIRM" -eq 0 ]; then
        printf "${BOLD}Proceed with scan WITHOUT these enterprise features? (y/n):${NC} "
        read -r RESPONSE
        case "$RESPONSE" in
            y|Y|yes|YES)
                echo
                echo "Continuing with Open Source features only..."
                echo
                ;;
            *)
                echo
                echo "Scan cancelled."
                echo
                exit 0
                ;;
        esac
    else
        echo "Auto-confirm enabled - continuing with Open Source features only..."
        echo
    fi
fi

# Check dependencies
check_deps

# =============================
# Generate hash for unique scan config
# =============================
generate_scan_hash() {
    # Create a string representing all scan parameters
    PARAMS="${ASN}_${SWEEP_START}_${SWEEP_END}_${PREFIX_START}_${PREFIX_END}_${PARALLEL}"
    PARAMS="${PARAMS}_${SKIP_PTR}_${SKIP_DEAD}_${MODE_INTERNET_ONLY}_${MODE_STRICT_VALID}_${MODE_GATEWAY_ONLY}"
    PARAMS="${PARAMS}_${DO_IPV4}_${DO_IPV6}_${DO_TRACE}_${TRACE_MODE}_${TRACE_PARALLEL}_${MAX_HOPS}"
    PARAMS="${PARAMS}_${DO_CT}_${CT_TIMEOUT}_${DO_HOP_ASN}"
    PARAMS="${PARAMS}_${DO_TLS}_${TLS_MODE}_${TLS_PORT}_${TLS_PARALLEL}"
    
    # Generate 8-character hash using md5
    echo "$PARAMS" | md5sum 2>/dev/null | cut -c1-8 || echo "$PARAMS" | md5 2>/dev/null | cut -c1-8
}

SCAN_HASH=$(generate_scan_hash)
SCANS_DIR="scans"

# Set output directory based on mode
if [ "$ASN_RANGE_MODE" -eq 1 ]; then
    OUTDIR="$SCANS_DIR/ASN_RANGE_${ASN_START}-${ASN_END}_${SCAN_HASH}"
else
    OUTDIR="$SCANS_DIR/${ASN}_${SCAN_HASH}"
fi

# Create scans directory if it doesn't exist
mkdir -p "$SCANS_DIR"
mkdir -p "$OUTDIR"

# =============================
# Update scan metadata with completion time
# =============================
update_scan_metadata_completion() {
    META_FILE="$OUTDIR/scan_metadata.txt"
    if [ -f "$META_FILE" ]; then
        echo "" >> "$META_FILE"
        echo "Scan Completion:" >> "$META_FILE"
        echo "  End Time:           $(date '+%Y-%m-%d %H:%M:%S %Z')" >> "$META_FILE"
    fi
}

# =============================
# Save scan metadata
# =============================
save_scan_metadata() {
    META_FILE="$OUTDIR/scan_metadata.txt"
    cat > "$META_FILE" <<EOF
ASNSPY v$VERSION - Scan Metadata
================================

Scan Information:
  ASN:                $ASN
  Scan Hash:          $SCAN_HASH
  Start Time:         $(date '+%Y-%m-%d %H:%M:%S %Z')
  Output Directory:   $OUTDIR

Scan Parameters:
  Host Range:         $SWEEP_START-$SWEEP_END
  Prefix Range:       $PREFIX_START-$PREFIX_END
  Parallel PTR:       $PARALLEL
  Skip PTR:           $([ "$SKIP_PTR" -eq 1 ] && echo "Yes" || echo "No")
  Skip Dead:          $([ "$SKIP_DEAD" -eq 1 ] && echo "Yes" || echo "No")
  Internet Only:      $([ "$MODE_INTERNET_ONLY" -eq 1 ] && echo "Yes" || echo "No")
  Strict Valid:       $([ "$MODE_STRICT_VALID" -eq 1 ] && echo "Yes" || echo "No")
  Gateway Only:       $([ "$MODE_GATEWAY_ONLY" -eq 1 ] && echo "Yes" || echo "No")

Protocol Settings:
  IPv4:               $([ "$DO_IPV4" -eq 1 ] && echo "Enabled" || echo "Disabled")
  IPv6:               $([ "$DO_IPV6" -eq 1 ] && echo "Enabled" || echo "Disabled")

Traceroute Settings:
  Enabled:            $([ "$DO_TRACE" -eq 1 ] && echo "Yes" || echo "No")
  Mode:               $TRACE_MODE
  Parallel:           $TRACE_PARALLEL
  Max Hops:           $MAX_HOPS
  Timeout (sec):      $TRACE_TIMEOUT
  ASN Lookup:         $([ "$DO_HOP_ASN" -eq 1 ] && echo "Enabled" || echo "Disabled")

Certificate Transparency:
  Enabled:            $([ "$DO_CT" -eq 1 ] && echo "Yes" || echo "No")
  Timeout (sec):      $([ "$CT_TIMEOUT" -eq 0 ] && echo "None (unlimited)" || echo "$CT_TIMEOUT")

TLS Certificate Scan:
  Enabled:            $([ "$DO_TLS" -eq 1 ] && echo "Yes" || echo "No")
  Mode:               $TLS_MODE
  Port:               $TLS_PORT
  Parallel:           $TLS_PARALLEL
  Timeout (sec):      $TLS_TIMEOUT

Command Line:
  ./asnspy.sh $ORIGINAL_ARGS

================================
EOF
    
    log_info "Scan metadata saved to: $META_FILE"
}

# Save original command line args (moved to before parsing)
# ORIGINAL_ARGS is set before the CLI parser

# =============================
# Generate folder name (legacy - kept for compatibility)
# =============================
SCAN_ID="full"
[ "$SKIP_DEAD" -eq 1 ] && SCAN_ID="${SCAN_ID}__no-dead"
[ "$MODE_INTERNET_ONLY" -eq 1 ] && SCAN_ID="${SCAN_ID}__internet-only"
[ "$MODE_STRICT_VALID" -eq 1 ] && SCAN_ID="${SCAN_ID}__strict"
[ "$MODE_GATEWAY_ONLY" -eq 1 ] && SCAN_ID="${SCAN_ID}__gateway-only"
[ "$DO_IPV6" -eq 1 ] && [ "$DO_IPV4" -eq 0 ] && SCAN_ID="${SCAN_ID}__ipv6"
[ "$DO_IPV4" -eq 1 ] && [ "$DO_IPV6" -eq 0 ] && SCAN_ID="${SCAN_ID}__ipv4"
[ "$SWEEP_START" -ne 1 ] || [ "$SWEEP_END" -ne 255 ] && SCAN_ID="${SCAN_ID}__host_${SWEEP_START}-${SWEEP_END}"
[ "$PARALLEL" -gt 1 ] && SCAN_ID="${SCAN_ID}__p${PARALLEL}"
[ "$PREFIX_START" -ne 0 ] || [ "$PREFIX_END" -ne 255 ] && SCAN_ID="${SCAN_ID}__prefix_${PREFIX_START}-${PREFIX_END}"
[ "$DO_TRACE" -eq 1 ] && SCAN_ID="${SCAN_ID}__trace-${TRACE_MODE}"
[ "$DO_CT" -eq 1 ] && SCAN_ID="${SCAN_ID}__ct"

# Note: OUTDIR is now set above as ${ASN}_${SCAN_HASH}
# SCAN_ID kept for reference but not used in directory name

PREFIX_FILE="$OUTDIR/prefixes.txt"
PTR_FILE="$OUTDIR/ptr_results.txt"
DOMAIN_FILE="$OUTDIR/domains.txt"
CT_FILE="$OUTDIR/ct_results.txt"
TRACE_FILE="$OUTDIR/traceroute_results.txt"
TRACE_SUMMARY="$OUTDIR/traceroute_summary.txt"
TRACE_TOPOLOGY="$OUTDIR/traceroute_topology.txt"
TLS_FILE="$OUTDIR/tls_results.txt"
TLS_CSV="$OUTDIR/tls_certificates.csv"
TLS_ISSUES="$OUTDIR/tls_issues.txt"
TLS_CHAINS="$OUTDIR/tls_chains.txt"
TLS_STATS="$OUTDIR/tls_statistics.txt"
TLS_SUMMARY="$OUTDIR/tls_summary.txt"
TLS_TARGETS="$OUTDIR/.tls_targets.tmp"
RESUME_FILE="$OUTDIR/resume.state"
TRACE_TARGETS="$OUTDIR/.trace_targets.tmp"
VERSION_CSV="$OUTDIR/server_versions.csv"
VERSION_SUMMARY="$OUTDIR/version_summary.txt"
VERSION_TARGETS="$OUTDIR/.version_targets.tmp"
CVE_CSV="$OUTDIR/vulnerabilities.csv"
CVE_SUMMARY="$OUTDIR/cve_summary.txt"
LEAK_CSV="$OUTDIR/leak_exposures.csv"
LEAK_SUMMARY="$OUTDIR/leak_summary.txt"
LEAK_TARGETS="$OUTDIR/.leak_targets.tmp"
PORT_SCAN_TARGETS="$OUTDIR/.port_scan_targets.tmp"
PORT_SCAN_CSV="$OUTDIR/port_scan_results.csv"
PORT_SCAN_SUMMARY="$OUTDIR/port_scan_summary.txt"
VERSION_FILE="$OUTDIR/server_versions.csv"
LEAK_CSV="$OUTDIR/leak_findings.csv"
LEAK_SUMMARY="$OUTDIR/leak_summary.txt"
LEAK_TARGETS="$OUTDIR/.leak_targets.tmp"
PORT_SCAN_TARGETS="$OUTDIR/.port_scan_targets.tmp"
PORT_SCAN_CSV="$OUTDIR/port_scan_results.csv"
PORT_SCAN_SUMMARY="$OUTDIR/port_scan_summary.txt"

# Create lock files for parallel mode
[ "$PARALLEL" -gt 1 ] && touch "$RESUME_FILE.lock"
[ "$TRACE_PARALLEL" -gt 1 ] && [ "$DO_TRACE" -eq 1 ] && touch "$TRACE_FILE.lock"
[ "$TLS_PARALLEL" -gt 1 ] && [ "$DO_TLS" -eq 1 ] && touch "$TLS_FILE.lock"

# =============================
# Utility: Get DNS tool
# =============================
get_dns_tool() {
    if command -v drill >/dev/null 2>&1; then
        echo "drill"
    elif command -v dig >/dev/null 2>&1; then
        echo "dig"
    fi
}

DNS_TOOL=$(get_dns_tool)

# =============================
# Utility: DNS Lookup
# =============================
dns_lookup() {
    IP="$1"
    if [ "$DNS_TOOL" = "drill" ]; then
        drill -x "$IP" 2>/dev/null | awk '/PTR/ && NF>4 {print $5}' | sed 's/\.$//' | head -1
    else
        dig +short -x "$IP" 2>/dev/null | sed 's/\.$//' | head -1
    fi
}

# =============================
# Octet filter
# =============================
filter_octet() {
    OCT="$1"
    [ "$SKIP_DEAD" -eq 1 ] && case "$OCT" in 0|127|255) return 1 ;; esac
    [ "$MODE_STRICT_VALID" -eq 1 ] && { [ "$OCT" -lt 2 ] && return 1; [ "$OCT" -gt 254 ] && return 1; }
    [ "$MODE_INTERNET_ONLY" -eq 1 ] && case "$OCT" in 0|1|127|254|255) return 1 ;; esac
    [ "$MODE_GATEWAY_ONLY" -eq 1 ] && { [ "$OCT" -eq 1 ] && return 0; [ "$OCT" -eq 254 ] && return 0; return 1; }
    return 0
}

# =============================
# Fetch prefixes
# =============================
fetch_prefixes() {
    log_info "Fetching prefixes for $ASN..."
    curl -4 -s "https://stat.ripe.net/data/announced-prefixes/data.json?resource=$ASN" \
        | jq -r '.data.prefixes // [] | .[].prefix' 2>/dev/null \
        | sort -u > "$PREFIX_FILE"

    if [ ! -s "$PREFIX_FILE" ]; then
        log_warning "No prefixes found from RIPE. Exiting."
        touch "$PTR_FILE" "$DOMAIN_FILE" "$CT_FILE"
        return 1
    fi

    # Apply prefix range filter
    if [ "$PREFIX_START" -ne 0 ] || [ "$PREFIX_END" -ne 255 ]; then
        TMP="$PREFIX_FILE.tmp"
        rm -f "$TMP"
        while read PREF; do
            case "$PREF" in
                *.*)
                    FIRST_OCT=$(echo "$PREF" | cut -d. -f1)
                    if [ "$FIRST_OCT" -ge "$PREFIX_START" ] && [ "$FIRST_OCT" -le "$PREFIX_END" ]; then
                        echo "$PREF" >> "$TMP"
                    fi
                    ;;
                *:*)
                    echo "$PREF" >> "$TMP"
                    ;;
            esac
        done < "$PREFIX_FILE"
        mv "$TMP" "$PREFIX_FILE"
    fi
    
    PCOUNT=$(wc -l < "$PREFIX_FILE")
    echo "[+] Found $PCOUNT prefixes to scan"
}

# =============================
# Resume helpers
# =============================
get_last_ip_for_prefix() {
    PREF="$1"
    [ ! -f "$RESUME_FILE" ] && echo "" && return
    grep "^$PREF=" "$RESUME_FILE" 2>/dev/null | cut -d= -f2
}

save_last_ip_for_prefix() {
    PREF="$1"
    IP="$2"
    grep -v "^$PREF=" "$RESUME_FILE" 2>/dev/null > "$RESUME_FILE.tmp" 2>/dev/null || true
    mv "$RESUME_FILE.tmp" "$RESUME_FILE" 2>/dev/null || true
    echo "$PREF=$IP" >> "$RESUME_FILE"
}

# =============================
# Resume message
# =============================
print_resume_message() {
    RESUME_FOUND=0
    if [ ! -s "$RESUME_FILE" ]; then
        log_info "Starting fresh scan..."
        return
    fi
    
    while read PREF; do
        LAST=$(get_last_ip_for_prefix "$PREF")
        [ -z "$LAST" ] && continue
        RESUME_FOUND=1
        log_warning "Resuming from last checkpoint..."
        return
    done < "$PREFIX_FILE"

    [ "$RESUME_FOUND" -eq 0 ] && log_info "Starting fresh scan..."
}

# =============================
# IPv4 sweep
# =============================
sweep_ipv4_seq() {
    PREF="$1"
    BLOCK=$(echo "$PREF" | cut -d/ -f1 | cut -d. -f1-3)
    LAST_IP=$(get_last_ip_for_prefix "$PREF")
    if [ -n "$LAST_IP" ]; then
        LAST_OCTET=$(echo "$LAST_IP" | cut -d. -f4)
        START=$((LAST_OCTET + 1))
    else
        START=$SWEEP_START
    fi

    if [ "$PARALLEL" -le 1 ]; then
        for i in $(seq $START $SWEEP_END); do
            filter_octet "$i" || continue
            IP="$BLOCK.$i"
            PTR=$(dns_lookup "$IP")
            if [ -n "$PTR" ]; then
                echo "$IP,$PTR" >> "$PTR_FILE"
                printf "%s -> %s\n" "$IP" "$PTR"
            else
                printf "%s -> -\n" "$IP"
            fi
            save_last_ip_for_prefix "$PREF" "$IP"
        done
        return
    fi

    export BLOCK PREF PTR_FILE RESUME_FILE DNS_TOOL
    seq $START $SWEEP_END | while read i; do filter_octet "$i" && echo "$i"; done | \
    xargs -P "$PARALLEL" -I{} sh -c '
        IP="$BLOCK.{}"
        if [ "$DNS_TOOL" = "drill" ]; then
            PTR=$(drill -x "$IP" 2>/dev/null | awk "/PTR/ && NF>4 {print \$5}" | sed "s/\\.\$//" | head -1)
        else
            PTR=$(dig +short -x "$IP" 2>/dev/null | sed "s/\\.\$//" | head -1)
        fi
        if [ -n "$PTR" ]; then
            echo "$IP,$PTR" >> "'"$PTR_FILE"'"
            printf "%s -> %s\n" "$IP" "$PTR"
        else
            printf "%s -> -\n" "$IP"
        fi
        (
            flock -x 200
            grep -v "^$PREF=" "'"$RESUME_FILE"'" 2>/dev/null > "'"$RESUME_FILE"'.tmp" 2>/dev/null || true
            mv "'"$RESUME_FILE"'.tmp" "'"$RESUME_FILE"'" 2>/dev/null || true
            echo "$PREF=$IP" >> "'"$RESUME_FILE"'"
        ) 200>"'"$RESUME_FILE"'.lock"
    '
}

# =============================
# IPv6 sweep
# =============================
sweep_ipv6_prefix() {
    PREF="$1"
    BASE=$(echo "$PREF" | cut -d/ -f1)
    MASK=$(echo "$PREF" | cut -d/ -f2)
    [ "$MASK" -lt 120 ] && { log_warning "IPv6 prefix too large: $PREF"; return; }
    
    LAST_HOST=$(get_last_ip_for_prefix "$PREF")
    if [ -n "$LAST_HOST" ]; then
        START=$((LAST_HOST + 1))
    else
        START=$SWEEP_START
    fi
    
    for i in $(seq $START $SWEEP_END); do
        HEX=$(printf "%x" "$i")
        IP="${BASE}${HEX}"
        
        PTR=$(dns_lookup "$IP")
        if [ -n "$PTR" ]; then
            echo "$IP,$PTR" >> "$PTR_FILE"
            printf "%s -> %s\n" "$IP" "$PTR"
        else
            printf "%s -> -\n" "$IP"
        fi
        save_last_ip_for_prefix "$PREF" "$i"
    done
}

# =============================
# Extract domains
# =============================
extract_domains() {
    [ ! -s "$PTR_FILE" ] && return
    log_info "Extracting domains from PTR records..."
    rm -f "$DOMAIN_FILE"
    while read LINE; do
        PTR=$(echo "$LINE" | awk -F, '{print $2}')
        [ -z "$PTR" ] && continue
        
        echo "$PTR" | grep -qi 'arpa$' && continue
        
        DOMAIN=$(echo "$PTR" | awk -F. '{if (NF>=2) print $(NF-1)"."$NF}')
        [ -z "$DOMAIN" ] && continue
        echo "$DOMAIN" | grep -q '\.' || continue
        
        echo "$DOMAIN" >> "$DOMAIN_FILE"
    done < "$PTR_FILE"
    
    if [ -s "$DOMAIN_FILE" ]; then
        sort -u "$DOMAIN_FILE" -o "$DOMAIN_FILE"
        DCOUNT=$(wc -l < "$DOMAIN_FILE")
        echo "[+] Extracted $DCOUNT unique domains"
    fi
}

# =============================
# Certificate Transparency scan
# =============================
full_ct_scan() {
    [ "$DO_CT" -eq 0 ] && return
    [ ! -s "$DOMAIN_FILE" ] && { log_warning "No domains to scan for CT logs"; return; }
    
    log_info "Starting Certificate Transparency scan..."
    if [ "$CT_TIMEOUT" -eq 0 ]; then
        log_warning "No timeout set - will wait indefinitely for each domain"
    else
        log_warning "Timeout: ${CT_TIMEOUT}s per domain"
    fi
    log_warning "Note: Large/popular domains may timeout or be skipped"
    rm -f "$CT_FILE"
    TOTAL=$(wc -l < "$DOMAIN_FILE")
    COUNT=0
    MAX_SIZE=5242880  # 5MB limit
    
    while read d; do
        COUNT=$((COUNT + 1))
        printf "\r[*] CT scan: %d/%d - %s                    " "$COUNT" "$TOTAL" "$d"
        
        # Build curl command with conditional timeout
        if [ "$CT_TIMEOUT" -gt 0 ]; then
            RESULT=$(curl -s --max-time "$CT_TIMEOUT" --max-filesize "$MAX_SIZE" \
                "https://crt.sh/?q=$d&output=json" 2>/dev/null)
        else
            RESULT=$(curl -s --max-filesize "$MAX_SIZE" \
                "https://crt.sh/?q=$d&output=json" 2>/dev/null)
        fi
        
        EXIT_CODE=$?
        
        if [ $EXIT_CODE -eq 0 ] && [ -n "$RESULT" ]; then
            # Limit to first 1000 results to avoid jq hanging
            echo "$RESULT" | jq -r 'limit(1000; .[].name_value)' 2>/dev/null | \
                sed 's/\*\.//g' >> "$CT_FILE"
        elif [ $EXIT_CODE -eq 28 ]; then
            printf " [timeout]"
        elif [ $EXIT_CODE -eq 63 ]; then
            printf " [too large, skipped]"
        else
            printf " [error]"
        fi
        
        sleep 2
    done < "$DOMAIN_FILE"
    echo
    
    if [ -s "$CT_FILE" ]; then
        sort -u "$CT_FILE" -o "$CT_FILE"
        CTCOUNT=$(wc -l < "$CT_FILE")
        echo "[+] Found $CTCOUNT unique CT subdomains"
    else
        log_warning "No CT subdomains found"
    fi
}

# =============================
# ASN Lookup for IP
# =============================
lookup_asn_for_ip() {
    IP="$1"
    [ "$DO_HOP_ASN" -eq 0 ] && echo "N/A,N/A" && return
    
    # Use Team Cymru DNS-based ASN lookup
    REVERSED=$(echo "$IP" | awk -F. '{print $4"."$3"."$2"."$1}')
    ASN_DATA=$(dig +short "$REVERSED.origin.asn.cymru.com" TXT 2>/dev/null | tr -d '"' | head -1)
    
    if [ -n "$ASN_DATA" ]; then
        HOP_ASN=$(echo "$ASN_DATA" | awk '{print $1}')
        HOP_ORG=$(echo "$ASN_DATA" | cut -d'|' -f5- | sed 's/^ *//')
        echo "$HOP_ASN,$HOP_ORG"
    else
        echo "N/A,N/A"
    fi
}

# =============================
# Single traceroute
# =============================
perform_traceroute() {
    TARGET="$1"
    IS_IPV6=$(echo "$TARGET" | grep -q ':' && echo 1 || echo 0)
    
    if [ "$IS_IPV6" -eq 1 ]; then
        TRACE_CMD="traceroute6"
        if ! command -v traceroute6 >/dev/null 2>&1; then
            log_warning "traceroute6 not available, skipping $TARGET"
            return
        fi
    else
        TRACE_CMD="traceroute"
    fi
    
    # Perform traceroute
    TRACE_OUT=$($TRACE_CMD -m "$MAX_HOPS" -w "$TRACE_TIMEOUT" -q 1 "$TARGET" 2>/dev/null)
    
    # Parse output
    echo "$TRACE_OUT" | grep -E '^ *[0-9]' | while read line; do
        HOP_NUM=$(echo "$line" | awk '{print $1}')
        HOP_IP=$(echo "$line" | awk '{for(i=2;i<=NF;i++) if($i ~ /^[0-9]/) {print $i; exit}}')
        HOP_HOSTNAME=$(echo "$line" | awk '{if($2 !~ /^[0-9]/ && $2 != "*") print $2; else print "-"}')
        RTT=$(echo "$line" | awk '{for(i=2;i<=NF;i++) if($i ~ /ms$/) {gsub(/ms/,"",$i); print $i; exit}}')
        
        [ -z "$HOP_IP" ] && HOP_IP="*"
        [ -z "$HOP_HOSTNAME" ] && HOP_HOSTNAME="-"
        [ -z "$RTT" ] && RTT="*"
        
        # Get ASN for this hop
        if [ "$HOP_IP" != "*" ]; then
            ASN_INFO=$(lookup_asn_for_ip "$HOP_IP")
        else
            ASN_INFO="N/A,N/A"
        fi
        
        HOP_ASN=$(echo "$ASN_INFO" | cut -d, -f1)
        HOP_ORG=$(echo "$ASN_INFO" | cut -d, -f2-)
        
        # Write to results
        echo "$TARGET,$HOP_NUM,$HOP_IP,$HOP_HOSTNAME,$RTT,$HOP_ASN,$HOP_ORG" >> "$TRACE_FILE"
    done
}

# =============================
# Build trace target list
# =============================
build_trace_targets() {
    rm -f "$TRACE_TARGETS"
    
    case "$TRACE_MODE" in
        ptr)
            # Only IPs with PTR records
            if [ -s "$PTR_FILE" ]; then
                cut -d, -f1 "$PTR_FILE" > "$TRACE_TARGETS"
            fi
            ;;
        gateway)
            # Only gateway IPs (.1 and .254)
            while read PREF; do
                case "$PREF" in
                    *.*)
                        BLOCK=$(echo "$PREF" | cut -d/ -f1 | cut -d. -f1-3)
                        echo "$BLOCK.1" >> "$TRACE_TARGETS"
                        echo "$BLOCK.254" >> "$TRACE_TARGETS"
                        ;;
                esac
            done < "$PREFIX_FILE"
            ;;
        all)
            # Every IP in scan ranges
            while read PREF; do
                case "$PREF" in
                    *.*)
                        BLOCK=$(echo "$PREF" | cut -d/ -f1 | cut -d. -f1-3)
                        for i in $(seq $SWEEP_START $SWEEP_END); do
                            filter_octet "$i" && echo "$BLOCK.$i" >> "$TRACE_TARGETS"
                        done
                        ;;
                    *:*)
                        BASE=$(echo "$PREF" | cut -d/ -f1)
                        for i in $(seq $SWEEP_START $SWEEP_END); do
                            HEX=$(printf "%x" "$i")
                            echo "${BASE}${HEX}" >> "$TRACE_TARGETS"
                        done
                        ;;
                esac
            done < "$PREFIX_FILE"
            ;;
    esac
    
    if [ -s "$TRACE_TARGETS" ]; then
        sort -u "$TRACE_TARGETS" -o "$TRACE_TARGETS"
    fi
}

# =============================
# Traceroute phase
# =============================
run_traceroute_phase() {
    [ "$DO_TRACE" -eq 0 ] && return
    
    log_header "Network Path Analysis"
    
    build_trace_targets
    
    if [ ! -s "$TRACE_TARGETS" ]; then
        log_warning "No targets to trace (empty target list)"
        return
    fi
    
    TRACE_COUNT=$(wc -l < "$TRACE_TARGETS")
    log_info "Traceroute mode: $TRACE_MODE"
    log_info "Targets to trace: $TRACE_COUNT"
    log_info "Max hops: $MAX_HOPS"
    log_info "Parallel traces: $TRACE_PARALLEL"
    [ "$DO_HOP_ASN" -eq 1 ] && log_info "ASN lookup: enabled" || log_info" ASN lookup: disabled"
    echo
    
    # Initialize trace file with header
    echo "target_ip,hop_num,hop_ip,hop_hostname,rtt_ms,hop_asn,hop_org" > "$TRACE_FILE"
    
    if [ "$TRACE_PARALLEL" -le 1 ]; then
        COUNT=0
        while read TARGET; do
            COUNT=$((COUNT + 1))
            printf "\r[*] Tracing: %d/%d - %s          " "$COUNT" "$TRACE_COUNT" "$TARGET"
            perform_traceroute "$TARGET"
        done < "$TRACE_TARGETS"
        echo
    else
        export MAX_HOPS TRACE_TIMEOUT DO_HOP_ASN TRACE_FILE
        cat "$TRACE_TARGETS" | xargs -P "$TRACE_PARALLEL" -I{} sh -c '
            TARGET="{}"
            IS_IPV6=$(echo "$TARGET" | grep -q ":" && echo 1 || echo 0)
            
            if [ "$IS_IPV6" -eq 1 ]; then
                TRACE_CMD="traceroute6"
                command -v traceroute6 >/dev/null 2>&1 || exit 0
            else
                TRACE_CMD="traceroute"
            fi
            
            TRACE_OUT=$($TRACE_CMD -m "$MAX_HOPS" -w "$TRACE_TIMEOUT" -q 1 "$TARGET" 2>/dev/null)
            
            echo "$TRACE_OUT" | grep -E "^ *[0-9]" | while read line; do
                HOP_NUM=$(echo "$line" | awk "{print \$1}")
                HOP_IP=$(echo "$line" | awk "{for(i=2;i<=NF;i++) if(\$i ~ /^[0-9]/) {print \$i; exit}}")
                HOP_HOSTNAME=$(echo "$line" | awk "{if(\$2 !~ /^[0-9]/ && \$2 != \"*\") print \$2; else print \"-\"}")
                RTT=$(echo "$line" | awk "{for(i=2;i<=NF;i++) if(\$i ~ /ms\$/) {gsub(/ms/,\"\",\$i); print \$i; exit}}")
                
                [ -z "$HOP_IP" ] && HOP_IP="*"
                [ -z "$HOP_HOSTNAME" ] && HOP_HOSTNAME="-"
                [ -z "$RTT" ] && RTT="*"
                
                if [ "$DO_HOP_ASN" -eq 1 ] && [ "$HOP_IP" != "*" ]; then
                    REVERSED=$(echo "$HOP_IP" | awk -F. "{print \$4\".\"\$3\".\"\$2\".\"\$1}")
                    ASN_DATA=$(dig +short "$REVERSED.origin.asn.cymru.com" TXT 2>/dev/null | tr -d "\"" | head -1)
                    if [ -n "$ASN_DATA" ]; then
                        HOP_ASN=$(echo "$ASN_DATA" | awk "{print \$1}")
                        HOP_ORG=$(echo "$ASN_DATA" | cut -d"|" -f5- | sed "s/^ *//")
                    else
                        HOP_ASN="N/A"
                        HOP_ORG="N/A"
                    fi
                else
                    HOP_ASN="N/A"
                    HOP_ORG="N/A"
                fi
                
                (
                    flock -x 200
                    echo "$TARGET,$HOP_NUM,$HOP_IP,$HOP_HOSTNAME,$RTT,$HOP_ASN,$HOP_ORG" >> "'"$TRACE_FILE"'"
                ) 200>"'"$TRACE_FILE"'.lock"
            done
            printf "."
        '
        echo
    fi
    
    echo "[+] Traceroute phase complete"
    
    # Generate summary
    generate_trace_summary
}

# =============================
# Generate trace summary
# =============================
generate_trace_summary() {
    [ ! -s "$TRACE_FILE" ] && return
    
    log_info "Generating traceroute analysis..."
    
    # Summary: paths per target
    {
        echo "==================================="
        echo "Traceroute Summary"
        echo "==================================="
        echo
        
        awk -F, 'NR>1 {targets[$1]++; if($6!="N/A") asns[$6]++} 
                 END {
                     print "Targets traced: " length(targets)
                     print "Unique ASNs discovered: " length(asns)
                 }' "$TRACE_FILE"
        echo
        echo "Top 10 ASNs by hop frequency:"
        awk -F, 'NR>1 && $6!="N/A" {count[$6" "$7]++} 
                 END {for(asn in count) print count[asn], asn}' "$TRACE_FILE" | \
            sort -rn | head -10 | awk '{printf "  %3d hops - AS%s %s\n", $1, $2, substr($0, index($0,$3))}'
    } > "$TRACE_SUMMARY"
    
    # Topology: unique paths
    {
        echo "==================================="
        echo "Network Topology - Unique Paths"
        echo "==================================="
        awk -F, 'NR>1 {path[$1]=path[$1]" -> "$3} 
                 END {for(t in path) print t": " substr(path[t],5)}' "$TRACE_FILE" | sort
    } > "$TRACE_TOPOLOGY"
    
    cat "$TRACE_SUMMARY"
    echo
}

# =============================
# Apply Parallel Value Inheritance
# =============================
apply_parallel_defaults() {
    # If phase-specific parallel is 0 (unset), inherit from main PARALLEL
    [ "$TRACE_PARALLEL" -eq 0 ] && TRACE_PARALLEL="$PARALLEL"
    [ "$TLS_PARALLEL" -eq 0 ] && TLS_PARALLEL="$PARALLEL"
    [ "$VERSION_PARALLEL" -eq 0 ] && VERSION_PARALLEL="$PARALLEL"
    [ "$HTTP_SECURITY_PARALLEL" -eq 0 ] && HTTP_SECURITY_PARALLEL="$PARALLEL"
    [ "$PORT_SCAN_PARALLEL" -eq 0 ] && PORT_SCAN_PARALLEL="$PARALLEL"
    [ "$LEAK_PARALLEL" -eq 0 ] && LEAK_PARALLEL="$PARALLEL"
    
    log_debug "Applied parallel defaults: PARALLEL=$PARALLEL"
    log_debug "  TRACE_PARALLEL=$TRACE_PARALLEL"
    log_debug "  TLS_PARALLEL=$TLS_PARALLEL"
    log_debug "  VERSION_PARALLEL=$VERSION_PARALLEL"
    log_debug "  HTTP_SECURITY_PARALLEL=$HTTP_SECURITY_PARALLEL"
    log_debug "  PORT_SCAN_PARALLEL=$PORT_SCAN_PARALLEL"
    log_debug "  LEAK_PARALLEL=$LEAK_PARALLEL"
}

# =============================
# Main workflow
# =============================
main() {
    # Apply parallel value inheritance
    apply_parallel_defaults
    
    # Check if in ASN range mode
    if [ "$ASN_RANGE_MODE" -eq 1 ]; then
        # ASN Range scan mode - different workflow
        run_asn_range_scan
        export_asn_range_json
        exit 0
    fi
    
    # Normal single ASN mode continues below
    # Save scan metadata at start
    save_scan_metadata
    
    # Send webhook notification for scan start
    
    # Initialize SIEM if enabled
    init_siem    
    # Initialize database if enabled
    if [ "$DO_DATABASE" -eq 1 ]; then
        init_database
        if [ $? -eq 0 ]; then
            # Create scan record
            db_insert_scan "$SCAN_HASH" "$ASN" "$SCAN_HASH" "$SCAN_PROFILE" "$OUTDIR"
    
    # Initialize diff mode if enabled
    init_diff_mode
        fi
    fi
    
        webhook_scan_start
    
    
    # Check authorizations for sensitive scans
    check_all_authorizations
    
    # Prompt for full indicator export if enabled
    prompt_full_indicator_export
    
    # Prompt for raw credential export if enabled (separate authorization)
    prompt_raw_credential_export
    
        log_header "ASN Intelligence Gathering"
    asn_whois
    fetch_prefixes || exit 0
    
    if [ "$SKIP_PTR" -eq 1 ]; then
        log_warning "PTR sweep skipped per user request."
        extract_domains
        full_ct_scan
        run_traceroute_phase
        print_final_summary
        exit 0
    fi
    
    log_header "Host Discovery & DNS Mapping"
    print_resume_message
    
    while read PREF; do
        case "$PREF" in
            *:*) [ "$DO_IPV6" -eq 1 ] && sweep_ipv6_prefix "$PREF" ;;
            *.*) [ "$DO_IPV4" -eq 1 ] && sweep_ipv4_seq "$PREF" ;;
        esac
    done < "$PREFIX_FILE"
    
    extract_domains
    full_ct_scan
    
    # Run all phases in order
    run_traceroute_phase      # PHASE 3
    run_tls_phase             # PHASE 4
    run_port_scan_phase       # PHASE 5 (Port Scanning)
    run_version_phase         # PHASE 6
    run_cve_phase             # PHASE 6
    enrich_ptr_with_cloud     # PHASE 7 (Cloud detection)
    run_http_security_phase   # PHASE 8 (HTTP Security)
    run_leak_detection_phase  # PHASE 9 (Leak Detection)
    
    # Export to JSON if requested (FINAL PHASE)
    export_json
    
    # Update metadata with completion time
    update_scan_metadata_completion
    
    
    # Run diff analysis if enabled
    if [ "$DO_DIFF" -eq 1 ]; then
        run_diff_analysis
    fi
    
    # Finalize database (import all data)
    if [ "$DO_DATABASE" -eq 1 ]; then
        SCAN_END=$(date +%s)
        DURATION=$((SCAN_END - $(date -d "$(grep 'Start Time:' $OUTDIR/scan_metadata.txt | cut -d: -f2- | xargs)" +%s 2>/dev/null || echo $SCAN_END)))
        db_finalize_scan "$SCAN_HASH" "$DURATION"
    fi
    
    # Cleanup old scans based on retention policy
    cleanup_old_scans
    
    print_final_summary
}

# =============================
# Final summary
# =============================
print_final_summary() {
    echo
    log_header "ASNSPY SCAN COMPLETE"
    echo "Output directory: $OUTDIR"
    echo
    echo "Results:"
    [ -f "$PREFIX_FILE" ] && echo "  Prefixes:       $(wc -l < "$PREFIX_FILE") networks"
    [ -f "$PTR_FILE" ] && echo "  PTR Records:    $(wc -l < "$PTR_FILE") entries"
    [ -f "$DOMAIN_FILE" ] && echo "  Domains:        $(wc -l < "$DOMAIN_FILE") unique"
    if [ "$DO_CT" -eq 1 ] && [ -f "$CT_FILE" ]; then
        echo "  CT Subdomains:  $(wc -l < "$CT_FILE") found"
    fi
    if [ -f "$TRACE_FILE" ] && [ "$DO_TRACE" -eq 1 ]; then
        TRACE_LINES=$(($(wc -l < "$TRACE_FILE") - 1))
        [ "$TRACE_LINES" -lt 0 ] && TRACE_LINES=0
        echo "  Trace Hops:     $TRACE_LINES recorded"
    fi
    if [ "$DO_TLS" -eq 1 ] && [ -f "$TLS_FILE" ]; then
        TLS_LINES=$(($(wc -l < "$TLS_FILE") - 1))
        [ "$TLS_LINES" -lt 0 ] && TLS_LINES=0
        echo "  TLS Scans:      $TLS_LINES completed"
    fi
    if [ "$DO_VERSION" -eq 1 ] && [ -f "$VERSION_CSV" ]; then
        VERSION_LINES=$(($(wc -l < "$VERSION_CSV") - 1))
        [ "$VERSION_LINES" -lt 0 ] && VERSION_LINES=0
        echo "  Version Scans:  $VERSION_LINES completed"
    fi
    if [ "$DO_CVE" -eq 1 ] && [ -f "$CVE_CSV" ]; then
        CVE_LINES=$(($(wc -l < "$CVE_CSV") - 1))
        [ "$CVE_LINES" -lt 0 ] && CVE_LINES=0
        echo "  CVEs Found:     $CVE_LINES vulnerabilities"
    fi
    echo
    echo "Files:"
    echo "  $PREFIX_FILE"
    echo "  $PTR_FILE"
    echo "  $DOMAIN_FILE"
    [ "$DO_CT" -eq 1 ] && echo "  $CT_FILE"
    [ "$DO_TRACE" -eq 1 ] && echo "  $TRACE_FILE"
    [ "$DO_TRACE" -eq 1 ] && echo "  $TRACE_SUMMARY"
    [ "$DO_TRACE" -eq 1 ] && echo "  $TRACE_TOPOLOGY"
    [ "$DO_TLS" -eq 1 ] && echo "  $TLS_FILE"
    [ "$DO_TLS" -eq 1 ] && echo "  $TLS_CSV"
    [ "$DO_TLS" -eq 1 ] && echo "  $TLS_ISSUES"
    [ "$DO_TLS" -eq 1 ] && echo "  $TLS_CHAINS"
    [ "$DO_TLS" -eq 1 ] && echo "  $TLS_STATS"
    [ "$DO_TLS" -eq 1 ] && echo "  $TLS_SUMMARY"
    [ "$DO_VERSION" -eq 1 ] && echo "  $VERSION_CSV"
    [ "$DO_VERSION" -eq 1 ] && echo "  $VERSION_SUMMARY"
    [ "$DO_CVE" -eq 1 ] && echo "  $CVE_CSV"
    [ "$DO_CVE" -eq 1 ] && echo "  $CVE_SUMMARY"
    echo "  $OUTDIR/asn_whois.txt"
    
    # Calculate scan duration for webhook
    if [ -f "$OUTDIR/scan_metadata.txt" ]; then
        START_TIME=$(grep "Start Time:" "$OUTDIR/scan_metadata.txt" | cut -d: -f2- | sed 's/^ *//')
        END_TIME=$(date '+%Y-%m-%d %H:%M:%S %Z')
        # Simple duration message
        DURATION="completed"
    else
        DURATION="unknown"
    fi
    
    # Send webhook notification for scan complete
    webhook_scan_complete "$DURATION"
    
    echo "========================================"
}

main
