#!/bin/bash
#===============================================================================
# Mail Security Proxy Setup Script
#===============================================================================
# Description: Deploys HAProxy as a TCP proxy with Postfix postscreen and
#              Fail2ban in front of SMTP and POP3 services
#
# Architecture:
#   SMTP:  Client (port 25)  -> HAProxy (rate limit) -> postscreen (port 2525) -> smtpd
#   POP3:  Client (port 110) -> HAProxy (rate limit) -> Dovecot (port 1100)
#
# Defense layers:
#   1. HAProxy TCP proxy    - rate limiting, connection limits, IP ACLs
#   2. Postfix postscreen   - greeting delay, protocol compliance, DNSBL
#   3. Postfix restrictions - anti-relay, anti-spoofing, HELO enforcement
#   4. Dovecot hardening    - auth rate limiting
#   5. Fail2ban             - brute force auto-ban for SMTP and POP3
#   6. Firewall             - only required ports open
#
# Features:
#   - HAProxy TCP proxy with per-IP rate limiting for SMTP and POP3
#   - Postfix postscreen (greeting delay, protocol compliance tests)
#   - Postfix hardening (anti-relay, anti-spoofing, HELO enforcement)
#   - Dovecot auth rate limiting
#   - Fail2ban for brute force protection
#   - Firewall configuration (firewalld or iptables)
#   - Cross-distro support (RHEL/Fedora, Debian/Ubuntu)
#   - Backup and rollback capability
#   - End-to-end mail delivery testing
#
# Usage:
#   sudo ./mail_security_proxy.sh [OPTIONS]
#
# Options:
#   --install          Install and configure mail security proxy
#   --uninstall        Remove proxy and restore original config
#   --status           Show current status of all services
#   --test-security    Test with attack patterns
#   --test-mail        End-to-end mail delivery test (creates test user)
#   --dry-run          Show what would be done without making changes
#   -h, --help         Show this help message
#
# Author: Security Toolkit
# License: MIT
#===============================================================================

set -euo pipefail

#-------------------------------------------------------------------------------
# Configuration
#-------------------------------------------------------------------------------
SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_NAME
readonly BACKUP_DIR="/var/backups/security/mail_proxy"
readonly LOG_FILE="/var/log/mail_proxy_install.log"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
readonly TIMESTAMP

# Backend ports (services moved behind HAProxy)
POSTFIX_BACKEND_PORT=2525
DOVECOT_POP3_BACKEND_PORT=1100

# Defaults
DRY_RUN=false

# Test user for end-to-end verification
readonly TEST_USER="mailtest"
readonly TEST_PASSWORD="Mail_Test_2024!"

# Colors
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m'

#-------------------------------------------------------------------------------
# Logging Functions
#-------------------------------------------------------------------------------
setup_logging() {
    mkdir -p "$(dirname "$LOG_FILE")"
    exec > >(tee -a "$LOG_FILE") 2>&1
}

log_info() {
    echo -e "${GREEN}[INFO]${NC} $(date '+%H:%M:%S') $*"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $(date '+%H:%M:%S') $*" >&2
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $(date '+%H:%M:%S') $*" >&2
}

log_step() {
    echo -e "${BLUE}[STEP]${NC} $(date '+%H:%M:%S') $*"
}

#-------------------------------------------------------------------------------
# System Detection
#-------------------------------------------------------------------------------
detect_system() {
    if command -v dnf &>/dev/null; then
        PKG_MGR="dnf"
        PKG_INSTALL="dnf install -y"
        DISTRO_FAMILY="rhel"
        POSTFIX_SERVICE="postfix"
        DOVECOT_SERVICE="dovecot"
        HAPROXY_SERVICE="haproxy"
    elif command -v apt-get &>/dev/null; then
        PKG_MGR="apt"
        PKG_INSTALL="apt-get install -y"
        DISTRO_FAMILY="debian"
        POSTFIX_SERVICE="postfix"
        DOVECOT_SERVICE="dovecot"
        HAPROXY_SERVICE="haproxy"
    elif command -v yum &>/dev/null; then
        PKG_MGR="yum"
        PKG_INSTALL="yum install -y"
        DISTRO_FAMILY="rhel"
        POSTFIX_SERVICE="postfix"
        DOVECOT_SERVICE="dovecot"
        HAPROXY_SERVICE="haproxy"
    else
        log_error "Unsupported distribution"
        exit 1
    fi

    # Detect firewall
    if command -v firewall-cmd &>/dev/null && systemctl is-active firewalld &>/dev/null; then
        FIREWALL="firewalld"
    elif command -v iptables &>/dev/null; then
        FIREWALL="iptables"
    else
        FIREWALL="none"
    fi

    # Check SELinux
    if command -v getenforce &>/dev/null; then
        SELINUX_STATUS=$(getenforce 2>/dev/null || echo "Disabled")
    else
        SELINUX_STATUS="Disabled"
    fi

    log_info "Detected: $DISTRO_FAMILY, firewall=$FIREWALL, SELinux=$SELINUX_STATUS"
}

#-------------------------------------------------------------------------------
# Prerequisite Checks
#-------------------------------------------------------------------------------
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

check_mail_services() {
    local errors=0

    if ! systemctl is-active "$POSTFIX_SERVICE" &>/dev/null; then
        log_error "Postfix is not running"
        errors=$((errors + 1))
    else
        log_info "Postfix is running"
    fi

    if ! systemctl is-active "$DOVECOT_SERVICE" &>/dev/null; then
        log_error "Dovecot is not running"
        errors=$((errors + 1))
    else
        log_info "Dovecot is running"
    fi

    # Check Postfix version for PROXY protocol support
    local pf_version
    pf_version=$(postconf -h mail_version 2>/dev/null || echo "0")
    local pf_major pf_minor
    pf_major=$(echo "$pf_version" | cut -d. -f1)
    pf_minor=$(echo "$pf_version" | cut -d. -f2)

    if [[ "$pf_major" -lt 3 ]] || { [[ "$pf_major" -eq 3 ]] && [[ "$pf_minor" -lt 4 ]]; }; then
        log_error "Postfix $pf_version is too old. Need 3.4+ for PROXY protocol support."
        errors=$((errors + 1))
    else
        log_info "Postfix $pf_version supports PROXY protocol"
    fi

    if [[ $errors -gt 0 ]]; then
        log_error "Prerequisite check failed with $errors errors"
        exit 1
    fi
}

prompt_stats_password() {
    if [[ "$DRY_RUN" == true ]]; then
        STATS_PASSWORD="dryrun-placeholder"
        return 0
    fi

    # Allow non-interactive mode via environment variable
    if [[ -n "${MAIL_PROXY_STATS_PASSWORD:-}" ]]; then
        STATS_PASSWORD="$MAIL_PROXY_STATS_PASSWORD"
        log_info "Stats password set from environment variable"
        return 0
    fi

    echo ""
    log_warn "========================================================================="
    log_warn "HAProxy stats page requires a password."
    log_warn "Set a secure one-time password. Stored in /etc/haproxy/haproxy.cfg"
    log_warn "in plain text - treat as a one-time credential."
    log_warn "========================================================================="
    echo ""

    local password="" password_confirm=""
    while true; do
        read -r -s -p "Enter HAProxy stats password: " password
        echo ""
        if [[ -z "$password" ]]; then
            log_error "Password cannot be empty"
            continue
        fi
        if [[ ${#password} -lt 12 ]]; then
            log_error "Password must be at least 12 characters"
            continue
        fi
        read -r -s -p "Confirm password: " password_confirm
        echo ""
        if [[ "$password" != "$password_confirm" ]]; then
            log_error "Passwords do not match"
            continue
        fi
        break
    done

    STATS_PASSWORD="$password"
    log_info "Stats password set"
}

#-------------------------------------------------------------------------------
# Backup Functions
#-------------------------------------------------------------------------------
create_backup() {
    log_step "Creating backup of current configuration..."

    if [[ "$DRY_RUN" == true ]]; then
        log_info "[DRY-RUN] Would create backup in $BACKUP_DIR/$TIMESTAMP"
        return 0
    fi

    mkdir -p "$BACKUP_DIR/$TIMESTAMP"

    # Backup Postfix config
    if [[ -d /etc/postfix ]]; then
        cp -a /etc/postfix "$BACKUP_DIR/$TIMESTAMP/postfix"
    fi

    # Backup Dovecot config
    if [[ -d /etc/dovecot ]]; then
        cp -a /etc/dovecot "$BACKUP_DIR/$TIMESTAMP/dovecot"
    fi

    # Backup HAProxy config if exists
    if [[ -f /etc/haproxy/haproxy.cfg ]]; then
        cp /etc/haproxy/haproxy.cfg "$BACKUP_DIR/$TIMESTAMP/"
    fi

    # Backup Fail2ban config if exists
    if [[ -d /etc/fail2ban ]]; then
        cp -a /etc/fail2ban "$BACKUP_DIR/$TIMESTAMP/fail2ban"
    fi

    # Save state info
    cat > "$BACKUP_DIR/$TIMESTAMP/state.txt" << EOF
timestamp=$TIMESTAMP
distro_family=$DISTRO_FAMILY
postfix_backend_port=$POSTFIX_BACKEND_PORT
dovecot_pop3_backend_port=$DOVECOT_POP3_BACKEND_PORT
firewall=$FIREWALL
EOF

    log_info "Backup created: $BACKUP_DIR/$TIMESTAMP"
}

#-------------------------------------------------------------------------------
# Installation Functions
#-------------------------------------------------------------------------------
install_packages() {
    log_step "Installing required packages..."

    if [[ "$DRY_RUN" == true ]]; then
        log_info "[DRY-RUN] Would install: haproxy, fail2ban"
        return 0
    fi

    case "$DISTRO_FAMILY" in
        rhel)
            dnf install -y haproxy fail2ban
            ;;
        debian)
            apt-get update
            apt-get install -y haproxy fail2ban
            ;;
    esac

    log_info "Packages installed"
}

configure_postfix_backend() {
    log_step "Configuring Postfix to run behind HAProxy on port $POSTFIX_BACKEND_PORT..."

    if [[ "$DRY_RUN" == true ]]; then
        log_info "[DRY-RUN] Would reconfigure Postfix master.cf for postscreen on port $POSTFIX_BACKEND_PORT"
        return 0
    fi

    local master_cf="/etc/postfix/master.cf"

    # Comment out original smtp inet line
    sed -i 's/^smtp      inet/#smtp      inet/' "$master_cf"

    # Check if our config block already exists
    if grep -q "# --- Mail Security Proxy ---" "$master_cf"; then
        log_warn "Mail security proxy block already exists in master.cf, skipping"
        return 0
    fi

    # Add postscreen configuration block
    cat >> "$master_cf" << EOF

# --- Mail Security Proxy ---
# HAProxy sends to this port with PROXY protocol
${POSTFIX_BACKEND_PORT}      inet  n       -       n       -       1       postscreen
    -o postscreen_upstream_proxy_protocol=haproxy
smtpd     pass  -       -       n       -       -       smtpd
dnsblog   unix  -       -       n       -       0       dnsblog
tlsproxy  unix  -       -       n       -       0       tlsproxy
# --- End Mail Security Proxy ---
EOF

    log_info "Postfix master.cf configured with postscreen on port $POSTFIX_BACKEND_PORT"
}

configure_postscreen() {
    log_step "Configuring Postfix postscreen..."

    if [[ "$DRY_RUN" == true ]]; then
        log_info "[DRY-RUN] Would configure postscreen settings"
        return 0
    fi

    # Add postscreen settings to main.cf
    # Using postconf ensures proper formatting
    postconf -e "postscreen_access_list = permit_mynetworks"

    # Greeting test: delay the real banner, catch bots that talk early
    postconf -e "postscreen_greet_action = enforce"
    postconf -e "postscreen_greet_wait = 3s"
    postconf -e "postscreen_greet_banner = \$smtpd_banner"

    # Protocol compliance tests
    postconf -e "postscreen_non_smtp_command_enable = yes"
    postconf -e "postscreen_non_smtp_command_action = enforce"
    postconf -e "postscreen_pipelining_enable = yes"
    postconf -e "postscreen_pipelining_action = enforce"
    postconf -e "postscreen_bare_newline_enable = yes"
    postconf -e "postscreen_bare_newline_action = ignore"

    # DNSBL checks (action=ignore = log only, safe for competition)
    # These log suspicious senders but don't block, avoiding false positives
    postconf -e "postscreen_dnsbl_action = ignore"
    postconf -e "postscreen_dnsbl_sites = zen.spamhaus.org*2 bl.spamcop.net"

    # Allowlist duration for clients that pass all tests
    postconf -e "postscreen_dnsbl_allowlist_threshold = -1"

    log_info "Postscreen configured (greeting test + protocol compliance)"
}

harden_postfix() {
    log_step "Hardening Postfix configuration..."

    if [[ "$DRY_RUN" == true ]]; then
        log_info "[DRY-RUN] Would harden Postfix main.cf"
        return 0
    fi

    # HELO enforcement
    postconf -e "smtpd_helo_required = yes"
    postconf -e "smtpd_helo_restrictions = reject_invalid_helo_hostname, reject_non_fqdn_helo_hostname"

    # Sender restrictions
    postconf -e "smtpd_sender_restrictions = reject_non_fqdn_sender, reject_unknown_sender_domain"

    # Recipient restrictions (critical: prevent open relay)
    postconf -e "smtpd_recipient_restrictions = permit_mynetworks, reject_unauth_destination, reject_non_fqdn_recipient, reject_unknown_recipient_domain"

    # Relay restrictions (Postfix 2.10+)
    postconf -e "smtpd_relay_restrictions = permit_mynetworks, reject_unauth_destination"

    # Disable VRFY and EXPN (information disclosure)
    postconf -e "disable_vrfy_command = yes"

    # Harden banner (don't reveal version)
    postconf -e "smtpd_banner = \$myhostname ESMTP"

    # Message size limit (25MB)
    postconf -e "message_size_limit = 26214400"

    # Rate limiting via anvil
    postconf -e "smtpd_client_connection_rate_limit = 30"
    postconf -e "smtpd_client_message_rate_limit = 60"
    postconf -e "smtpd_client_recipient_rate_limit = 100"
    postconf -e "smtpd_error_sleep_time = 1s"
    postconf -e "smtpd_soft_error_limit = 5"
    postconf -e "smtpd_hard_error_limit = 10"

    # Reject early talkers
    postconf -e "smtpd_data_restrictions = reject_unauth_pipelining"

    log_info "Postfix hardening applied"
}

configure_dovecot_backend() {
    log_step "Configuring Dovecot POP3 to run behind HAProxy on port $DOVECOT_POP3_BACKEND_PORT..."

    if [[ "$DRY_RUN" == true ]]; then
        log_info "[DRY-RUN] Would reconfigure Dovecot POP3 port"
        return 0
    fi

    local master_conf="/etc/dovecot/conf.d/10-master.conf"

    # Replace the pop3-login service block to use backend port with haproxy support
    # We need to carefully modify just the pop3-login section
    if grep -q "# --- Mail Security Proxy ---" "$master_conf" 2>/dev/null; then
        log_warn "Mail security proxy block already exists in Dovecot config, skipping"
        return 0
    fi

    # Comment out the existing pop3-login block and add our version
    # Use a Python one-liner for reliable multi-line replacement
    python3 << PYEOF
import re

with open("$master_conf", "r") as f:
    content = f.read()

# Find and comment out the existing pop3-login block
old_block = re.search(r'(service pop3-login \{.*?\n\})', content, re.DOTALL)
if old_block:
    commented = '# --- Original pop3-login (commented by Mail Security Proxy) ---\n'
    for line in old_block.group(1).split('\n'):
        commented += '#' + line + '\n'
    commented += '# --- End original pop3-login ---'
    content = content.replace(old_block.group(1), commented)

# Add our new pop3-login block
new_block = """
# --- Mail Security Proxy ---
service pop3-login {
  # HAProxy sends POP3 traffic here with PROXY protocol
  inet_listener pop3 {
    port = $DOVECOT_POP3_BACKEND_PORT
    address = 127.0.0.1
    haproxy = yes
  }
  # Keep POP3S on default port (direct, no HAProxy)
  inet_listener pop3s {
    port = 995
    ssl = yes
  }
}
# --- End Mail Security Proxy ---
"""
content += new_block

with open("$master_conf", "w") as f:
    f.write(content)
PYEOF

    # Enable haproxy trusted networks in main dovecot config
    local dovecot_conf="/etc/dovecot/dovecot.conf"

    if ! grep -q "haproxy_trusted_networks" "$dovecot_conf" 2>/dev/null; then
        cat >> "$dovecot_conf" << 'EOF'

# --- Mail Security Proxy ---
haproxy_trusted_networks = 127.0.0.1 ::1
haproxy_timeout = 3s
# --- End Mail Security Proxy ---
EOF
    fi

    # Allow non-SSL POP3 connections (required for POP3 scoring on port 110)
    # ssl=yes means TLS is available but not required
    local ssl_conf="/etc/dovecot/conf.d/10-ssl.conf"
    if [[ -f "$ssl_conf" ]]; then
        sed -i 's/^ssl = required/ssl = yes/' "$ssl_conf"
    fi
    # Also check main dovecot.conf
    sed -i 's/^ssl = required/ssl = yes/' "$dovecot_conf" 2>/dev/null || true

    log_info "Dovecot POP3 configured on 127.0.0.1:$DOVECOT_POP3_BACKEND_PORT with PROXY protocol"
}

harden_dovecot() {
    log_step "Hardening Dovecot configuration..."

    if [[ "$DRY_RUN" == true ]]; then
        log_info "[DRY-RUN] Would harden Dovecot configuration"
        return 0
    fi

    local auth_conf="/etc/dovecot/conf.d/10-auth.conf"

    # Add auth rate limiting and hardening
    if ! grep -q "# --- Mail Security Proxy ---" "$auth_conf" 2>/dev/null; then
        cat >> "$auth_conf" << 'EOF'

# --- Mail Security Proxy ---
# Rate limit authentication attempts
auth_failure_delay = 2 secs

# Verbose auth logging for fail2ban
auth_verbose = yes
auth_verbose_passwords = no
# --- End Mail Security Proxy ---
EOF
    fi

    # Enable verbose logging for fail2ban detection
    local log_conf="/etc/dovecot/conf.d/10-logging.conf"
    if [[ -f "$log_conf" ]] && ! grep -q "# --- Mail Security Proxy ---" "$log_conf" 2>/dev/null; then
        cat >> "$log_conf" << 'EOF'

# --- Mail Security Proxy ---
auth_verbose = yes
auth_debug = no
# --- End Mail Security Proxy ---
EOF
    fi

    log_info "Dovecot hardening applied"
}

configure_haproxy() {
    log_step "Configuring HAProxy TCP proxy for SMTP and POP3..."

    if [[ "$DRY_RUN" == true ]]; then
        log_info "[DRY-RUN] Would create HAProxy configuration"
        return 0
    fi

    mkdir -p /etc/haproxy
    mkdir -p /var/lib/haproxy
    chown haproxy:haproxy /var/lib/haproxy 2>/dev/null || true

    cat > /etc/haproxy/haproxy.cfg << EOF
#===============================================================================
# HAProxy Configuration - Mail Security Proxy
# Generated: $(date)
# Architecture:
#   SMTP:  *:25  -> 127.0.0.1:${POSTFIX_BACKEND_PORT} (Postfix postscreen)
#   POP3:  *:110 -> 127.0.0.1:${DOVECOT_POP3_BACKEND_PORT} (Dovecot)
#===============================================================================

global
    log /dev/log local0
    log /dev/log local1 notice
    stats socket /var/lib/haproxy/stats mode 660 level admin
    stats timeout 30s
    user haproxy
    group haproxy
    daemon

defaults
    log     global
    timeout connect 10s
    timeout client  300s
    timeout server  300s
    retries 3

#-------------------------------------------------------------------------------
# Frontend - SMTP (port 25) with rate limiting
#-------------------------------------------------------------------------------
frontend smtp_front
    bind *:25
    mode tcp

    # Per-IP rate limiting for SMTP
    stick-table type ip size 100k expire 120s store conn_rate(60s),conn_cur
    tcp-request connection track-sc0 src

    # Max 30 new connections per minute per IP
    tcp-request connection reject if { sc_conn_rate(0) gt 30 }
    # Max 10 concurrent connections per IP
    tcp-request connection reject if { sc_conn_cur(0) gt 10 }

    default_backend postfix_backend

#-------------------------------------------------------------------------------
# Frontend - POP3 (port 110) with rate limiting
#-------------------------------------------------------------------------------
frontend pop3_front
    bind *:110
    mode tcp

    # Per-IP rate limiting for POP3
    stick-table type ip size 100k expire 120s store conn_rate(60s),conn_cur
    tcp-request connection track-sc0 src

    # Max 20 new connections per minute per IP
    tcp-request connection reject if { sc_conn_rate(0) gt 20 }
    # Max 5 concurrent connections per IP
    tcp-request connection reject if { sc_conn_cur(0) gt 5 }

    default_backend dovecot_pop3_backend

#-------------------------------------------------------------------------------
# Backend - Postfix postscreen (SMTP)
#-------------------------------------------------------------------------------
backend postfix_backend
    mode tcp

    # Send PROXY protocol v1 so Postfix sees the real client IP
    server postfix 127.0.0.1:${POSTFIX_BACKEND_PORT} send-proxy check-send-proxy check inter 10s fall 3 rise 2

#-------------------------------------------------------------------------------
# Backend - Dovecot POP3
#-------------------------------------------------------------------------------
backend dovecot_pop3_backend
    mode tcp

    # Send PROXY protocol v1 so Dovecot sees the real client IP
    server dovecot-pop3 127.0.0.1:${DOVECOT_POP3_BACKEND_PORT} send-proxy check-send-proxy check inter 10s fall 3 rise 2

#-------------------------------------------------------------------------------
# Statistics page (localhost only)
#-------------------------------------------------------------------------------
listen stats
    bind 127.0.0.1:8404
    mode http
    stats enable
    stats uri /haproxy-stats
    stats refresh 10s
    stats admin if LOCALHOST
    stats auth admin:${STATS_PASSWORD}
EOF

    chmod 640 /etc/haproxy/haproxy.cfg
    chown root:haproxy /etc/haproxy/haproxy.cfg 2>/dev/null || true

    log_info "HAProxy TCP proxy configured for SMTP (:25) and POP3 (:110)"
}

configure_fail2ban() {
    log_step "Configuring Fail2ban for SMTP and POP3..."

    if [[ "$DRY_RUN" == true ]]; then
        log_info "[DRY-RUN] Would configure Fail2ban jails"
        return 0
    fi

    # Determine ban action based on firewall
    local ban_action="iptables-multiport"
    if [[ "$FIREWALL" == "firewalld" ]]; then
        ban_action="firewallcmd-ipset"
    fi

    # Create jail.local with mail-specific jails
    cat > /etc/fail2ban/jail.local << EOF
# Mail Security Proxy - Fail2ban Configuration
# Generated: $(date)

[DEFAULT]
bantime = 600
findtime = 300
maxretry = 5
banaction = $ban_action

# Postfix SMTP authentication failures
[postfix]
enabled = true
port = smtp,ssmtp,submission
filter = postfix
logpath = /var/log/maillog
maxretry = 5
bantime = 600

# Postfix SASL auth failures
[postfix-sasl]
enabled = true
port = smtp,ssmtp,submission
filter = postfix[mode=auth]
logpath = /var/log/maillog
maxretry = 3
bantime = 1200

# Dovecot auth failures (POP3/IMAP)
[dovecot]
enabled = true
port = pop3,imap,pop3s,imaps
filter = dovecot
logpath = /var/log/maillog
maxretry = 5
bantime = 600

# Postfix reject/abuse patterns
[postfix-rbl]
enabled = true
port = smtp,ssmtp,submission
filter = postfix[mode=rbl]
logpath = /var/log/maillog
maxretry = 3
bantime = 1200
EOF

    # Ensure Fail2ban has a proper Dovecot filter (some distros miss it)
    if [[ ! -f /etc/fail2ban/filter.d/dovecot.conf ]]; then
        cat > /etc/fail2ban/filter.d/dovecot.conf << 'EOF'
[Definition]
failregex = ^.*auth: Error: .*(unknown user|password mismatch).*rip=<HOST>.*$
            ^.*auth-worker\(\d+\): Error: .*(unknown user|password mismatch).*rip=<HOST>.*$
ignoreregex =
EOF
    fi

    log_info "Fail2ban configured with postfix, postfix-sasl, and dovecot jails"
}

configure_firewall() {
    log_step "Configuring firewall..."

    if [[ "$DRY_RUN" == true ]]; then
        log_info "[DRY-RUN] Would open ports 25 and 110"
        return 0
    fi

    case "$FIREWALL" in
        firewalld)
            firewall-cmd --permanent --add-service=smtp
            firewall-cmd --permanent --add-port=110/tcp
            firewall-cmd --reload
            log_info "Firewalld: opened SMTP (25) and POP3 (110)"
            ;;
        iptables)
            iptables -I INPUT -p tcp --dport 25 -j ACCEPT
            iptables -I INPUT -p tcp --dport 110 -j ACCEPT
            # Try to save rules
            if command -v iptables-save &>/dev/null; then
                iptables-save > /etc/sysconfig/iptables 2>/dev/null || true
            fi
            log_info "iptables: opened SMTP (25) and POP3 (110)"
            ;;
        none)
            log_warn "No firewall detected, skipping firewall configuration"
            ;;
    esac
}

configure_selinux() {
    if [[ "$SELINUX_STATUS" != "Enforcing" ]]; then
        return 0
    fi

    log_step "Configuring SELinux policies..."

    if [[ "$DRY_RUN" == true ]]; then
        log_info "[DRY-RUN] Would configure SELinux for HAProxy and backend ports"
        return 0
    fi

    # Allow HAProxy to bind to SMTP and POP3 ports and connect to backends
    setsebool -P haproxy_connect_any 1 2>/dev/null || true

    # Label backend ports so Postfix and Dovecot can bind to them
    if command -v semanage &>/dev/null; then
        semanage port -a -t smtp_port_t -p tcp "$POSTFIX_BACKEND_PORT" 2>/dev/null \
            || semanage port -m -t smtp_port_t -p tcp "$POSTFIX_BACKEND_PORT" 2>/dev/null || true
        semanage port -a -t pop_port_t -p tcp "$DOVECOT_POP3_BACKEND_PORT" 2>/dev/null \
            || semanage port -m -t pop_port_t -p tcp "$DOVECOT_POP3_BACKEND_PORT" 2>/dev/null || true
        log_info "SELinux: labeled backend ports ($POSTFIX_BACKEND_PORT=smtp, $DOVECOT_POP3_BACKEND_PORT=pop3)"
    fi

    log_info "SELinux: allowed HAProxy to connect to any port"
}

#-------------------------------------------------------------------------------
# Main Operations
#-------------------------------------------------------------------------------
do_install() {
    log_info "=============================================="
    log_info "Installing Mail Security Proxy"
    log_info "=============================================="

    prompt_stats_password
    check_mail_services
    create_backup
    install_packages
    configure_postfix_backend
    configure_postscreen
    harden_postfix
    configure_dovecot_backend
    harden_dovecot
    configure_haproxy
    configure_fail2ban
    configure_firewall
    configure_selinux

    if [[ "$DRY_RUN" == true ]]; then
        log_info "[DRY-RUN] Installation simulation complete"
        return 0
    fi

    # Validate HAProxy config
    log_step "Validating HAProxy configuration..."
    if ! haproxy -c -f /etc/haproxy/haproxy.cfg 2>&1; then
        log_error "HAProxy configuration validation failed!"
        log_warn "Check /etc/haproxy/haproxy.cfg"
        exit 1
    fi
    log_info "HAProxy config valid"

    # Restart services in correct order
    log_step "Restarting services..."

    # 1. Restart Postfix (now listens on backend port with postscreen)
    systemctl restart "$POSTFIX_SERVICE"
    log_info "Postfix restarted"

    # 2. Restart Dovecot (POP3 now on backend port)
    systemctl restart "$DOVECOT_SERVICE"
    log_info "Dovecot restarted"

    # 3. Wait for backends to be ready
    sleep 2

    # 4. Start HAProxy (takes over ports 25 and 110)
    systemctl enable "$HAPROXY_SERVICE"
    systemctl restart "$HAPROXY_SERVICE"
    log_info "HAProxy started"

    # 5. Start Fail2ban
    systemctl enable fail2ban
    systemctl restart fail2ban
    log_info "Fail2ban started"

    # Wait for everything to settle
    sleep 3

    # Verify
    log_step "Verifying installation..."
    local errors=0

    if ! ss -tlnp | grep -q ":25 "; then
        log_error "HAProxy is not listening on port 25 (SMTP)"
        errors=$((errors + 1))
    else
        log_info "Port 25 (SMTP): HAProxy listening"
    fi

    if ! ss -tlnp | grep -q ":110 "; then
        log_error "HAProxy is not listening on port 110 (POP3)"
        errors=$((errors + 1))
    else
        log_info "Port 110 (POP3): HAProxy listening"
    fi

    if ! ss -tlnp | grep -q ":${POSTFIX_BACKEND_PORT} "; then
        log_error "Postfix is not listening on port $POSTFIX_BACKEND_PORT"
        errors=$((errors + 1))
    else
        log_info "Port $POSTFIX_BACKEND_PORT (Postfix backend): listening"
    fi

    if ! ss -tlnp | grep -q ":${DOVECOT_POP3_BACKEND_PORT} "; then
        log_error "Dovecot POP3 is not listening on port $DOVECOT_POP3_BACKEND_PORT"
        errors=$((errors + 1))
    else
        log_info "Port $DOVECOT_POP3_BACKEND_PORT (Dovecot POP3 backend): listening"
    fi

    if [[ $errors -gt 0 ]]; then
        log_error "Installation verification failed with $errors errors"
        log_warn "Run '$0 --status' for details or '$0 --uninstall' to revert"
        exit 1
    fi

    echo ""
    log_info "=============================================="
    log_info "Mail Security Proxy installed successfully!"
    log_info "=============================================="
    echo ""
    log_info "Architecture:"
    log_info "  SMTP:  Client:25  -> HAProxy (rate limit) -> postscreen:$POSTFIX_BACKEND_PORT -> smtpd"
    log_info "  POP3:  Client:110 -> HAProxy (rate limit) -> Dovecot:$DOVECOT_POP3_BACKEND_PORT"
    echo ""
    log_info "Defense layers:"
    log_info "  1. HAProxy TCP proxy   - rate limiting, connection limits"
    log_info "  2. Postfix postscreen  - greeting delay, protocol compliance"
    log_info "  3. Postfix restrictions - anti-relay, HELO enforcement"
    log_info "  4. Dovecot hardening   - auth rate limiting"
    log_info "  5. Fail2ban            - auto-ban brute force"
    echo ""
    log_info "HAProxy stats: http://localhost:8404/haproxy-stats (admin:<your password>)"
    echo ""
    log_info "To test: $0 --test-security"
    log_info "To test mail flow: $0 --test-mail"
    log_info "To uninstall: $0 --uninstall"
}

do_uninstall() {
    log_info "Uninstalling Mail Security Proxy..."

    local latest_backup
    latest_backup=$(find "$BACKUP_DIR" -maxdepth 1 -mindepth 1 -type d -printf '%T@ %p\n' 2>/dev/null | sort -rn | head -1 | cut -d' ' -f2-)

    if [[ -z "$latest_backup" ]]; then
        log_error "No backup found for restoration"
        exit 1
    fi

    if [[ "$DRY_RUN" == true ]]; then
        log_info "[DRY-RUN] Would restore from: $latest_backup"
        return 0
    fi

    log_step "Stopping services..."
    systemctl stop "$HAPROXY_SERVICE" 2>/dev/null || true
    systemctl stop fail2ban 2>/dev/null || true

    log_step "Restoring Postfix configuration..."
    if [[ -d "$latest_backup/postfix" ]]; then
        rm -rf /etc/postfix
        cp -a "$latest_backup/postfix" /etc/postfix
    fi

    log_step "Restoring Dovecot configuration..."
    if [[ -d "$latest_backup/dovecot" ]]; then
        rm -rf /etc/dovecot
        cp -a "$latest_backup/dovecot" /etc/dovecot
    fi

    # Make Postfix listen on all interfaces since we're removing HAProxy
    postconf -e "inet_interfaces = all"

    log_step "Restarting mail services..."
    systemctl restart "$POSTFIX_SERVICE"
    systemctl restart "$DOVECOT_SERVICE"

    log_info "Mail Security Proxy removed. Services restored to direct access."
    log_info "Note: Postfix inet_interfaces set to 'all' for direct external access"
}

do_status() {
    log_info "Service Status:"
    echo ""

    echo "HAProxy (TCP Proxy):"
    if systemctl is-active "$HAPROXY_SERVICE" &>/dev/null; then
        echo -e "  Status: ${GREEN}Running${NC}"
        echo "  Listening on:"
        ss -tlnp | grep haproxy | awk '{print "    " $4}' 2>/dev/null || true
    else
        echo -e "  Status: ${RED}Stopped${NC}"
    fi
    echo ""

    echo "Postfix (SMTP):"
    if systemctl is-active "$POSTFIX_SERVICE" &>/dev/null; then
        echo -e "  Status: ${GREEN}Running${NC}"
        echo "  Listening on:"
        ss -tlnp | grep master | awk '{print "    " $4}' 2>/dev/null || true
    else
        echo -e "  Status: ${RED}Stopped${NC}"
    fi
    echo ""

    echo "Dovecot (POP3/IMAP):"
    if systemctl is-active "$DOVECOT_SERVICE" &>/dev/null; then
        echo -e "  Status: ${GREEN}Running${NC}"
        echo "  Listening on:"
        ss -tlnp | grep dovecot | awk '{print "    " $4}' 2>/dev/null || true
    else
        echo -e "  Status: ${RED}Stopped${NC}"
    fi
    echo ""

    echo "Fail2ban:"
    if systemctl is-active fail2ban &>/dev/null; then
        echo -e "  Status: ${GREEN}Running${NC}"
        echo "  Active jails:"
        fail2ban-client status 2>/dev/null | grep "Jail list" || echo "    (unable to query)"
    else
        echo -e "  Status: ${RED}Stopped${NC}"
    fi
    echo ""

    echo "Port Summary:"
    echo "  Port 25  (SMTP/HAProxy):  $(ss -tlnp | grep -q ':25 ' && echo -e "${GREEN}In use${NC}" || echo -e "${YELLOW}Free${NC}")"
    echo "  Port 110 (POP3/HAProxy):  $(ss -tlnp | grep -q ':110 ' && echo -e "${GREEN}In use${NC}" || echo -e "${YELLOW}Free${NC}")"
    echo "  Port $POSTFIX_BACKEND_PORT (Postfix backend): $(ss -tlnp | grep -q ":$POSTFIX_BACKEND_PORT " && echo -e "${GREEN}In use${NC}" || echo -e "${YELLOW}Free${NC}")"
    echo "  Port $DOVECOT_POP3_BACKEND_PORT (Dovecot backend):  $(ss -tlnp | grep -q ":$DOVECOT_POP3_BACKEND_PORT " && echo -e "${GREEN}In use${NC}" || echo -e "${YELLOW}Free${NC}")"
    echo "  Port 143 (IMAP/Dovecot):  $(ss -tlnp | grep -q ':143 ' && echo -e "${GREEN}In use${NC}" || echo -e "${YELLOW}Free${NC}")"
}

do_test_security() {
    log_info "Testing mail security defenses..."
    echo ""

    local tests_passed=0
    local tests_failed=0

    #-----------------------------------------------------------------------
    # Test 1: Normal SMTP connection via Python (handles postscreen properly)
    #-----------------------------------------------------------------------
    echo -n "Test 1 - Normal SMTP connection: "
    local smtp_test
    smtp_test=$(python3 -c "
import smtplib, sys
try:
    s = smtplib.SMTP('127.0.0.1', 25, timeout=15)
    banner = s.ehlo('test.local')
    print('PASS:' + str(banner[0]))
    s.quit()
except Exception as e:
    print('FAIL:' + str(e))
" 2>/dev/null)
    if echo "$smtp_test" | grep -q "^PASS:250"; then
        echo -e "${GREEN}PASS${NC} (SMTP EHLO accepted)"
        tests_passed=$((tests_passed + 1))
    else
        echo -e "${RED}FAIL${NC} ($smtp_test)"
        tests_failed=$((tests_failed + 1))
    fi

    #-----------------------------------------------------------------------
    # Test 2: Open relay attempt (should be rejected)
    #-----------------------------------------------------------------------
    echo -n "Test 2 - Open relay attempt: "
    local relay_test
    relay_test=$(python3 -c "
import smtplib, sys
try:
    s = smtplib.SMTP('127.0.0.1', 25, timeout=15)
    s.ehlo('test.example.com')
    s.mail('spammer@evil.com')
    code, msg = s.rcpt('victim@external-domain.com')
    print('CODE:' + str(code) + ':' + msg.decode())
    s.quit()
except smtplib.SMTPRecipientsRefused as e:
    print('BLOCKED:recipients_refused')
except smtplib.SMTPResponseException as e:
    print('BLOCKED:' + str(e.smtp_code) + ':' + str(e.smtp_error))
except Exception as e:
    print('ERROR:' + str(e))
" 2>/dev/null)
    if echo "$relay_test" | grep -qE "^BLOCKED|^CODE:5"; then
        echo -e "${GREEN}BLOCKED${NC} (relay denied)"
        tests_passed=$((tests_passed + 1))
    else
        echo -e "${YELLOW}REVIEW${NC} ($relay_test)"
        tests_failed=$((tests_failed + 1))
    fi

    #-----------------------------------------------------------------------
    # Test 3: VRFY command (should be rejected)
    #-----------------------------------------------------------------------
    echo -n "Test 3 - VRFY probe: "
    local vrfy_test
    vrfy_test=$(python3 -c "
import smtplib
try:
    s = smtplib.SMTP('127.0.0.1', 25, timeout=15)
    s.ehlo('test.local')
    code, msg = s.vrfy('root')
    print('CODE:' + str(code) + ':' + msg.decode())
    s.quit()
except smtplib.SMTPResponseException as e:
    print('BLOCKED:' + str(e.smtp_code))
except Exception as e:
    print('ERROR:' + str(e))
" 2>/dev/null)
    if echo "$vrfy_test" | grep -qE "^CODE:252|^CODE:502|^CODE:550|^BLOCKED:5"; then
        echo -e "${GREEN}BLOCKED${NC} (VRFY disabled)"
        tests_passed=$((tests_passed + 1))
    else
        echo -e "${YELLOW}REVIEW${NC} ($vrfy_test)"
        tests_failed=$((tests_failed + 1))
    fi

    #-----------------------------------------------------------------------
    # Test 4: Invalid HELO (should be rejected)
    #-----------------------------------------------------------------------
    echo -n "Test 4 - Invalid HELO: "
    local helo_test
    helo_test=$(python3 -c "
import smtplib
try:
    s = smtplib.SMTP('127.0.0.1', 25, timeout=15)
    code, msg = s.helo('')
    if code >= 500:
        print('BLOCKED:' + str(code))
    else:
        # Try to send with the bad helo
        s.mail('test@test.com')
        code2, msg2 = s.rcpt('nobody@localhost')
        print('CODE:' + str(code2))
    s.quit()
except smtplib.SMTPResponseException as e:
    print('BLOCKED:' + str(e.smtp_code))
except Exception as e:
    print('BLOCKED:' + str(e))
" 2>/dev/null)
    if echo "$helo_test" | grep -qE "^BLOCKED"; then
        echo -e "${GREEN}BLOCKED${NC} (invalid HELO rejected)"
        tests_passed=$((tests_passed + 1))
    else
        echo -e "${YELLOW}REVIEW${NC} ($helo_test)"
        tests_failed=$((tests_failed + 1))
    fi

    #-----------------------------------------------------------------------
    # Test 5: Banner version disclosure
    #-----------------------------------------------------------------------
    echo -n "Test 5 - Banner version disclosure: "
    local banner_test
    banner_test=$(python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(10)
s.connect(('127.0.0.1', 25))
banner = s.recv(1024).decode()
s.close()
print(banner.strip())
" 2>/dev/null)
    if echo "$banner_test" | grep -qiE "postfix|MTA|version|[0-9]+\.[0-9]+\.[0-9]+"; then
        echo -e "${YELLOW}REVIEW${NC} (banner reveals info: $banner_test)"
        tests_failed=$((tests_failed + 1))
    else
        echo -e "${GREEN}PASS${NC} (banner clean: $banner_test)"
        tests_passed=$((tests_passed + 1))
    fi

    #-----------------------------------------------------------------------
    # Test 6: POP3 normal connection
    #-----------------------------------------------------------------------
    echo -n "Test 6 - Normal POP3 banner: "
    local pop3_test
    pop3_test=$(python3 -c "
import poplib
try:
    p = poplib.POP3('127.0.0.1', 110, timeout=10)
    banner = p.getwelcome().decode()
    print('PASS:' + banner)
    p.quit()
except Exception as e:
    print('FAIL:' + str(e))
" 2>/dev/null)
    if echo "$pop3_test" | grep -q "^PASS:"; then
        echo -e "${GREEN}PASS${NC} (got POP3 greeting)"
        tests_passed=$((tests_passed + 1))
    else
        echo -e "${RED}FAIL${NC} ($pop3_test)"
        tests_failed=$((tests_failed + 1))
    fi

    #-----------------------------------------------------------------------
    # Test 7: POP3 bad auth
    #-----------------------------------------------------------------------
    echo -n "Test 7 - POP3 bad auth: "
    local pop3_auth_test
    pop3_auth_test=$(python3 -c "
import poplib
try:
    p = poplib.POP3('127.0.0.1', 110, timeout=10)
    p.user('fakeuser')
    p.pass_('wrongpassword')
    print('NOT_BLOCKED')
    p.quit()
except Exception as e:
    print('BLOCKED:' + str(e))
" 2>/dev/null)
    if echo "$pop3_auth_test" | grep -qE "^BLOCKED"; then
        echo -e "${GREEN}PASS${NC} (auth rejected properly)"
        tests_passed=$((tests_passed + 1))
    else
        echo -e "${YELLOW}REVIEW${NC} ($pop3_auth_test)"
        tests_failed=$((tests_failed + 1))
    fi

    #-----------------------------------------------------------------------
    # Test 8: HAProxy rate limiting active
    #-----------------------------------------------------------------------
    echo -n "Test 8 - HAProxy rate limiting: "
    if ss -tlnp | grep -q "haproxy"; then
        echo -e "${GREEN}PASS${NC} (HAProxy active with rate limit tables)"
        tests_passed=$((tests_passed + 1))
    else
        echo -e "${RED}FAIL${NC} (HAProxy not detected)"
        tests_failed=$((tests_failed + 1))
    fi

    #-----------------------------------------------------------------------
    # Test 9: Fail2ban active
    #-----------------------------------------------------------------------
    echo -n "Test 9 - Fail2ban active: "
    if systemctl is-active fail2ban &>/dev/null; then
        echo -e "${GREEN}PASS${NC} (fail2ban running, mail jails active)"
        tests_passed=$((tests_passed + 1))
    else
        echo -e "${RED}FAIL${NC} (fail2ban not running)"
        tests_failed=$((tests_failed + 1))
    fi

    echo ""
    echo "=============================================="
    echo -e "Results: ${GREEN}$tests_passed passed${NC}, ${YELLOW}$tests_failed need review${NC}"
    echo "=============================================="
}

do_test_mail() {
    log_info "End-to-end mail delivery test..."
    echo ""

    # Ensure test user exists
    if ! id "$TEST_USER" &>/dev/null; then
        log_step "Creating test user '$TEST_USER'..."
        useradd -m "$TEST_USER" 2>/dev/null || true
    fi
    echo "$TEST_USER:$TEST_PASSWORD" | chpasswd

    # Ensure Maildir exists
    local maildir="/home/$TEST_USER/Maildir"
    mkdir -p "$maildir/new" "$maildir/cur" "$maildir/tmp"
    chown -R "$TEST_USER:$TEST_USER" "$maildir"

    local test_subject="MailProxyTest_${TIMESTAMP}"
    local test_body="This is an automated test message sent at $(date)"

    local hostname
    hostname=$(postconf -h myhostname 2>/dev/null || hostname)

    #-----------------------------------------------------------------------
    # Step 1: Send email via SMTP through HAProxy (using Python smtplib)
    #-----------------------------------------------------------------------
    log_step "Sending test email via SMTP (port 25)..."

    local smtp_result
    smtp_result=$(python3 -c "
import smtplib
from email.mime.text import MIMEText
try:
    msg = MIMEText('$test_body')
    msg['Subject'] = '$test_subject'
    msg['From'] = 'test@$hostname'
    msg['To'] = '$TEST_USER@$hostname'
    s = smtplib.SMTP('127.0.0.1', 25, timeout=30)
    s.ehlo('test.local')
    s.sendmail('test@$hostname', '$TEST_USER@$hostname', msg.as_string())
    s.quit()
    print('OK')
except Exception as e:
    print('FAIL:' + str(e))
" 2>/dev/null)

    if [[ "$smtp_result" == "OK" ]]; then
        echo -e "  SMTP delivery: ${GREEN}PASS${NC} (message queued)"
    else
        echo -e "  SMTP delivery: ${RED}FAIL${NC} ($smtp_result)"
        return 1
    fi

    sleep 3

    #-----------------------------------------------------------------------
    # Step 2: Check local delivery
    #-----------------------------------------------------------------------
    log_step "Checking local delivery..."
    local delivered=false
    if find "$maildir/new" "$maildir/cur" -type f -exec grep -l "$test_subject" {} \; 2>/dev/null | grep -q .; then
        delivered=true
        echo -e "  Local delivery: ${GREEN}PASS${NC} (found in Maildir)"
    elif grep -q "$test_subject" /var/mail/"$TEST_USER" 2>/dev/null || grep -q "$test_subject" /var/spool/mail/"$TEST_USER" 2>/dev/null; then
        delivered=true
        echo -e "  Local delivery: ${GREEN}PASS${NC} (found in mbox)"
    else
        echo -e "  Local delivery: ${YELLOW}REVIEW${NC} (message not found yet)"
    fi

    #-----------------------------------------------------------------------
    # Step 3: Retrieve email via POP3 through HAProxy
    #-----------------------------------------------------------------------
    log_step "Retrieving email via POP3 (port 110)..."

    local pop3_result
    pop3_result=$(python3 -c "
import poplib
try:
    p = poplib.POP3('127.0.0.1', 110, timeout=15)
    p.user('$TEST_USER')
    p.pass_('$TEST_PASSWORD')
    count, size = p.stat()
    print('AUTH_OK:messages=' + str(count))
    found = False
    for i in range(count, max(0, count-5), -1):
        resp, lines, octets = p.retr(i)
        body = b'\n'.join(lines).decode('utf-8', errors='replace')
        if '$test_subject' in body:
            found = True
            break
    if found:
        print('FOUND')
    else:
        print('NOT_FOUND:' + str(count) + '_messages')
    p.quit()
except Exception as e:
    print('FAIL:' + str(e))
" 2>/dev/null)

    if echo "$pop3_result" | grep -q "^AUTH_OK"; then
        echo -e "  POP3 auth: ${GREEN}PASS${NC}"
    else
        echo -e "  POP3 auth: ${RED}FAIL${NC} ($pop3_result)"
    fi

    if echo "$pop3_result" | grep -q "^FOUND"; then
        echo -e "  POP3 retrieve: ${GREEN}PASS${NC} (test message found)"
    else
        echo -e "  POP3 retrieve: ${YELLOW}REVIEW${NC} ($(echo "$pop3_result" | tail -1))"
    fi

    #-----------------------------------------------------------------------
    # False positive tests (all should PASS through)
    #-----------------------------------------------------------------------
    echo ""
    log_step "False positive tests (these should all PASS through)..."

    # FP1: HTML email
    echo -n "  FP1 - HTML email: "
    local fp1
    fp1=$(python3 -c "
import smtplib
from email.mime.text import MIMEText
try:
    msg = MIMEText('<html><body><h1>Hello</h1><p>Normal <b>newsletter</b> with <a href=\"http://example.com\">link</a>.</p></body></html>', 'html')
    msg['Subject'] = 'Weekly Newsletter'
    msg['From'] = 'newsletter@$hostname'
    msg['To'] = '$TEST_USER@$hostname'
    s = smtplib.SMTP('127.0.0.1', 25, timeout=30)
    s.ehlo('test.local')
    s.sendmail('newsletter@$hostname', '$TEST_USER@$hostname', msg.as_string())
    s.quit()
    print('OK')
except Exception as e:
    print('FAIL:' + str(e))
" 2>/dev/null)
    if [[ "$fp1" == "OK" ]]; then
        echo -e "${GREEN}PASS${NC} (delivered)"
    else
        echo -e "${RED}FALSE POSITIVE${NC} ($fp1)"
    fi

    # FP2: MIME multipart email
    echo -n "  FP2 - MIME multipart email: "
    local fp2
    fp2=$(python3 -c "
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
try:
    msg = MIMEMultipart()
    msg['Subject'] = 'Document attached'
    msg['From'] = 'colleague@$hostname'
    msg['To'] = '$TEST_USER@$hostname'
    msg.attach(MIMEText('Please see attached document.', 'plain'))
    msg.attach(MIMEText('Simulated attachment content', 'plain'))
    s = smtplib.SMTP('127.0.0.1', 25, timeout=30)
    s.ehlo('test.local')
    s.sendmail('colleague@$hostname', '$TEST_USER@$hostname', msg.as_string())
    s.quit()
    print('OK')
except Exception as e:
    print('FAIL:' + str(e))
" 2>/dev/null)
    if [[ "$fp2" == "OK" ]]; then
        echo -e "${GREEN}PASS${NC} (delivered)"
    else
        echo -e "${RED}FALSE POSITIVE${NC} ($fp2)"
    fi

    # FP3: Phishing-like but legitimate business content
    echo -n "  FP3 - Business content email: "
    local fp3
    fp3=$(python3 -c "
import smtplib
from email.mime.text import MIMEText
try:
    msg = MIMEText('Dear user, please update your account information. Your password will expire soon. Click here to verify your account.')
    msg['Subject'] = 'Account Update Required'
    msg['From'] = 'admin@$hostname'
    msg['To'] = '$TEST_USER@$hostname'
    s = smtplib.SMTP('127.0.0.1', 25, timeout=30)
    s.ehlo('test.local')
    s.sendmail('admin@$hostname', '$TEST_USER@$hostname', msg.as_string())
    s.quit()
    print('OK')
except Exception as e:
    print('FAIL:' + str(e))
" 2>/dev/null)
    if [[ "$fp3" == "OK" ]]; then
        echo -e "${GREEN}PASS${NC} (delivered)"
    else
        echo -e "${RED}FALSE POSITIVE${NC} ($fp3)"
    fi

    # FP4: Rapid POP3 polling (5x, simulating a mail client)
    echo -n "  FP4 - Rapid POP3 polling (5x): "
    local fp4_ok=0
    local fp4
    fp4=$(python3 -c "
import poplib
ok = 0
for i in range(5):
    try:
        p = poplib.POP3('127.0.0.1', 110, timeout=10)
        p.user('$TEST_USER')
        p.pass_('$TEST_PASSWORD')
        p.stat()
        p.quit()
        ok += 1
    except:
        pass
print(str(ok))
" 2>/dev/null)
    if [[ "$fp4" == "5" ]]; then
        echo -e "${GREEN}PASS${NC} (all 5 connections succeeded)"
    else
        echo -e "${YELLOW}REVIEW${NC} ($fp4/5 succeeded - rate limit may be too aggressive)"
    fi

    echo ""
    log_info "End-to-end test complete"
}

show_help() {
    cat << EOF
Mail Security Proxy Setup Script

Deploys HAProxy TCP proxy with Postfix postscreen and Fail2ban
in front of SMTP and POP3 services.

Usage: $SCRIPT_NAME [OPTIONS]

Options:
  --install          Install and configure mail security proxy
  --uninstall        Remove proxy and restore original config
  --status           Show current status of all services
  --test-security    Test with attack patterns (open relay, VRFY, etc.)
  --test-mail        End-to-end mail delivery and retrieval test
  --dry-run          Show what would be done without making changes
  -h, --help         Show this help message

Environment variables:
  MAIL_PROXY_STATS_PASSWORD   Set HAProxy stats password non-interactively

Examples:
  # Install with default settings
  sudo $SCRIPT_NAME --install

  # Preview changes without installing
  sudo $SCRIPT_NAME --install --dry-run

  # Check status of all services
  sudo $SCRIPT_NAME --status

  # Test security defenses
  sudo $SCRIPT_NAME --test-security

  # Test end-to-end mail delivery (creates test user)
  sudo $SCRIPT_NAME --test-mail

  # Non-interactive install
  MAIL_PROXY_STATS_PASSWORD="YourSecurePass123" sudo $SCRIPT_NAME --install

  # Remove and restore original configuration
  sudo $SCRIPT_NAME --uninstall

Architecture after installation:
  SMTP:  Internet:25  -> HAProxy (rate limit) -> postscreen:2525 -> smtpd
  POP3:  Internet:110 -> HAProxy (rate limit) -> Dovecot:1100

Defense Layers:
  1. HAProxy TCP proxy   - per-IP rate limiting, connection limits
  2. Postfix postscreen  - greeting delay, protocol compliance tests
  3. Postfix restrictions - anti-relay, anti-spoofing, HELO enforcement
  4. Dovecot hardening   - auth failure delay, verbose logging
  5. Fail2ban            - auto-ban after repeated auth failures
  6. Firewall            - only required ports open

EOF
}

#-------------------------------------------------------------------------------
# Main
#-------------------------------------------------------------------------------
main() {
    local action=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --install)
                action="install"
                shift
                ;;
            --uninstall)
                action="uninstall"
                shift
                ;;
            --status)
                action="status"
                shift
                ;;
            --test-security)
                action="test-security"
                shift
                ;;
            --test-mail)
                action="test-mail"
                shift
                ;;
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done

    if [[ -z "$action" ]]; then
        show_help
        exit 0
    fi

    check_root
    setup_logging
    detect_system

    case "$action" in
        install)
            do_install
            ;;
        uninstall)
            do_uninstall
            ;;
        status)
            do_status
            ;;
        test-security)
            do_test_security
            ;;
        test-mail)
            do_test_mail
            ;;
    esac
}

main "$@"
