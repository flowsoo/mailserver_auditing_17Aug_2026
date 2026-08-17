#!/usr/bin/env bash

# ============================================================
# Mail Server Security Audit
#
# Areas:
#   - Operating system security
#   - Network exposure & ports
#   - Firewall
#   - Fail2ban / brute-force protection
#
# READ-ONLY: This script does not modify the system.
# ============================================================

set +e

PASS=0
WARN=0
FAIL=0
INFO=0

PASS_MSG=()
WARN_MSG=()
FAIL_MSG=()
INFO_MSG=()

pass() {
    echo "[PASS] $1"
    PASS=$((PASS+1))
    PASS_MSG+=("$1")
}

warn() {
    echo "[WARN] $1"
    WARN=$((WARN+1))
    WARN_MSG+=("$1")
}

fail() {
    echo "[FAIL] $1"
    FAIL=$((FAIL+1))
    FAIL_MSG+=("$1")
}

info() {
    echo "[INFO] $1"
    INFO=$((INFO+1))
    INFO_MSG+=("$1")
}

section() {
    echo
    echo "============================================================"
    echo "$1"
    echo "============================================================"
}

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# ------------------------------------------------------------
# Header
# ------------------------------------------------------------

echo
echo "============================================================"
echo " MAIL SERVER OPERATING SYSTEM SECURITY AUDIT"
echo "============================================================"
echo " Host: $(hostname -f 2>/dev/null || hostname)"
echo " Date: $(date)"
echo " User: $(id -un)"
echo " Kernel: $(uname -sr)"
echo

# ============================================================
# 1. OPERATING SYSTEM SECURITY
# ============================================================

section "1. OPERATING SYSTEM SECURITY"

# ------------------------------------------------------------
# OS identification
# ------------------------------------------------------------

if [ -f /etc/os-release ]; then
    . /etc/os-release
    info "Operating system: ${PRETTY_NAME:-unknown}"
else
    warn "/etc/os-release not found; OS could not be identified."
fi

# ------------------------------------------------------------
# Root privileges
# ------------------------------------------------------------

if [ "$EUID" -eq 0 ]; then
    pass "Script is running as root."
else
    warn "Script is not running as root. Some checks will be incomplete."
    info "Recommended: run with sudo."
fi

# ------------------------------------------------------------
# Kernel
# ------------------------------------------------------------

info "Kernel: $(uname -r)"

# ------------------------------------------------------------
# Security updates - Debian/Ubuntu
# ------------------------------------------------------------

if command_exists apt; then

    echo
    echo "Checking pending package updates..."

    apt_update_status=$(apt-get -s upgrade 2>/dev/null)

    security_updates=$(echo "$apt_update_status" |
        grep '^Inst ' |
        grep -Ei 'security|openssl|openssh|linux|postfix|dovecot|php|nginx|apache' |
        wc -l)

    total_updates=$(echo "$apt_update_status" |
        grep '^Inst ' |
        wc -l)

    if [ "$security_updates" -gt 0 ]; then
        warn "$security_updates potentially security-relevant package update(s) appear pending."
    elif [ "$total_updates" -gt 0 ]; then
        info "$total_updates package update(s) appear pending."
    else
        pass "No pending package upgrades detected."
    fi

elif command_exists dnf; then

    if dnf check-update >/dev/null 2>&1; then
        pass "No pending DNF updates detected."
    else
        warn "DNF reports pending package updates. Review with: dnf check-update"
    fi

elif command_exists yum; then

    info "YUM detected. Review available updates with: yum check-update"

else
    warn "Could not determine package management system."
fi

# ------------------------------------------------------------
# Automatic security updates
# ------------------------------------------------------------

if command_exists systemctl; then

    if systemctl is-enabled unattended-upgrades >/dev/null 2>&1 ||
       systemctl is-active unattended-upgrades >/dev/null 2>&1; then
        pass "unattended-upgrades appears to be enabled."
    elif systemctl is-enabled dnf-automatic.timer >/dev/null 2>&1 ||
         systemctl is-active dnf-automatic.timer >/dev/null 2>&1; then
        pass "dnf-automatic appears to be enabled."
    else
        warn "No obvious automatic update service detected."
        info "Recommendation: enable automatic security updates or establish a documented patching process."
    fi
fi

# ------------------------------------------------------------
# SSH
# ------------------------------------------------------------

section "SSH SECURITY"

if [ -f /etc/ssh/sshd_config ]; then

    sshd -T 2>/dev/null > /tmp/mail_audit_sshd.$$ 2>/dev/null

    permit_root=$(grep '^permitrootlogin ' /tmp/mail_audit_sshd.$$ | awk '{print $2}')
    password_auth=$(grep '^passwordauthentication ' /tmp/mail_audit_sshd.$$ | awk '{print $2}')
    pubkey_auth=$(grep '^pubkeyauthentication ' /tmp/mail_audit_sshd.$$ | awk '{print $2}')

    if [ "$permit_root" = "no" ]; then
        pass "SSH root login is disabled."
    else
        warn "SSH root login is not explicitly disabled."
        info "Recommendation: set PermitRootLogin no."
    fi

    if [ "$password_auth" = "no" ]; then
        pass "SSH password authentication is disabled."
    else
        warn "SSH password authentication is enabled."
        info "Recommendation: use SSH keys and disable password authentication where operationally appropriate."
    fi

    if [ "$pubkey_auth" = "yes" ]; then
        pass "SSH public-key authentication is enabled."
    else
        warn "SSH public-key authentication is not enabled."
    fi

    rm -f /tmp/mail_audit_sshd.$$

else
    warn "sshd_config not found."
fi

# ------------------------------------------------------------
# Unnecessary services
# ------------------------------------------------------------

section "SYSTEM SERVICES"

if command_exists systemctl; then

    echo "Potentially relevant listening services:"

    systemctl --type=service --state=running 2>/dev/null |
        grep -Ei 'ssh|postfix|dovecot|nginx|apache|fail2ban|mysql|mariadb|postgres|php' |
        sed 's/^/  /'

    echo
    info "Review all running services and disable anything not required."
fi

# ------------------------------------------------------------
# AppArmor / SELinux
# ------------------------------------------------------------

section "MANDATORY ACCESS CONTROL"

if command_exists aa-status; then

    aa_output=$(aa-status 2>/dev/null)

    if echo "$aa_output" | grep -q "apparmor module is loaded"; then
        pass "AppArmor is loaded."
    else
        warn "AppArmor does not appear to be loaded."
    fi

elif command_exists getenforce; then

    selinux_status=$(getenforce 2>/dev/null)

    case "$selinux_status" in
        Enforcing)
            pass "SELinux is enforcing."
            ;;
        Permissive)
            warn "SELinux is permissive."
            ;;
        Disabled)
            warn "SELinux is disabled."
            ;;
        *)
            info "SELinux status: $selinux_status"
            ;;
    esac

else
    info "No AppArmor/SELinux status utility detected."
fi

# ------------------------------------------------------------
# Time synchronization
# ------------------------------------------------------------

section "TIME SYNCHRONIZATION"

if command_exists timedatectl; then

    sync_status=$(timedatectl show -p NTPSynchronized --value 2>/dev/null)

    if [ "$sync_status" = "yes" ]; then
        pass "System clock is NTP synchronized."
    else
        warn "System clock does not appear to be NTP synchronized."
    fi

else
    info "timedatectl unavailable."
fi

# ============================================================
# 2. NETWORK EXPOSURE
# ============================================================

section "2. NETWORK EXPOSURE & PORTS"

if command_exists ss; then

    echo
    echo "Listening TCP sockets:"
    ss -lntp 2>/dev/null

    echo
    echo "Relevant mail/web ports:"

    for port in 25 80 110 143 443 465 587 993 995; do

        result=$(ss -lnt 2>/dev/null |
            awk -v p=":$port" '$4 ~ p"$" || $4 ~ p"[^0-9]"')

        if [ -n "$result" ]; then
            case "$port" in
                25)
                    info "TCP 25 is listening — expected if this server receives Internet mail."
                    ;;
                80)
                    info "TCP 80 is listening — review whether it is only used for HTTP→HTTPS/ACME."
                    ;;
                110)
                    warn "TCP 110 (POP3) is listening."
                    info "Recommendation: disable if POP3 is not required."
                    ;;
                143)
                    warn "TCP 143 (IMAP) is listening."
                    info "Recommendation: disable if all clients can use IMAPS/993."
                    ;;
                443)
                    pass "TCP 443 (HTTPS) is listening."
                    ;;
                465)
                    info "TCP 465 (SMTPS) is listening — disable if not required."
                    ;;
                587)
                    pass "TCP 587 (SMTP submission) is listening."
                    ;;
                993)
                    pass "TCP 993 (IMAPS) is listening."
                    ;;
                995)
                    warn "TCP 995 (POP3S) is listening."
                    info "Recommendation: disable if POP3 is not required."
                    ;;
            esac
        else
            case "$port" in
                25|443|587|993)
                    info "TCP $port is not listening."
                    ;;
                *)
                    pass "TCP $port is not listening."
                    ;;
            esac
        fi
    done

else
    warn "ss command not available."
fi

# ============================================================
# 3. FIREWALL
# ============================================================

section "3. FIREWALL"

firewall_found=0

if command_exists ufw; then

    firewall_found=1

    ufw_status=$(ufw status 2>/dev/null)

    if echo "$ufw_status" | grep -q "^Status: active"; then
        pass "UFW is active."
    else
        warn "UFW is installed but not active."
    fi

    echo
    echo "$ufw_status"

elif command_exists firewall-cmd; then

    firewall_found=1

    if firewall-cmd --state 2>/dev/null | grep -q running; then
        pass "firewalld is running."
        echo
        firewall-cmd --list-all 2>/dev/null
    else
        warn "firewalld is installed but not running."
    fi

elif command_exists nft; then

    firewall_found=1

    ruleset=$(nft list ruleset 2>/dev/null)

    if [ -n "$ruleset" ]; then
        pass "nftables ruleset exists."
        echo
        echo "$ruleset" | head -200
    else
        warn "nftables is available but no ruleset was detected."
    fi

elif command_exists iptables; then

    firewall_found=1

    echo "iptables rules:"
    iptables -L -n -v 2>/dev/null

    if iptables -L 2>/dev/null | grep -q ACCEPT; then
        info "iptables rules detected; review manually for default-deny behavior."
    else
        warn "Could not confirm a restrictive iptables policy."
    fi
fi

if [ "$firewall_found" -eq 0 ]; then
    fail "No active firewall management system detected."
    info "Recommendation: deploy and enable nftables, UFW, firewalld, or an equivalent firewall."
fi

# ============================================================
# 4. FAIL2BAN / BRUTE FORCE
# ============================================================

section "4. FAIL2BAN & BRUTE-FORCE PROTECTION"

if command_exists fail2ban-client; then

    if systemctl is-active fail2ban >/dev/null 2>&1; then

        pass "Fail2ban service is active."

        echo
        echo "Configured jails:"
        fail2ban-client status 2>/dev/null

        echo
        echo "Jail details:"

        jails=$(fail2ban-client status 2>/dev/null |
            sed -n 's/.*Jail list:[[:space:]]*//p' |
            tr ',' ' ')

        for jail in $jails; do
            echo
            echo "--- $jail ---"
            fail2ban-client status "$jail" 2>/dev/null
        done

        if fail2ban-client status 2>/dev/null |
            grep -Eq 'sshd|dovecot|postfix|roundcube|nginx|apache'; then
            pass "Fail2ban has relevant mail/web protection jails configured."
        else
            warn "Fail2ban is active but no obvious mail/web authentication jail was detected."
            info "Recommendation: consider jails for SSH, Dovecot, Postfix SMTP AUTH, and the Roundcube/web layer."
        fi

    else
        fail "Fail2ban is installed but not active."
    fi

else
    warn "Fail2ban is not installed."
    info "Recommendation: deploy brute-force protection for SSH, Dovecot, Postfix submission, and Roundcube."
fi

# ============================================================
# 5. FILESYSTEM / SENSITIVE FILE PERMISSIONS
# ============================================================

section "5. GENERAL SENSITIVE FILE PERMISSIONS"

check_sensitive_file() {

    file="$1"

    if [ -e "$file" ]; then

        perms=$(stat -c '%a' "$file" 2>/dev/null)
        owner=$(stat -c '%U:%G' "$file" 2>/dev/null)

        echo "$file : permissions=$perms owner=$owner"

        # World writable
        if [ -w "$file" ] && [ "$(stat -c '%a' "$file" | cut -c3)" != "0" ]; then
            warn "$file is writable by non-owner/group users."
        fi
    fi
}

check_sensitive_file /etc/shadow
check_sensitive_file /etc/gshadow
check_sensitive_file /etc/ssh/sshd_config

# ============================================================
# SUMMARY
# ============================================================

section "AUDIT SUMMARY"

echo
echo "PASS : $PASS"
echo "WARN : $WARN"
echo "FAIL : $FAIL"
echo "INFO : $INFO"

echo
echo "Overall recommendations:"

if [ "$FAIL" -gt 0 ]; then
    echo "  * Address FAIL items before considering the server hardened."
fi

if [ "$WARN" -gt 0 ]; then
    echo "  * Review WARN items and determine whether they are intentional."
fi

echo "  * Verify that every exposed network service is required."
echo "  * Maintain OS/security updates."
echo "  * Keep brute-force protection active."
echo "  * Review firewall rules whenever services are added or removed."

echo
echo "Audit complete."
