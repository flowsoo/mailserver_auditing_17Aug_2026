#!/usr/bin/env bash

# ============================================================
# Dovecot Security Audit
#
# Areas:
#   - Dovecot configuration
#   - IMAP exposure
#   - TLS
#   - Authentication
#   - Password authentication
#   - Permissions
#   - Authentication sockets
#   - Mailbox access
#   - Brute-force indicators
#   - Resource/rate limits
#   - Mail abuse indicators
#
# READ-ONLY: This script does not modify Dovecot.
# ============================================================

set +e

PASS=0
WARN=0
FAIL=0
INFO=0

pass() {
    echo "[PASS] $1"
    PASS=$((PASS+1))
}

warn() {
    echo "[WARN] $1"
    WARN=$((WARN+1))
}

fail() {
    echo "[FAIL] $1"
    FAIL=$((FAIL+1))
}

info() {
    echo "[INFO] $1"
    INFO=$((INFO+1))
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

dconf() {
    doveconf -h "$1" 2>/dev/null
}

echo
echo "============================================================"
echo " DOVECOT SECURITY AUDIT"
echo "============================================================"
echo " Host: $(hostname -f 2>/dev/null || hostname)"
echo " Date: $(date)"
echo

if ! command_exists doveconf; then
    fail "doveconf is not installed or Dovecot is unavailable."
    exit 1
fi

version=$(doveconf --version 2>/dev/null)
info "Dovecot version: $version"

# ============================================================
# 1. CORE CONFIGURATION
# ============================================================

section "1. CORE DOVECOT CONFIGURATION"

echo "protocols       = $(dconf protocols)"
echo "listen          = $(dconf listen)"
echo "ssl             = $(dconf ssl)"
echo "auth_mechanisms = $(dconf auth_mechanisms)"

# ============================================================
# 2. PROTOCOLS
# ============================================================

section "2. ENABLED PROTOCOLS"

protocols=$(dconf protocols)

echo "$protocols"

if echo "$protocols" | grep -qw imap; then
    pass "IMAP is enabled."
else
    warn "IMAP is not enabled."
fi

if echo "$protocols" | grep -qw pop3; then
    warn "POP3 is enabled."
    info "Recommendation: disable POP3 if it is not required."
else
    pass "POP3 is not enabled."
fi

# ============================================================
# 3. IMAP PORTS
# ============================================================

section "3. IMAP NETWORK EXPOSURE"

if command_exists ss; then

    echo "IMAP-related listening sockets:"
    ss -lntp 2>/dev/null |
        grep -E ':(143|993)[[:space:]]' || true

    if ss -lnt 2>/dev/null | grep -Eq ':(993)[[:space:]]'; then
        pass "IMAPS port 993 is listening."
    else
        warn "IMAPS port 993 is not listening."
    fi

    if ss -lnt 2>/dev/null | grep -Eq ':(143)[[:space:]]'; then
        warn "IMAP port 143 is listening."
        info "Review whether plaintext/STARTTLS IMAP is necessary."
    else
        pass "IMAP port 143 is not listening."
    fi
fi

# ============================================================
# 4. TLS
# ============================================================

section "4. TLS CONFIGURATION"

ssl=$(dconf ssl)

echo "ssl             = $ssl"
echo "ssl_cert        = $(dconf ssl_cert)"
echo "ssl_key         = $(dconf ssl_key)"
echo "ssl_min_protocol = $(dconf ssl_min_protocol)"
echo "ssl_cipher_list  = $(dconf ssl_cipher_list)"

if [ "$ssl" = "required" ]; then
    pass "Dovecot requires TLS."
elif [ "$ssl" = "yes" ]; then
    warn "Dovecot TLS is enabled but not necessarily required."
    info "Recommendation: require TLS for password authentication."
else
    fail "Dovecot TLS does not appear to be enabled."
fi

# Certificate
cert=$(dconf ssl_cert | sed 's/^<//')
key=$(dconf ssl_key | sed 's/^<//')

if [ -n "$cert" ]; then

    cert_file=$(echo "$cert" | awk '{print $1}')

    if [ -f "$cert_file" ]; then
        pass "Configured Dovecot TLS certificate exists: $cert_file"

        if command_exists openssl; then

            expiry=$(openssl x509 -in "$cert_file" -noout -enddate 2>/dev/null)

            if [ -n "$expiry" ]; then
                echo "Certificate expiry: $expiry"

                expiry_epoch=$(openssl x509 -in "$cert_file" -noout -enddate 2>/dev/null |
                    cut -d= -f2 |
                    xargs -0 date -d 2>/dev/null +%s)

                now_epoch=$(date +%s)

                if [ -n "$expiry_epoch" ]; then
                    days=$(( (expiry_epoch - now_epoch) / 86400 ))

                    if [ "$days" -lt 0 ]; then
                        fail "Dovecot TLS certificate has expired."
                    elif [ "$days" -lt 30 ]; then
                        warn "Dovecot TLS certificate expires in approximately $days days."
                    else
                        pass "Dovecot TLS certificate has approximately $days days remaining."
                    fi
                fi
            fi
        fi
    else
        fail "Configured Dovecot TLS certificate does not exist."
    fi
fi

if [ -n "$key" ]; then

    key_file=$(echo "$key" | awk '{print $1}')

    if [ -f "$key_file" ]; then

        # Resolve Let's Encrypt live/ symlinks so that permissions
        # are checked on the actual private-key file in archive/.
        actual_key_file=$(readlink -f "$key_file" 2>/dev/null)

        if [ -n "$actual_key_file" ] && [ -f "$actual_key_file" ]; then

            perms=$(stat -c '%a' "$actual_key_file" 2>/dev/null)
            owner=$(stat -c '%U:%G' "$actual_key_file" 2>/dev/null)

            echo "TLS private key: $key_file"
            echo "Actual TLS private key: $actual_key_file"
            echo "Permissions: $perms"
            echo "Owner: $owner"

            if [ $((10#$perms % 10)) -eq 0 ]; then
                pass "Dovecot TLS private key is not world-readable."
            else
                fail "Dovecot TLS private key is world-readable."
            fi

        else
            fail "Configured Dovecot TLS private key symlink target does not exist."
        fi

    else
        fail "Configured Dovecot TLS private key does not exist."
    fi
fi

# ============================================================
# 5. AUTHENTICATION
# ============================================================

section "5. AUTHENTICATION"

auth_mechanisms=$(dconf auth_mechanisms)

echo "auth_mechanisms = $auth_mechanisms"

if [ -z "$auth_mechanisms" ]; then
    warn "No Dovecot authentication mechanisms detected."
else
    info "Configured authentication mechanisms: $auth_mechanisms"
fi

if echo "$auth_mechanisms" | grep -Eq 'plain|login'; then

    if [ "$ssl" = "required" ]; then
        pass "PLAIN/LOGIN authentication is used with mandatory TLS."
    else
        warn "PLAIN/LOGIN authentication is enabled without confirmed mandatory TLS."
        info "Recommendation: never allow plaintext credentials over an unencrypted connection."
    fi
fi

# ============================================================
# 6. AUTHENTICATION SOCKETS
# ============================================================

section "6. AUTHENTICATION SOCKETS"

echo "Configured auth sockets:"
doveconf -n 2>/dev/null |
    grep -Ei 'auth.*socket|socket.*auth' |
    head -100

info "Review authentication socket ownership and permissions, particularly Postfix/Dovecot integration sockets."

# ============================================================
# 7. PASSWORD DATABASE
# ============================================================

section "7. PASSWORD DATABASE"

echo "Password database configuration:"
doveconf -n 2>/dev/null |
    grep -Ei 'passdb|password|driver' |
    head -100

info "Verify that mailbox password storage uses an appropriate password hashing scheme."

# Search for obvious plaintext password storage
if doveconf -n 2>/dev/null |
    grep -Ei 'scheme[[:space:]]*=[[:space:]]*(PLAIN|CLEARTEXT)' >/dev/null; then

    fail "Dovecot configuration appears to contain a plaintext password scheme."
    info "Recommendation: use a strong password hashing scheme."
else
    pass "No obvious plaintext password hashing scheme was detected in doveconf output."
fi

# ============================================================
# 8. MAILBOX / STORAGE
# ============================================================

section "8. MAILBOX STORAGE"

echo "mail_location = $(dconf mail_location)"

mail_location=$(dconf mail_location)

if [ -z "$mail_location" ]; then
    warn "mail_location is not explicitly configured."
else
    info "Mail location: $mail_location"
fi

# ============================================================
# 9. MAIL DIRECTORY PERMISSIONS
# ============================================================

section "9. MAILBOX PERMISSIONS"

# Try to identify common mail storage paths
for path in \
    /var/mail \
    /var/vmail \
    /home \
    /srv/mail \
    /srv/vmail
do

    if [ -d "$path" ]; then

        perms=$(stat -c '%a' "$path" 2>/dev/null)
        owner=$(stat -c '%U:%G' "$path" 2>/dev/null)

        echo "$path : permissions=$perms owner=$owner"

        # World writable
        if [ $((10#$perms % 10)) -ne 0 ]; then
            warn "$path is accessible for writing by other users."
        fi
    fi
done

info "Verify that users cannot read other users' mailboxes through filesystem permissions."

# ============================================================
# 10. DOVECOT PROCESS PRIVILEGES
# ============================================================

section "10. DOVECOT PROCESS / PRIVILEGES"

echo "Dovecot service status:"
systemctl is-active dovecot 2>/dev/null

echo
echo "Dovecot processes:"
ps aux 2>/dev/null | grep '[d]ovecot' | head -50

info "Review that Dovecot services operate with least-required privileges."

# ============================================================
# 11. CONNECTION / RESOURCE LIMITS
# ============================================================

section "11. CONNECTION & RESOURCE LIMITS"

echo "Relevant connection/resource settings:"

doveconf -n 2>/dev/null |
    grep -Ei \
    'mail_max_user_connections|mail_max_userip_connections|process_limit|client_limit|service_count|vsz_limit|max_user_connections|auth_worker_max_count|auth_failure_delay' |
    head -100

if doveconf -n 2>/dev/null |
    grep -Eq \
    'mail_max_user_connections|mail_max_userip_connections|auth_failure_delay|process_limit'; then

    pass "Dovecot has explicit connection/resource controls configured."
else
    warn "No obvious Dovecot connection/resource limits were detected."
    info "Recommendation: establish appropriate per-user and service limits."
fi

# ============================================================
# 12. LOGIN / BRUTE FORCE
# ============================================================

section "12. LOGIN / BRUTE-FORCE INDICATORS"

log_file=""

if [ -f /var/log/mail.log ]; then
    log_file="/var/log/mail.log"
elif [ -f /var/log/maillog ]; then
    log_file="/var/log/maillog"
fi

if [ -n "$log_file" ]; then

    failed_logins=$(grep -Ei \
        'dovecot.*(authentication failed|auth failed|password mismatch|unknown user)' \
        "$log_file" 2>/dev/null |
        tail -1000 |
        wc -l)

    echo "Recent matching authentication failures: $failed_logins"

    if [ "$failed_logins" -gt 100 ]; then
        warn "Large number of recent Dovecot authentication failures detected."
        info "Review for brute-force activity and ensure Fail2ban is protecting Dovecot."
    elif [ "$failed_logins" -gt 20 ]; then
        info "Dovecot authentication failures detected; review logs."
    else
        pass "No unusually large number of recent Dovecot authentication failures detected."
    fi

elif command_exists journalctl; then

    failed_logins=$(journalctl -u dovecot --no-pager 2>/dev/null |
        grep -Ei 'authentication failed|auth failed|password mismatch|unknown user' |
        tail -1000 |
        wc -l)

    echo "Recent matching authentication failures: $failed_logins"

else
    info "Could not determine Dovecot authentication log source."
fi

# ============================================================
# 13. FAIL2BAN INTEGRATION
# ============================================================

section "13. FAIL2BAN / DOVECOT"

if command_exists fail2ban-client &&
   systemctl is-active fail2ban >/dev/null 2>&1; then

    if fail2ban-client status 2>/dev/null |
        grep -qi dovecot; then
        pass "Fail2ban appears to have a Dovecot-related jail."
    else
        warn "No Dovecot Fail2ban jail detected."
        info "Recommendation: protect Dovecot authentication against brute-force attacks."
    fi
else
    warn "Fail2ban is not active."
    info "Recommendation: deploy brute-force protection for Dovecot."
fi

# ============================================================
# 14. MAIL ABUSE / LOGIN ABUSE
# ============================================================

section "14. MAIL ABUSE / AUTHENTICATED USER ABUSE"

info "Dovecot itself does not normally enforce outbound mail rate limits."
info "Outbound abuse controls should primarily be implemented in Postfix and/or the external relay."

echo
echo "Look for suspicious authenticated sessions:"
if [ -n "$log_file" ]; then

    grep -Ei \
        'dovecot.*(Login|imap-login).*rip=' \
        "$log_file" 2>/dev/null |
        tail -20

else
    journalctl -u dovecot --no-pager 2>/dev/null |
        grep -Ei 'Login|imap-login' |
        tail -20
fi

info "Investigate unusual IP addresses, login frequency, or geographically unexpected access."

# ============================================================
# 15. DOVECOT CONFIG FILE PERMISSIONS
# ============================================================

section "15. DOVECOT CONFIGURATION FILE PERMISSIONS"

for file in \
    /etc/dovecot/dovecot.conf \
    /etc/dovecot/conf.d/10-auth.conf \
    /etc/dovecot/conf.d/10-ssl.conf \
    /etc/dovecot/conf.d/10-master.conf
do

    if [ -f "$file" ]; then

        perms=$(stat -c '%a' "$file" 2>/dev/null)
        owner=$(stat -c '%U:%G' "$file" 2>/dev/null)

        echo "$file : $perms $owner"

        if [ $((10#$perms % 10)) -ne 0 ]; then
            warn "$file is readable by other users."
        else
            pass "$file is not world-writable."
        fi
    fi
done

# ============================================================
# 16. CONFIGURATION SECRETS
# ============================================================

section "16. DOVECOT CONFIGURATION SECRETS"

# Search for obvious password assignments, without displaying values.
secret_matches=$(grep -RInE \
    '^[[:space:]]*(password|pass)[[:space:]]*=' \
    /etc/dovecot 2>/dev/null |
    sed -E 's/(password|pass)[[:space:]]*=.*/\1 = [REDACTED]/I' |
    head -50)

if [ -n "$secret_matches" ]; then
    warn "Password assignments were detected in Dovecot configuration."
    echo "$secret_matches"
    info "Review whether these secrets need to be present in configuration files and protect the files accordingly."
else
    pass "No obvious plaintext password assignments detected in Dovecot configuration."
fi

# ============================================================
# 17. LOGGING
# ============================================================

section "17. DOVECOT LOGGING"

if [ -f /var/log/mail.log ]; then
    pass "/var/log/mail.log exists."
elif [ -f /var/log/maillog ]; then
    pass "/var/log/maillog exists."
else
    info "Traditional mail log file not found; Dovecot may be logging through journald."
fi

if command_exists journalctl; then
    if journalctl -u dovecot --no-pager -n 5 >/dev/null 2>&1; then
        pass "Dovecot journald logs are available."
    fi
fi

# ============================================================
# SUMMARY
# ============================================================

section "DOVECOT AUDIT SUMMARY"

echo
echo "PASS : $PASS"
echo "WARN : $WARN"
echo "FAIL : $FAIL"
echo "INFO : $INFO"

echo
echo "Priority recommendations:"

[ "$FAIL" -gt 0 ] &&
    echo "  * Resolve FAIL items before considering Dovecot hardened."

[ "$WARN" -gt 0 ] &&
    echo "  * Review WARN items and document intentional exceptions."

echo "  * Require TLS for mailbox authentication."
echo "  * Prefer IMAPS/993 over unencrypted IMAP."
echo "  * Protect Dovecot authentication and mailbox files."
echo "  * Monitor authentication failures."
echo "  * Protect Dovecot with brute-force controls."

echo
echo "Dovecot audit complete."
