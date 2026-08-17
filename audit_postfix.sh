#!/usr/bin/env bash

# ============================================================
# Postfix Security Audit
#
# Areas:
#   - Postfix configuration
#   - Open relay protection
#   - SMTP / submission security
#   - TLS
#   - SASL authentication
#   - Relay configuration
#   - Credential/password protection
#   - Permissions
#   - Queue / mail abuse indicators
#   - Rate limiting
#
# READ-ONLY: This script does not modify Postfix.
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

getconf() {
    postconf -h "$1" 2>/dev/null
}

echo
echo "============================================================"
echo " POSTFIX SECURITY AUDIT"
echo "============================================================"
echo " Host: $(hostname -f 2>/dev/null || hostname)"
echo " Date: $(date)"
echo

if ! command_exists postconf; then
    fail "postconf is not installed or Postfix is not available."
    exit 1
fi

postfix_version=$(postconf mail_version)
info "Postfix version: $postfix_version"

# ============================================================
# 1. CORE CONFIGURATION
# ============================================================

section "1. CORE POSTFIX CONFIGURATION"

echo "myhostname        = $(getconf myhostname)"
echo "mydomain          = $(getconf mydomain)"
echo "myorigin          = $(getconf myorigin)"
echo "mydestination     = $(getconf mydestination)"
echo "mynetworks        = $(getconf mynetworks)"
echo "inet_interfaces   = $(getconf inet_interfaces)"
echo "inet_protocols    = $(getconf inet_protocols)"
echo "relayhost         = $(getconf relayhost)"

# ============================================================
# 2. OPEN RELAY PROTECTION
# ============================================================

section "2. OPEN RELAY PROTECTION"

relay_restrictions=$(getconf smtpd_relay_restrictions)
recipient_restrictions=$(getconf smtpd_recipient_restrictions)

echo "smtpd_relay_restrictions:"
echo "$relay_restrictions"

echo
echo "smtpd_recipient_restrictions:"
echo "$recipient_restrictions"

if echo "$relay_restrictions $recipient_restrictions" |
    grep -q "reject_unauth_destination"; then
    pass "reject_unauth_destination is present."
else
    fail "Could not find reject_unauth_destination in relay/recipient restrictions."
    info "Recommendation: ensure unauthenticated clients cannot relay arbitrary external mail."
fi

if echo "$relay_restrictions $recipient_restrictions" |
    grep -Eq 'permit_sasl_authenticated'; then
    pass "Authenticated SMTP clients are explicitly permitted."
else
    warn "permit_sasl_authenticated was not detected."
fi

# Check for dangerous permit patterns
if echo "$relay_restrictions $recipient_restrictions" |
    grep -Eq '(^|[ ,])permit([ ,]|$)'; then
    warn "A broad 'permit' restriction was detected."
    info "Review ordering carefully; a broad permit before reject_unauth_destination can create an open relay."
fi

# ============================================================
# 3. MYNETWORKS
# ============================================================

section "3. MYNETWORKS"

mynetworks=$(getconf mynetworks)

echo "$mynetworks"

if echo "$mynetworks" | grep -Eq '0\.0\.0\.0/0|0/0|::/0'; then
    fail "mynetworks appears to include the entire Internet."
    info "Recommendation: restrict mynetworks to trusted local addresses only."
else
    pass "mynetworks does not appear to allow the entire Internet."
fi

# ============================================================
# 4. SMTP AUTH
# ============================================================

section "4. SMTP AUTH / SUBMISSION"

smtp_sasl_auth=$(getconf smtp_sasl_auth_enable)
smtpd_sasl_auth=$(getconf smtpd_sasl_auth_enable)

echo "smtp_sasl_auth_enable  = $smtp_sasl_auth"
echo "smtpd_sasl_auth_enable = $smtpd_sasl_auth"

if [ "$smtpd_sasl_auth" = "yes" ]; then
    pass "Postfix SMTP server-side SASL authentication is enabled."
else
    warn "smtpd_sasl_auth_enable is not enabled."
fi

if [ "$smtp_sasl_auth" = "yes" ]; then
    pass "Postfix SMTP client-side SASL authentication is enabled."
else
    info "Outbound SMTP SASL authentication is disabled."
fi

# ============================================================
# 5. TLS
# ============================================================

section "5. TLS CONFIGURATION"

echo "smtpd_tls_security_level = $(getconf smtpd_tls_security_level)"
echo "smtpd_tls_auth_only     = $(getconf smtpd_tls_auth_only)"
echo "smtp_tls_security_level  = $(getconf smtp_tls_security_level)"
echo "smtp_tls_wrappermode     = $(getconf smtp_tls_wrappermode)"
echo "smtpd_tls_cert_file      = $(getconf smtpd_tls_cert_file)"
echo "smtpd_tls_key_file       = $(getconf smtpd_tls_key_file)"
echo "smtpd_tls_CAfile         = $(getconf smtpd_tls_CAfile)"
echo "smtpd_tls_CApath         = $(getconf smtpd_tls_CApath)"
echo "smtp_tls_CAfile          = $(getconf smtp_tls_CAfile)"
echo "smtp_tls_CApath          = $(getconf smtp_tls_CApath)"

submission_tls=$(getconf smtpd_tls_auth_only)

if [ "$submission_tls" = "yes" ]; then
    pass "SMTP AUTH is restricted to TLS connections via smtpd_tls_auth_only."
else
    warn "smtpd_tls_auth_only is not enabled."
    info "Recommendation: authenticated submission should require TLS."
fi

out_tls=$(getconf smtp_tls_security_level)

case "$out_tls" in
    encrypt|verify|secure|dane|dane-only)
        pass "Outbound SMTP TLS security level is $out_tls."
        ;;
    *)
        warn "Outbound SMTP TLS security level is '$out_tls'."
        ;;
esac

# ============================================================
# 6. SMTP AUTH PASSWORD MAP
# ============================================================

section "6. SMTP AUTH CREDENTIALS"

password_maps=$(getconf smtp_sasl_password_maps)

echo "smtp_sasl_password_maps = $password_maps"

if [ -z "$password_maps" ]; then
    warn "No smtp_sasl_password_maps configured."
else
    map_file=$(echo "$password_maps" |
        sed -n 's/.*:\([^ ]*\/sasl_passwd\).*/\1/p')

    if [ -z "$map_file" ]; then
        map_file="/etc/postfix/sasl_passwd"
    fi

    echo "Likely credential file: $map_file"

    if [ -f "$map_file" ]; then

        perms=$(stat -c '%a' "$map_file" 2>/dev/null)
        owner=$(stat -c '%U:%G' "$map_file" 2>/dev/null)

        echo "Permissions: $perms"
        echo "Owner:       $owner"

        if [ "$perms" = "600" ] || [ "$perms" = "640" ] || [ "$perms" = "400" ]; then
            pass "SMTP credential file permissions are reasonably restrictive."
        else
            fail "SMTP credential file permissions are $perms."
            info "Recommendation: restrict access to root/Postfix as appropriate."
        fi

        # Check for world-readable
        mode=$(stat -c '%a' "$map_file" 2>/dev/null)

        if [ $((10#$mode % 10)) -ne 0 ]; then
            fail "SMTP credential file appears readable by other users."
        fi

    else
        warn "Configured SMTP credential file was not found."
    fi
fi

# Password DB
if [ -f /etc/postfix/sasl_passwd.db ]; then

    perms=$(stat -c '%a' /etc/postfix/sasl_passwd.db 2>/dev/null)

    echo "/etc/postfix/sasl_passwd.db permissions: $perms"

    if [ $((10#$perms % 10)) -eq 0 ]; then
        pass "SMTP password database is not world-readable."
    else
        fail "SMTP password database is accessible to other users."
    fi
fi

# ============================================================
# 7. RELAYHOST
# ============================================================

section "7. OUTBOUND RELAY"

relayhost=$(getconf relayhost)

if [ -n "$relayhost" ]; then
    pass "Outbound relayhost is configured."
    echo "relayhost = $relayhost"

    if echo "$relayhost" | grep -q ':587'; then
        pass "Relayhost uses port 587."
    elif echo "$relayhost" | grep -q ':465'; then
        info "Relayhost uses port 465. Verify wrapper-mode TLS configuration."
    elif echo "$relayhost" | grep -q ':25'; then
        warn "Relayhost uses port 25. Verify TLS and authentication requirements."
    fi
else
    info "No relayhost configured."
fi

# ============================================================
# 8. SMTP AUTH MECHANISMS
# ============================================================

section "8. SASL MECHANISMS"

echo "smtp_sasl_mechanism_filter = $(getconf smtp_sasl_mechanism_filter)"
echo "smtp_sasl_security_options = $(getconf smtp_sasl_security_options)"

if [ "$(getconf smtp_sasl_security_options)" = "noanonymous" ]; then
    pass "Anonymous SMTP SASL authentication is disabled."
else
    warn "smtp_sasl_security_options does not explicitly contain noanonymous."
fi

# ============================================================
# 9. MASTER.CF / SUBMISSION
# ============================================================

section "9. POSTFIX MASTER / SUBMISSION SERVICES"

if [ -f /etc/postfix/master.cf ]; then

    echo "Submission-related services:"
    grep -nE '^(submission|smtps)[[:space:]]' /etc/postfix/master.cf 2>/dev/null

    if grep -Eq '^submission[[:space:]]+inet' /etc/postfix/master.cf; then
        pass "SMTP submission service is configured in master.cf."
    else
        warn "No submission service found in master.cf."
    fi

    echo
    echo "Submission service configuration:"
    awk '
        /^submission[[:space:]]+inet/ {show=1}
        show {print}
        show && /^$/ {show=0}
    ' /etc/postfix/master.cf

else
    warn "/etc/postfix/master.cf not found."
fi

# ============================================================
# 10. RATE LIMITING / MAIL ABUSE
# ============================================================

section "10. RATE LIMITING / MAIL ABUSE"

rate_settings=$(postconf -n 2>/dev/null |
    grep -Ei 'rate|limit|destination_concurrency|recipient_limit|queue_run')

if [ -n "$rate_settings" ]; then
    echo "$rate_settings"
    info "Review the above rate/concurrency limits for suitability."
else
    warn "No obvious Postfix rate/concurrency controls were detected."
    info "Recommendation: establish sensible limits for authenticated submission and outbound delivery."
fi

# Queue size
if command_exists postqueue; then

    queue_count=$(postqueue -p 2>/dev/null |
        grep -cE '^[A-F0-9]{5,}' 2>/dev/null)

    echo
    echo "Approximate queued message count: $queue_count"

    if [ "$queue_count" -gt 500 ]; then
        warn "Large mail queue detected ($queue_count messages). Investigate for abuse or delivery problems."
    elif [ "$queue_count" -gt 100 ]; then
        info "Mail queue contains $queue_count messages; review if unexpected."
    else
        pass "Mail queue does not appear unusually large."
    fi
fi

# ============================================================
# 11. PERMISSIONS
# ============================================================

section "11. POSTFIX FILE PERMISSIONS"

for file in \
    /etc/postfix/main.cf \
    /etc/postfix/master.cf \
    /etc/postfix/sasl_passwd \
    /etc/postfix/sasl_passwd.db
do

    if [ -e "$file" ]; then

        perms=$(stat -c '%a' "$file" 2>/dev/null)
        owner=$(stat -c '%U:%G' "$file" 2>/dev/null)

        echo "$file : $perms $owner"

        case "$file" in
            */sasl_passwd|*/sasl_passwd.db)

                if [ $((10#$perms % 10)) -eq 0 ]; then
                    pass "$file is not world-readable."
                else
                    fail "$file is world-readable."
                fi
                ;;
        esac
    fi
done

# ============================================================
# 12. POSTFIX CHROOT / PRIVILEGES
# ============================================================

section "12. POSTFIX PROCESS / PRIVILEGE CONFIGURATION"

postconf daemon_directory
postconf data_directory
postconf mail_owner
postconf setgid_group

echo
echo "Review Postfix processes:"
ps aux 2>/dev/null | grep '[p]ostfix' | head -30

info "Verify that Postfix services run with least-required privileges."

# ============================================================
# 13. LOGGING
# ============================================================

section "13. POSTFIX LOGGING"

if [ -f /var/log/mail.log ]; then
    pass "/var/log/mail.log exists."
elif [ -f /var/log/maillog ]; then
    pass "/var/log/maillog exists."
else
    warn "Traditional Postfix mail log file not found."
    info "Logging may be handled entirely through journald."
fi

if command_exists journalctl; then
    if journalctl -u postfix --no-pager -n 5 >/dev/null 2>&1; then
        pass "Postfix journald logs are available."
    fi
fi

# ============================================================
# SUMMARY
# ============================================================

section "POSTFIX AUDIT SUMMARY"

echo
echo "PASS : $PASS"
echo "WARN : $WARN"
echo "FAIL : $FAIL"
echo "INFO : $INFO"

echo
echo "Priority recommendations:"

[ "$FAIL" -gt 0 ] &&
    echo "  * Resolve FAIL items before considering Postfix hardened."

[ "$WARN" -gt 0 ] &&
    echo "  * Review WARN items and document intentional exceptions."

echo "  * Verify that the server is not an open relay."
echo "  * Require TLS for authenticated SMTP submission."
echo "  * Protect SMTP relay credentials."
echo "  * Monitor queue size and authenticated outbound volume."

echo
echo "Postfix audit complete."
