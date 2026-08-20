#!/usr/bin/env bash
# Mail/Roundcube security audit: steps 2-9
# Read-only: does not modify configuration.

set -u

echo "============================================================"
echo " Postfix / Dovecot / Roundcube Security Audit"
echo "============================================================"
echo "Host: $(hostname -f 2>/dev/null || hostname)"
echo "Date: $(date)"
echo

section() {
    echo
    echo "------------------------------------------------------------"
    echo "$1"
    echo "------------------------------------------------------------"
}

check() {
    printf "%-5s %s\n" "$1" "$2"
}

# ------------------------------------------------------------
section "2. HTTPS / TLS"
# ------------------------------------------------------------

if command -v ss >/dev/null; then
    echo "[Listening ports]"
    ss -lntp 2>/dev/null | grep -E ':(80|443)\b' || echo "  No 80/443 listener detected."
fi

if command -v curl >/dev/null; then
    echo
    echo "[HTTP -> HTTPS]"
    HTTP_CODE=$(curl -ksI --max-time 5 http://localhost/ 2>/dev/null |
        awk 'tolower($1)=="location:" {print $2}' | head -1)
    if [[ "$HTTP_CODE" == https://* ]]; then
        check "OK" "HTTP redirects to HTTPS: $HTTP_CODE"
    else
        check "WARN" "Could not confirm HTTP redirects to HTTPS."
    fi

    echo
    echo "[HTTPS headers]"
    curl -ksI --max-time 5 https://localhost/ 2>/dev/null |
        grep -Ei '^(HTTP/|strict-transport-security:|content-security-policy:|x-content-type-options:|x-frame-options:|referrer-policy:)' ||
        echo "  Could not retrieve HTTPS headers."
fi

echo
echo "[TLS certificate]"
if command -v openssl >/dev/null && ss -lnt 2>/dev/null | grep -q ':443 '; then
    echo | openssl s_client -connect localhost:443 -servername localhost \
        2>/dev/null | openssl x509 -noout -subject -issuer -dates 2>/dev/null ||
        check "WARN" "Could not inspect the HTTPS certificate."
else
    check "INFO" "No local HTTPS listener detected."
fi

echo "Recommendation: use HTTPS only, TLS 1.2/1.3, a valid certificate, and HSTS."

# ------------------------------------------------------------
section "3. Web server"
# ------------------------------------------------------------

if command -v nginx >/dev/null; then
    check "INFO" "Nginx detected: $(nginx -v 2>&1)"
    nginx -T 2>/dev/null |
        grep -Ei 'server_name|root |ssl_protocols|ssl_certificate|autoindex|location ' |
        head -80
elif command -v apache2 >/dev/null; then
    check "INFO" "Apache detected: $(apache2 -v 2>/dev/null | head -1)"
    apache2ctl -S 2>/dev/null
else
    check "WARN" "Neither nginx nor apache2 detected."
fi

echo
echo "[Potentially dangerous web files]"
for f in .env .git/config config.inc.php installer/index.php; do
    found=$(find /var/www /usr/share/roundcube -path "*/$f" \
        -type f 2>/dev/null | head -5)
    [[ -n "$found" ]] && echo "WARN: $found"
done

echo "Recommendation: disable directory listing and prevent web access to Roundcube config, logs, temp, backups and VCS files."

# ------------------------------------------------------------
section "4. Roundcube"
# ------------------------------------------------------------

RC_DIR="/var/www/roundcube"

if [[ -n "$RC_DIR" ]]; then
    check "OK" "Roundcube found: $RC_DIR"

    if [[ -f "$RC_DIR/config/config.inc.php" ]]; then
        check "OK" "config.inc.php exists"

        # Corrected des_key check
        if grep -qE "des_key.*=" "$RC_DIR/config/config.inc.php"; then
            check "OK" "Roundcube des_key is configured"
        else
            check "FAIL" "Roundcube des_key is missing"
        fi

        grep -E "^\s*\$config\['(default_host|smtp_server|smtp_port|imap_host|imap_port|force_https|session_lifetime)'\]" \
            "$RC_DIR/config/config.inc.php" 2>/dev/null

        perms=$(stat -c '%a %U:%G' "$RC_DIR/config/config.inc.php" 2>/dev/null)
        echo "Config permissions: $perms"
    else
        check "WARN" "Roundcube config.inc.php not found."
    fi

    [[ -d "$RC_DIR/installer" ]] &&
        check "FAIL" "Roundcube installer directory exists: $RC_DIR/installer" ||
        check "OK" "Roundcube installer directory not found"

    for d in "$RC_DIR/logs" "$RC_DIR/temp"; do
        if [[ -d "$d" ]]; then
            check "INFO" "$d exists: $(stat -c '%a %U:%G' "$d")"
            if find "$d" -type f -perm -004 -print -quit 2>/dev/null | grep -q .; then
                check "FAIL" "Files in $d are world-readable"
            fi
        fi
    done

    if [[ -f "$RC_DIR/composer.json" ]]; then
        grep -E '"version"|"name"' "$RC_DIR/composer.json" | head
    fi
else
    check "WARN" "Roundcube installation directory not automatically located."
fi

echo "Recommendation: keep Roundcube current, use a strong unique des_key, remove the installer, and protect config/log/temp files."

# ------------------------------------------------------------
section "5. Roundcube authentication / IMAP"
# ------------------------------------------------------------

if [[ -n "$RC_DIR" && -f "$RC_DIR/config/config.inc.php" ]]; then
    grep -E "^\s*\$config\['(imap_host|imap_port|smtp_server|smtp_port|smtp_user|smtp_pass|password_charset)'\]" \
        "$RC_DIR/config/config.inc.php" 2>/dev/null
fi

echo
echo "[Dovecot authentication configuration]"
if command -v doveconf >/dev/null; then
    doveconf -n 2>/dev/null |
        grep -Ei '^(auth_mechanisms|auth_allow_cleartext|disable_plaintext_auth|ssl|ssl_min_protocol|protocols|listen|mail_location)' ||
        true
else
    check "WARN" "doveconf not found."
fi

echo "Recommendation: never permit plaintext authentication without TLS. Prefer IMAPS/STARTTLS with modern TLS."

# ------------------------------------------------------------
section "6. Dovecot"
# ------------------------------------------------------------

if command -v doveconf >/dev/null; then
    echo "[Dovecot effective configuration]"
    doveconf -n 2>/dev/null |
        grep -Ei '^(protocols|listen|ssl|ssl_min_protocol|ssl_cipher_list|auth_mechanisms|mail_location|service auth|service imap|service pop3)' |
        head -100

    echo
    echo "[Dovecot version]"
    doveconf --version 2>/dev/null
else
    check "WARN" "Dovecot configuration tool unavailable."
fi

# ------------------------------------------------------------
section "7. Exposed mail ports"
# ------------------------------------------------------------

echo "[Listening TCP ports]"
ss -lntp 2>/dev/null |
    awk 'NR==1 || /:(25|110|143|465|587|993|995)\b/'

echo
echo "Port guidance:"
echo "  25   SMTP        Internet mail delivery"
echo "  465  SMTPS       Submission (if used)"
echo "  587  Submission  Authenticated client submission"
echo "  993  IMAPS       Secure IMAP"
echo "  110/143/995      Avoid unless specifically required"

echo "Recommendation: expose only services you actually need; prefer 587 + 993 for clients."

# ------------------------------------------------------------
section "8. Postfix submission / SMTP AUTH"
# ------------------------------------------------------------

if command -v postconf >/dev/null; then
    echo "[Postfix version]"
    postconf mail_version

    echo
    echo "[SMTP/TLS/authentication configuration]"
    postconf -n 2>/dev/null |
        grep -Ei '^(inet_interfaces|inet_protocols|smtpd_tls|smtp_tls|smtpd_sasl|smtpd_recipient_restrictions|smtpd_relay_restrictions|smtpd_client_restrictions|submission|smtps)' |
        head -150

    echo
    echo "[master.cf submission services]"
    postconf -M 2>/dev/null |
        grep -E '^(submission|smtps)/' || true
else
    check "WARN" "postconf not found."
fi

echo
echo "Recommendation: require TLS + SMTP AUTH on submission (587/465), and never allow unauthenticated relay."

# ------------------------------------------------------------
section "9. Open relay sanity check"
# ------------------------------------------------------------

if command -v postconf >/dev/null; then
    echo "[Relay-related effective settings]"
    postconf -h mynetworks
    postconf -h relay_domains
    postconf -h smtpd_relay_restrictions
    postconf -h smtpd_recipient_restrictions 2>/dev/null
fi

echo
echo "IMPORTANT: configuration inspection cannot prove that the server is not an open relay."
echo "Perform an external SMTP relay test from a host NOT listed in mynetworks."
echo
echo "Safe manual test:"
echo "  openssl s_client -starttls smtp -connect YOUR_SERVER:25"
echo "Then attempt an unauthenticated RCPT TO for an external destination."
echo "It should be rejected (typically 5xx), not accepted for delivery."

# ------------------------------------------------------------
section "Summary / priority"
# ------------------------------------------------------------

cat <<'EOF'
HIGH PRIORITY:
  1. Roundcube must be HTTPS-only and fully patched.
  2. Remove/disable the Roundcube installer.
  3. Protect Roundcube config/log/temp directories.
  4. Dovecot must not accept plaintext authentication without TLS.
  5. SMTP AUTH should be restricted to authenticated submission.
  6. Verify Postfix is NOT an open relay from an external network.
  7. Expose only required mail/web ports.
  8. Use modern TLS on HTTPS, IMAP and SMTP submission.

This script is an audit aid, not a substitute for an external vulnerability scan.
EOF
