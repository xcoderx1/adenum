#!/bin/bash
################################################################################
# MODULE: Active Directory Certificate Services (ADCS)
# Coverage: ESC1-ESC16, Certificate template vulnerabilities
################################################################################

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
    ((TOTAL_CHECKS++))
    
    cd adcs || exit
    
    # Run Certipy find with vulnerability detection
    $CERTIPY_CMD find -u "$USERNAME@$DOMAIN" -p "$PASSWORD" -dc-ip "$DC_IP" \
        -vulnerable -stdout 2>&1 | tee certipy_output.txt
    
    if [ $? -eq 0 ]; then
        log_success "ADCS scan complete"
        ((SUCCESSFUL_CHECKS++))
        
        # Check for specific ESC vulnerabilities
        for esc in ESC{1..16}; do
            if grep -q "$esc" certipy_output.txt; then
                local esc_desc=""
                case "$esc" in
                    ESC1) esc_desc="Misconfigured Certificate Templates (SAN abuse)" ;;
                    ESC2) esc_desc="Any Purpose EKU" ;;
                    ESC3) esc_desc="Enrollment Agent Templates" ;;
                    ESC4) esc_desc="Vulnerable Template Access Control" ;;
                    ESC5) esc_desc="Vulnerable PKI Object Access Control" ;;
                    ESC6) esc_desc="EDITF_ATTRIBUTESUBJECTALTNAME2" ;;
                    ESC7) esc_desc="Vulnerable CA Access Control" ;;
                    ESC8) esc_desc="NTLM Relay to AD CS HTTP Endpoints" ;;
                    *) esc_desc="Certificate Services Vulnerability" ;;
                esac
                
                add_finding "CRITICAL" "ADCS - $esc" "$esc_desc vulnerability detected!" \
                    "certipy req -u $USERNAME@$DOMAIN -p PASSWORD -ca CA_NAME -template TEMPLATE -upn admin@$DOMAIN"
            fi
        done
        
        # Save detailed output
        $CERTIPY_CMD find -u "$USERNAME@$DOMAIN" -p "$PASSWORD" -dc-ip "$DC_IP" \
            -vulnerable -json -stdout > certipy_detailed.json 2>&1
        
    else
        log_error "ADCS scan failed"
        ((FAILED_CHECKS++))
    fi
    
    # Also enumerate certificate templates via LDAP
    run_ldap "(objectClass=pKICertificateTemplate)" \
        "../ldap/adcs_templates.ldif" "Enumerating certificate templates"
    
    cd .. || exit
    echo ""
}
