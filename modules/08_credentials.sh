#!/bin/bash
run_credential_hunt() {
    echo -e "${YELLOW}========================================${NC}"
    echo -e "${YELLOW}PHASE 8: Credential Hunting${NC}"
    echo -e "${YELLOW}========================================${NC}"
    log_info "Credential hunting via LDAP attributes"

    mkdir -p creds

    # NOTE: GPP cpassword hunting lives in 05_gpo.sh; share-based credential
    # discovery lives in 07_shares.sh. This module focuses on credential-bearing
    # attributes stored directly on directory objects.

    # LDAP pass for credentials stashed in user attributes that 01 may not surface.
    run_ldap "(|(userPassword=*)(unixUserPassword=*)(unicodePwd=*)(ms-MCS-AdmPwd=*))" \
        "creds/cred_attributes.ldif" \
        "Hunting credential-bearing attributes" \
        "sAMAccountName"

    local cred_count
    cred_count=$(ldif_count_dn "creds/cred_attributes.ldif")
    if [ "$cred_count" -gt 0 ]; then
        local cred_accounts
        cred_accounts=$(ldif_values "sAMAccountName" "creds/cred_attributes.ldif" | paste -sd ',' -)
        log_warning "Found $cred_count object(s) with credential-bearing attributes"
        add_finding "HIGH" "Credential Hunting" \
            "$cred_count object(s) expose credential-bearing attributes (userPassword/unixUserPassword/unicodePwd/ms-MCS-AdmPwd): ${cred_accounts}. Review creds/cred_attributes.ldif." \
            "Inspect creds/cred_attributes.ldif; extract/crack recovered secrets and rotate affected accounts."
    else
        log_info "No credential-bearing attributes readable by this principal"
    fi

    add_finding "INFO" "Credential Hunting" \
        "Credential hunting is distributed across modules: GPP cpassword in 05_gpo.sh, share-stored secrets in 07_shares.sh, and LAPS/gMSA secrets are best recovered via BloodHound/bloodyAD." \
        "Run BloodHound and bloodyAD (e.g. 'bloodyAD get search --filter ms-MCS-AdmPwd=*') for LAPS/gMSA password recovery."

    echo ""
}