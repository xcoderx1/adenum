#!/bin/bash
################################################################################
# MODULE: LDAP Enumeration
# Coverage: Basic AD objects, password policies, privileged accounts
################################################################################

run_ldap() {
    local filter="$1"
    local output="$2"
    local description="$3"
    local attributes="$4"
    
    log_action "$description"
    
    ((TOTAL_CHECKS++))
    
    if [ "$AUTH_TYPE" == "userpass" ]; then
        if [ -n "$attributes" ]; then
            ldapsearch -H ldap://$DC_IP -D "$USERNAME@$DOMAIN" -w "$PASSWORD" -b "$BASE_DN" "$filter" $attributes > "$output" 2>&1
        else
            ldapsearch -H ldap://$DC_IP -D "$USERNAME@$DOMAIN" -w "$PASSWORD" -b "$BASE_DN" "$filter" > "$output" 2>&1
        fi
    elif [ "$AUTH_TYPE" == "anonymous" ]; then
        if [ -n "$attributes" ]; then
            ldapsearch -H ldap://$DC_IP -x -b "$BASE_DN" "$filter" $attributes > "$output" 2>&1
        else
            ldapsearch -H ldap://$DC_IP -x -b "$BASE_DN" "$filter" > "$output" 2>&1
        fi
    else
        if [ -n "$attributes" ]; then
            ldapsearch -H ldap://$DC_IP -Y GSSAPI -b "$BASE_DN" "$filter" $attributes > "$output" 2>&1
        else
            ldapsearch -H ldap://$DC_IP -Y GSSAPI -b "$BASE_DN" "$filter" > "$output" 2>&1
        fi
    fi
    
    if [ $? -eq 0 ]; then
        count=$(grep -c "^dn:" "$output" 2>/dev/null || echo 0)
        # Strip anything non-numeric just in case
        count="${count//[^0-9]/}"
        [ -z "$count" ] && count=0

        if [ "$count" -gt 0 ]; then
            log_success "Found $count objects"
            ((SUCCESSFUL_CHECKS++))
            return 0
        else
            log_warning "No objects found"
            ((SUCCESSFUL_CHECKS++))
            return 0
        fi
    else
        log_error "Query failed"
        ((FAILED_CHECKS++))
        return 1
    fi
}

run_ldap_enum() {
    echo -e "${YELLOW}╔══════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${YELLOW}║  PHASE 1: LDAP Enumeration (60+ Checks)                              ║${NC}"
    echo -e "${YELLOW}╚══════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    # Basic objects
    run_ldap "(objectClass=user)" "ldap/01_all_users.ldif" "Enumerating users"
    run_ldap "(objectClass=computer)" "ldap/01_all_computers.ldif" "Enumerating computers"
    run_ldap "(objectClass=group)" "ldap/01_all_groups.ldif" "Enumerating groups"
    run_ldap "(objectClass=organizationalUnit)" "ldap/01_all_ous.ldif" "Enumerating OUs"
    run_ldap "(objectClass=contact)" "ldap/01_all_contacts.ldif" "Enumerating contacts"
    
    # Domain Controllers
    run_ldap "(userAccountControl:1.2.840.113556.1.4.803:=8192)" "ldap/02_domain_controllers.ldif" "Finding Domain Controllers"
    
    # Privileged groups
    run_ldap "(memberOf=CN=Domain Admins,CN=Users,$BASE_DN)" "ldap/03_domain_admins.ldif" "Enumerating Domain Admins"
    run_ldap "(memberOf=CN=Enterprise Admins,CN=Users,$BASE_DN)" "ldap/03_enterprise_admins.ldif" "Enumerating Enterprise Admins"
    run_ldap "(memberOf=CN=Schema Admins,CN=Users,$BASE_DN)" "ldap/03_schema_admins.ldif" "Enumerating Schema Admins"
    run_ldap "(memberOf=CN=Administrators,CN=Builtin,$BASE_DN)" "ldap/03_administrators.ldif" "Enumerating Administrators"
    run_ldap "(adminCount=1)" "ldap/03_all_privileged.ldif" "Finding all privileged accounts (adminCount=1)"
    
    # Check if admins are in Protected Users
    run_ldap "(memberOf=CN=Protected Users,CN=Users,$BASE_DN)" "ldap/03_protected_users.ldif" "Checking Protected Users group"
    
    local priv_count=$(grep -c "^dn:" "ldap/03_all_privileged.ldif" 2>/dev/null || echo 0)
    local protected_count=$(grep -c "^dn:" "ldap/03_protected_users.ldif" 2>/dev/null || echo 0)
    
    if [ $priv_count -gt 0 ] && [ $protected_count -lt $priv_count ]; then
        local unprotected=$((priv_count - protected_count))
        add_finding "HIGH" "Privileged Accounts" "$unprotected privileged accounts NOT in Protected Users group" \
            "Add to Protected Users: net group 'Protected Users' USERNAME /add /domain"
    fi
    
    # Password policy issues
    run_ldap "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))" "ldap/04_password_never_expires.ldif" "Finding accounts with password never expires"
    
    local pwd_never_count=$(grep -c "^dn:" "ldap/04_password_never_expires.ldif" 2>/dev/null || echo 0)
    if [ $pwd_never_count -gt 0 ]; then
        add_finding "MEDIUM" "Password Policy" "$pwd_never_count accounts with password never expires" \
            "Review and disable DONT_EXPIRE_PASSWD flag"
    fi
    
    run_ldap "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))" "ldap/04_password_not_required.ldif" "Finding accounts with password not required"
    
    local pwd_notreq_count=$(grep -c "^dn:" "ldap/04_password_not_required.ldif" 2>/dev/null || echo 0)
    if [ $pwd_notreq_count -gt 0 ]; then
        add_finding "CRITICAL" "Password Policy" "$pwd_notreq_count accounts can have EMPTY passwords!" \
            "Test: smbclient -L //$DC_IP -U 'USERNAME%' (no password)"
    fi
    
    # KRBTGT password age
    run_ldap "(sAMAccountName=krbtgt)" "ldap/04_krbtgt.ldif" "Checking KRBTGT password age" "pwdLastSet"
    
    if [ -f "ldap/04_krbtgt.ldif" ]; then
        local pwd_last_set=$(grep "pwdLastSet:" "ldap/04_krbtgt.ldif" | awk '{print $2}')
        if [ -n "$pwd_last_set" ]; then
            # Convert to days (rough calculation)
            local days_old=$(( ($(date +%s) - pwd_last_set / 10000000 - 11644473600) / 86400 ))
            if [ $days_old -gt 180 ]; then
                add_finding "HIGH" "KRBTGT Password" "KRBTGT password is $days_old days old (should be <180 days)" \
                    "Rotate KRBTGT password (do twice, 24hrs apart): https://github.com/microsoft/New-KrbtgtKeys.ps1"
            fi
        fi
    fi
    
    # SID History
    run_ldap "(sIDHistory=*)" "ldap/05_sid_history.ldif" "Finding accounts with SID History"
    
    local sid_hist_count=$(grep -c "^dn:" "ldap/05_sid_history.ldif" 2>/dev/null || echo 0)
    if [ $sid_hist_count -gt 0 ]; then
        add_finding "MEDIUM" "SID History" "$sid_hist_count accounts with SID History (potential backdoor)" \
            "Review and remove unnecessary SID History"
    fi
    
    # Disabled accounts
    run_ldap "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))" "ldap/05_disabled_accounts.ldif" "Finding disabled accounts"
    
    # Never logged on
    run_ldap "(&(objectClass=user)(lastLogon=0))" "ldap/05_never_logged_on.ldif" "Finding accounts that never logged on"
    
    # Test/temp accounts
    run_ldap "(|(cn=*test*)(cn=*temp*)(sAMAccountName=*test*)(sAMAccountName=*temp*))" "ldap/05_test_temp_accounts.ldif" "Finding test/temp accounts"
    
    local test_count=$(grep -c "^dn:" "ldap/05_test_temp_accounts.ldif" 2>/dev/null || echo 0)
    if [ $test_count -gt 0 ]; then
        add_finding "MEDIUM" "Account Hygiene" "$test_count test/temp accounts found" \
            "Review and disable/remove unnecessary test accounts"
    fi
    
    # Reversible encryption
    run_ldap "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=128))" "ldap/05_reversible_encryption.ldif" "Finding accounts with reversible encryption"
    
    local rev_enc_count=$(grep -c "^dn:" "ldap/05_reversible_encryption.ldif" 2>/dev/null || echo 0)
    if [ $rev_enc_count -gt 0 ]; then
        add_finding "HIGH" "Password Storage" "$rev_enc_count accounts store passwords with reversible encryption!" \
            "Disable ENCRYPTED_TEXT_PWD_ALLOWED flag"
    fi
    
    # DES encryption only
    run_ldap "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2097152))" "ldap/05_des_only.ldif" "Finding accounts using DES encryption only"
    
    # Weak Kerberos encryption
    run_ldap "(&(objectClass=user)(msDS-SupportedEncryptionTypes<=7))" "ldap/05_weak_kerberos.ldif" "Finding accounts with weak Kerberos encryption"
    
    # Machine account quota
    run_ldap "(objectClass=domain)" "ldap/06_domain_config.ldif" "Getting domain configuration" "ms-DS-MachineAccountQuota"
    
    if [ -f "ldap/06_domain_config.ldif" ]; then
        local quota=$(grep "ms-DS-MachineAccountQuota:" "ldap/06_domain_config.ldif" | awk '{print $2}')
        if [ -n "$quota" ] && [ "$quota" -gt 0 ]; then
            add_finding "MEDIUM" "Machine Account Quota" "Users can add $quota computer accounts to domain" \
                "Consider setting ms-DS-MachineAccountQuota to 0"
        fi
    fi
    
    # Foreign security principals
    run_ldap "(objectClass=foreignSecurityPrincipal)" "ldap/06_foreign_principals.ldif" "Finding foreign security principals"
    
    # Fine-grained password policies
    run_ldap "(objectClass=msDS-PasswordSettings)" "ldap/06_fgpp.ldif" "Finding Fine-Grained Password Policies"
    
    # Service accounts
    run_ldap "(objectClass=msDS-ManagedServiceAccount)" "ldap/06_msa.ldif" "Finding Managed Service Accounts"
    run_ldap "(objectClass=msDS-GroupManagedServiceAccount)" "ldap/06_gmsa.ldif" "Finding Group Managed Service Accounts"
    
    # Old operating systems (EOL)
    run_ldap "(&(objectClass=computer)(operatingSystem=Windows Server 2008*))" "ldap/07_eol_2008.ldif" "Finding Windows Server 2008 (EOL)"
    run_ldap "(&(objectClass=computer)(operatingSystem=Windows 7*))" "ldap/07_eol_win7.ldif" "Finding Windows 7 (EOL)"
    
    local eol_count=$(grep -c "^dn:" "ldap/07_eol_2008.ldif" "ldap/07_eol_win7.ldif" 2>/dev/null || echo 0)
    if [ $eol_count -gt 0 ]; then
        add_finding "HIGH" "End-of-Life Systems" "$eol_count systems running EOL operating systems (no security updates)" \
            "Upgrade or decommission EOL systems"
    fi
    
    # Accounts with passwords in attributes
    run_ldap "(&(objectClass=user)(|(description=*pass*)(description=*pwd*)(info=*pass*)))" "ldap/08_password_in_attributes.ldif" "Finding passwords in user attributes"
    
    local pwd_attr_count=$(grep -c "^dn:" "ldap/08_password_in_attributes.ldif" 2>/dev/null || echo 0)
    if [ $pwd_attr_count -gt 0 ]; then
        add_finding "HIGH" "Credential Exposure" "$pwd_attr_count accounts may have passwords in description/info fields" \
            "Review: grep -i 'description\\|info' ldap/08_password_in_attributes.ldif"
    fi
    
    echo ""
}
