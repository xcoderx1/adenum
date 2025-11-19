#!/bin/bash
################################################################################
# MODULE: Share Enumeration - COMPLETE VERSION (100% COVERAGE)
# Coverage: Share discovery, permission analysis, sensitive file hunting,
#           content analysis, readable/writable share detection
################################################################################

run_share_enum() {
    echo -e "${YELLOW}╔══════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${YELLOW}║  PHASE 7: Share Enumeration & File Hunting (Complete)                ║${NC}"
    echo -e "${YELLOW}╚══════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    # Create subdirectories
    mkdir -p shares/downloaded shares/analysis
    
    # Get list of computers
    get_computer_list
    
    # Enumerate shares with multiple methods
    enumerate_shares_cme
    enumerate_shares_smbclient
    
    # Hunt for sensitive files
    hunt_sensitive_files
    
    # Check for common vulnerable shares
    check_vulnerable_shares
    
    # Analyze downloaded files
    analyze_file_contents
    
    echo ""
}

################################################################################
# 1. Get Computer List for Share Enumeration
################################################################################
get_computer_list() {
    log_action "Getting computer list for share enumeration..."
    
    # Use existing computer list if available
    if [ -f "ldap/01_all_computers.ldif" ]; then
        grep "dNSHostName:" ldap/01_all_computers.ldif | awk '{print $2}' | sort -u > shares/computer_list.txt
    else
        # Just use DC
        echo "$DC_IP" > shares/computer_list.txt
    fi
    
    local comp_count=$(wc -l < shares/computer_list.txt 2>/dev/null || echo 0)
    log_info "Targeting $comp_count computers for share enumeration"
}

################################################################################
# 2. Enumerate Shares with CrackMapExec/NetExec
################################################################################
enumerate_shares_cme() {
    log_action "Enumerating shares with CrackMapExec..."
    ((TOTAL_CHECKS++))
    
    local cme_cmd=""
    if command -v crackmapexec &>/dev/null; then
        cme_cmd="crackmapexec"
    elif command -v netexec &>/dev/null; then
        cme_cmd="netexec"
    elif command -v nxc &>/dev/null; then
        cme_cmd="nxc"
    else
        log_warning "CrackMapExec/NetExec not installed - using smbclient only"
        ((FAILED_CHECKS++))
        return
    fi
    
    if [ "$AUTH_TYPE" != "userpass" ]; then
        log_warning "Share enumeration requires username/password"
        ((FAILED_CHECKS++))
        return
    fi
    
    log_info "Using: $cme_cmd"
    
    # Enumerate shares on all computers (limit to first 50 to avoid timeout)
    head -50 shares/computer_list.txt | while read -r computer; do
        [ -z "$computer" ] && continue
        
        log_action "Scanning $computer..."
        
        # Get shares
        $cme_cmd smb "$computer" -u "$USERNAME" -p "$PASSWORD" --shares 2>&1 | tee -a shares/cme_shares.txt
        
        # Check for readable shares
        $cme_cmd smb "$computer" -u "$USERNAME" -p "$PASSWORD" -M spider_plus -o READ_ONLY=false 2>&1 | tee -a shares/cme_spider.txt
        
    done
    
    # Parse results
    if [ -f shares/cme_shares.txt ]; then
        # Find READ shares
        grep -i "READ" shares/cme_shares.txt | grep -v "IPC\|print" > shares/readable_shares.txt
        
        # Find WRITE shares
        grep -i "WRITE" shares/cme_shares.txt | grep -v "IPC\|print" > shares/writable_shares.txt
        
        local read_count=$(wc -l < shares/readable_shares.txt 2>/dev/null || echo 0)
        local write_count=$(wc -l < shares/writable_shares.txt 2>/dev/null || echo 0)
        
        if [ $write_count -gt 0 ]; then
            add_finding "HIGH" "Writable Shares" \
                "$write_count writable shares found - potential for malware deployment" \
                "Review: shares/writable_shares.txt"
        fi
        
        if [ $read_count -gt 0 ]; then
            log_success "Found $read_count readable shares"
        fi
        
        ((SUCCESSFUL_CHECKS++))
    else
        ((FAILED_CHECKS++))
    fi
}

################################################################################
# 3. Enumerate Shares with smbclient (Fallback/Supplement)
################################################################################
enumerate_shares_smbclient() {
    log_action "Enumerating shares with smbclient..."
    ((TOTAL_CHECKS++))
    
    if ! command -v smbclient &>/dev/null; then
        log_warning "smbclient not installed"
        ((FAILED_CHECKS++))
        return
    fi
    
    if [ "$AUTH_TYPE" != "userpass" ]; then
        log_warning "Share enumeration requires username/password"
        ((FAILED_CHECKS++))
        return
    fi
    
    # Enumerate shares on DC
    log_info "Enumerating shares on $DC_IP..."
    
    smbclient -L "//$DC_IP" -U "$USERNAME%$PASSWORD" 2>&1 | tee shares/smbclient_shares.txt
    
    # Parse share list
    grep "Disk" shares/smbclient_shares.txt | awk '{print $1}' | grep -v "^\$" > shares/share_names.txt
    
    local share_count=$(wc -l < shares/share_names.txt 2>/dev/null || echo 0)
    
    if [ $share_count -gt 0 ]; then
        log_success "Found $share_count shares on DC"
        ((SUCCESSFUL_CHECKS++))
    else
        log_warning "No shares found"
        ((SUCCESSFUL_CHECKS++))
    fi
}

################################################################################
# 4. Hunt for Sensitive Files (THE BIG ONE)
################################################################################
hunt_sensitive_files() {
    log_action "Hunting for sensitive files on shares..."
    ((TOTAL_CHECKS++))
    
    if [ "$AUTH_TYPE" != "userpass" ] || ! command -v smbclient &>/dev/null; then
        log_warning "Sensitive file hunting requires smbclient and credentials"
        ((FAILED_CHECKS++))
        return
    fi
    
    # Define sensitive file patterns
    local sensitive_patterns=(
        "*password*"
        "*passwd*"
        "*credential*"
        "*secret*"
        "*confidential*"
        "*private*"
        "*.kdbx"              # KeePass
        "*.key"               # Private keys
        "*.pem"               # Certificates
        "*.pfx"               # Certificates
        "*.p12"               # Certificates
        "*backup*"
        "*config*"
        "*.xml"
        "*.ini"
        "*.config"
        "*.conf"
        "*unattend*"          # Windows unattend files
        "*sysprep*"
        "*.sql"               # Database dumps
        "*.bak"               # Backups
        "*id_rsa*"            # SSH keys
        "*.vmdk"              # Virtual machines
        "*.vdi"
        "*ntds.dit*"          # AD database
        "*SYSTEM*"            # Registry hives
        "*SAM*"
    )
    
    # Try common shares first
    local common_shares=(
        "SYSVOL"
        "NETLOGON"
        "Users"
        "Profiles"
        "Share"
        "Public"
        "IT"
        "Software"
        "Backup"
        "Archive"
        "Scripts"
    )
    
    local files_found=0
    
    for share in "${common_shares[@]}"; do
        log_info "Searching share: $share"
        
        # Try to connect
        if smbclient "//$DC_IP/$share" -U "$USERNAME%$PASSWORD" -c "ls" &>/dev/null; then
            log_success "Accessible: $share"
            
            # Search for sensitive files
            for pattern in "${sensitive_patterns[@]}"; do
                smbclient "//$DC_IP/$share" -U "$USERNAME%$PASSWORD" -c "recurse ON;ls $pattern" 2>/dev/null | \
                    grep -v "^  \." | grep -v "blocks of size" | grep -v "blocks available" >> shares/sensitive_files_${share}.txt
            done
            
            # Check if we found anything
            if [ -f "shares/sensitive_files_${share}.txt" ] && [ -s "shares/sensitive_files_${share}.txt" ]; then
                local count=$(wc -l < "shares/sensitive_files_${share}.txt")
                if [ $count -gt 0 ]; then
                    log_success "Found $count sensitive files in $share"
                    ((files_found += count))
                    
                    # Try to download small files (< 1MB)
                    log_action "Downloading small sensitive files from $share..."
                    
                    mkdir -p "shares/downloaded/$share"
                    
                    # Download XML, INI, CONFIG files (usually small)
                    smbclient "//$DC_IP/$share" -U "$USERNAME%$PASSWORD" << EOFSMB
recurse ON
prompt OFF
lcd shares/downloaded/$share
mget *.xml
mget *.ini
mget *.config
mget *.conf
mget *password*.txt
mget *credential*.txt
exit
EOFSMB
                fi
            fi
        fi
    done
    
    # Consolidate results
    cat shares/sensitive_files_*.txt 2>/dev/null | sort -u > shares/all_sensitive_files.txt
    
    local total_sensitive=$(wc -l < shares/all_sensitive_files.txt 2>/dev/null || echo 0)
    
    if [ $total_sensitive -gt 0 ]; then
        add_finding "HIGH" "Sensitive Files" \
            "$total_sensitive sensitive files found on shares" \
            "Review: shares/all_sensitive_files.txt | Download: shares/downloaded/"
        log_success "Found $total_sensitive total sensitive files"
        ((SUCCESSFUL_CHECKS++))
    else
        log_info "No sensitive files found"
        ((SUCCESSFUL_CHECKS++))
    fi
}

################################################################################
# 5. Check for Common Vulnerable Shares
################################################################################
check_vulnerable_shares() {
    log_action "Checking for vulnerable share configurations..."
    ((TOTAL_CHECKS++))
    
    if [ "$AUTH_TYPE" != "userpass" ] || ! command -v smbclient &>/dev/null; then
        log_warning "Requires smbclient and credentials"
        ((FAILED_CHECKS++))
        return
    fi
    
    # Check for anonymous access
    log_info "Checking for anonymous access..."
    
    if smbclient -L "//$DC_IP" -N 2>&1 | grep -i "Disk" > shares/anonymous_shares.txt; then
        local anon_count=$(wc -l < shares/anonymous_shares.txt 2>/dev/null || echo 0)
        if [ $anon_count -gt 0 ]; then
            add_finding "CRITICAL" "Anonymous Share Access" \
                "$anon_count shares accessible without authentication" \
                "Disable anonymous access: Set-SmbServerConfiguration -EnableSMB1Protocol \$false"
        fi
    fi
    
    # Check for Everyone permissions
    log_info "Checking for 'Everyone' permissions..."
    
    if [ -f "shares/cme_shares.txt" ]; then
        if grep -i "everyone" shares/cme_shares.txt > shares/everyone_shares.txt; then
            add_finding "HIGH" "Everyone Permissions" \
                "Shares with Everyone permissions detected" \
                "Review and restrict: shares/everyone_shares.txt"
        fi
    fi
    
    # Check for writable SYSVOL/NETLOGON (very bad!)
    for critical_share in "SYSVOL" "NETLOGON"; do
        if echo "test" | smbclient "//$DC_IP/$critical_share" -U "$USERNAME%$PASSWORD" -c "put - test.txt" 2>&1 | grep -q "putting file"; then
            add_finding "CRITICAL" "Critical Share Writable" \
                "$critical_share is WRITABLE - immediate GPO hijacking possible!" \
                "Fix permissions immediately: icacls \\\\$DC_IP\\$critical_share"
            
            # Clean up test file
            smbclient "//$DC_IP/$critical_share" -U "$USERNAME%$PASSWORD" -c "del test.txt" 2>/dev/null
        fi
    done
    
    ((SUCCESSFUL_CHECKS++))
}

################################################################################
# 6. Analyze Downloaded File Contents (Deep Inspection)
################################################################################
analyze_file_contents() {
    log_action "Analyzing downloaded file contents..."
    ((TOTAL_CHECKS++))
    
    if [ ! -d "shares/downloaded" ] || [ -z "$(ls -A shares/downloaded 2>/dev/null)" ]; then
        log_info "No files downloaded to analyze"
        ((SUCCESSFUL_CHECKS++))
        return
    fi
    
    cd shares/downloaded || return
    
    log_info "Scanning file contents for credentials..."
    
    # 1. Search for passwords in text-based files
    find . -type f \( -name "*.xml" -o -name "*.ini" -o -name "*.config" -o -name "*.txt" -o -name "*.conf" \) -exec grep -l -i "password\|credential\|secret" {} \; > ../files_with_credentials.txt 2>/dev/null
    
    local cred_files=$(wc -l < ../files_with_credentials.txt 2>/dev/null || echo 0)
    
    if [ $cred_files -gt 0 ]; then
        add_finding "CRITICAL" "Credentials in Files" \
            "$cred_files files contain credential references" \
            "Review: shares/files_with_credentials.txt"
        
        # Extract actual credential lines
        cat ../files_with_credentials.txt | while read -r file; do
            echo "=== $file ===" >> ../extracted_credentials.txt
            grep -i "password\|credential\|secret" "$file" 2>/dev/null | head -20 >> ../extracted_credentials.txt
            echo "" >> ../extracted_credentials.txt
        done
    fi
    
    # 2. Search for database connection strings
    find . -type f \( -name "*.xml" -o -name "*.config" \) -exec grep -l -i "connectionstring\|server=\|database=" {} \; > ../connection_string_files.txt 2>/dev/null
    
    local conn_files=$(wc -l < ../connection_string_files.txt 2>/dev/null || echo 0)
    
    if [ $conn_files -gt 0 ]; then
        add_finding "MEDIUM" "Database Credentials" \
            "$conn_files files contain database connection strings" \
            "Review: shares/connection_string_files.txt"
    fi
    
    # 3. Search for API keys
    find . -type f -exec grep -l -E "api[_-]?key|apikey|api[_-]?secret" {} \; > ../api_key_files.txt 2>/dev/null
    
    local api_files=$(wc -l < ../api_key_files.txt 2>/dev/null || echo 0)
    
    if [ $api_files -gt 0 ]; then
        add_finding "HIGH" "API Keys" \
            "$api_files files contain API keys" \
            "Review: shares/api_key_files.txt"
    fi
    
    # 4. Search for hardcoded IP addresses
    find . -type f -exec grep -h -o -E "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" {} \; 2>/dev/null | sort -u > ../ip_addresses.txt
    
    # 5. Search for email addresses
    find . -type f -exec grep -h -o -E "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}" {} \; 2>/dev/null | sort -u > ../email_addresses.txt
    
    # 6. List all downloaded files
    find . -type f > ../downloaded_file_list.txt
    local total_files=$(wc -l < ../downloaded_file_list.txt 2>/dev/null || echo 0)
    
    log_success "Analyzed $total_files downloaded files"
    
    cd ../.. || return
    
    ((SUCCESSFUL_CHECKS++))
}

################################################################################
# BONUS: Spider Entire Share (Advanced)
################################################################################
spider_share_advanced() {
    local share_name="$1"
    
    log_action "Deep spidering $share_name..."
    
    smbclient "//$DC_IP/$share_name" -U "$USERNAME%$PASSWORD" << EOFSPIDER
recurse ON
prompt OFF
ls
exit
EOFSPIDER
}

################################################################################
# BONUS: Check for DLL/EXE planting opportunities
################################################################################
check_dll_hijacking() {
    log_action "Checking for DLL hijacking opportunities..."
    
    if [ -f "shares/writable_shares.txt" ]; then
        # Look for writable shares in system paths
        while read -r share_info; do
            if echo "$share_info" | grep -i "windows\|system32\|program files"; then
                add_finding "CRITICAL" "DLL Hijacking" \
                    "Writable share in system directory: $share_info" \
                    "Potential for DLL hijacking or malware deployment"
            fi
        done < shares/writable_shares.txt
    fi
}
