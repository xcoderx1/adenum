#!/bin/bash
################################################################################
# MODULE: Living Off The Land & Persistence Mechanisms
# Coverage: Scheduled tasks, startup items, services, WMI persistence,
#           registry autoruns, DLL hijacking, COM hijacking
################################################################################

run_lolbins_persistence_enum() {
    echo -e "${YELLOW}╔══════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${YELLOW}║  PHASE 14: Living Off The Land & Persistence Analysis                ║${NC}"
    echo -e "${YELLOW}╚══════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    mkdir -p lolbins persistence
    
    # Check for persistence mechanisms
    check_scheduled_tasks
    check_startup_items
    check_suspicious_services
    check_wmi_persistence
    check_registry_autoruns
    check_com_hijacking
    check_dll_search_order
    
    echo ""
}

################################################################################
# 1. Scheduled Tasks (Common Persistence)
################################################################################
check_scheduled_tasks() {
    log_action "Checking for suspicious scheduled tasks..."
    ((TOTAL_CHECKS++))
    
    if [ "$AUTH_TYPE" != "userpass" ]; then
        log_warning "Scheduled task enumeration requires credentials"
        ((FAILED_CHECKS++))
        return
    fi
    
    # Use schtasks.exe via Impacket if available
    if command -v impacket-smbexec &>/dev/null || command -v impacket-wmiexec &>/dev/null; then
        log_info "Enumerating scheduled tasks on DC..."
        
        # Try via WMI
        if command -v impacket-wmiexec &>/dev/null; then
            impacket-wmiexec "$DOMAIN/$USERNAME:$PASSWORD@$DC_IP" "schtasks /query /fo CSV /v" > lolbins/scheduled_tasks.csv 2>&1
        fi
        
        if [ -f lolbins/scheduled_tasks.csv ] && [ -s lolbins/scheduled_tasks.csv ]; then
            # Parse for suspicious patterns
            grep -i "powershell\|cmd\|wscript\|cscript\|mshta\|rundll32\|regsvr32\|certutil" lolbins/scheduled_tasks.csv > lolbins/suspicious_scheduled_tasks.txt 2>/dev/null
            
            local suspicious_count=$(wc -l < lolbins/suspicious_scheduled_tasks.txt 2>/dev/null || echo 0)
            
            if [ $suspicious_count -gt 0 ]; then
                add_finding "MEDIUM" "Suspicious Scheduled Tasks" \
                    "$suspicious_count scheduled tasks with suspicious commands" \
                    "Review: lolbins/suspicious_scheduled_tasks.txt"
            fi
            
            # Check for tasks running as SYSTEM
            grep -i "SYSTEM" lolbins/scheduled_tasks.csv > lolbins/system_scheduled_tasks.txt 2>/dev/null
            
            log_success "Scheduled tasks enumerated"
            ((SUCCESSFUL_CHECKS++))
        else
            log_warning "Could not enumerate scheduled tasks"
            ((FAILED_CHECKS++))
        fi
    else
        log_info "Impacket tools not available for task enumeration"
        ((SUCCESSFUL_CHECKS++))
    fi
}

################################################################################
# 2. Startup Items via GPO/Scripts
################################################################################
check_startup_items() {
    log_action "Checking startup items and logon scripts..."
    ((TOTAL_CHECKS++))
    
    # Check for logon scripts in user profiles
    run_ldap "(&(objectClass=user)(scriptPath=*))" "lolbins/users_with_logon_scripts.ldif" \
        "Finding users with logon scripts" "sAMAccountName scriptPath"
    
    local script_users=$(grep -c "^dn:" lolbins/users_with_logon_scripts.ldif 2>/dev/null || echo 0)
    script_users="${script_users//[^0-9]/}"
    [ -z "$script_users" ] && script_users=0
    
    if [ $script_users -gt 0 ]; then
        log_success "Found $script_users users with logon scripts"
        
        # List the scripts
        grep "scriptPath:" lolbins/users_with_logon_scripts.ldif | awk '{print $2}' | sort -u > lolbins/logon_script_list.txt
        
        add_finding "INFO" "Logon Scripts" \
            "$script_users users have logon scripts configured" \
            "Review scripts in NETLOGON share for hardcoded credentials"
        
        ((SUCCESSFUL_CHECKS++))
    else
        log_info "No logon scripts configured"
        ((SUCCESSFUL_CHECKS++))
    fi
    
    # Check for startup scripts in GPO (if SYSVOL downloaded)
    if [ -d "gpo/sysvol" ]; then
        find gpo/sysvol -type f -name "*.bat" -o -name "*.cmd" -o -name "*.ps1" | grep -i "startup\|logon" > lolbins/startup_script_files.txt 2>/dev/null
        
        local startup_files=$(wc -l < lolbins/startup_script_files.txt 2>/dev/null || echo 0)
        
        if [ $startup_files -gt 0 ]; then
            add_finding "INFO" "Startup Scripts" \
                "$startup_files startup/logon scripts found in GPO" \
                "Review: lolbins/startup_script_files.txt"
        fi
    fi
}

################################################################################
# 3. Suspicious Services
################################################################################
check_suspicious_services() {
    log_action "Checking for suspicious services..."
    ((TOTAL_CHECKS++))
    
    # Query services via WMI if possible
    if [ "$AUTH_TYPE" == "userpass" ] && command -v impacket-wmiexec &>/dev/null; then
        log_info "Enumerating services on DC..."
        
        impacket-wmiexec "$DOMAIN/$USERNAME:$PASSWORD@$DC_IP" "sc query" > lolbins/services.txt 2>&1
        
        if [ -f lolbins/services.txt ] && [ -s lolbins/services.txt ]; then
            # Look for suspicious service names/paths
            grep -i "temp\|appdata\|public\|downloads\|users" lolbins/services.txt > lolbins/suspicious_service_paths.txt 2>/dev/null
            
            local suspicious_services=$(wc -l < lolbins/suspicious_service_paths.txt 2>/dev/null || echo 0)
            
            if [ $suspicious_services -gt 0 ]; then
                add_finding "HIGH" "Suspicious Services" \
                    "$suspicious_services services with suspicious paths (temp, appdata, etc.)" \
                    "Review: lolbins/suspicious_service_paths.txt | Potential malware"
            fi
            
            log_success "Services enumerated"
            ((SUCCESSFUL_CHECKS++))
        else
            log_warning "Could not enumerate services"
            ((FAILED_CHECKS++))
        fi
    else
        log_info "Service enumeration requires credentials and Impacket"
        ((SUCCESSFUL_CHECKS++))
    fi
}

################################################################################
# 4. WMI Persistence
################################################################################
check_wmi_persistence() {
    log_action "Checking for WMI persistence mechanisms..."
    ((TOTAL_CHECKS++))
    
    if [ "$AUTH_TYPE" == "userpass" ] && command -v impacket-wmiexec &>/dev/null; then
        log_info "Checking WMI event consumers..."
        
        # Query WMI event consumers (common persistence)
        impacket-wmiexec "$DOMAIN/$USERNAME:$PASSWORD@$DC_IP" \
            'wmic /NAMESPACE:"\\\\root\\subscription" PATH __EventFilter GET /FORMAT:list' \
            > lolbins/wmi_event_filters.txt 2>&1
        
        impacket-wmiexec "$DOMAIN/$USERNAME:$PASSWORD@$DC_IP" \
            'wmic /NAMESPACE:"\\\\root\\subscription" PATH CommandLineEventConsumer GET /FORMAT:list' \
            > lolbins/wmi_consumers.txt 2>&1
        
        # Check if any exist
        if [ -f lolbins/wmi_consumers.txt ] && grep -q "CommandLineTemplate" lolbins/wmi_consumers.txt; then
            add_finding "HIGH" "WMI Persistence" \
                "WMI Event Consumers detected - potential persistence mechanism" \
                "Review: lolbins/wmi_consumers.txt | Check for malicious consumers"
        fi
        
        log_success "WMI persistence check complete"
        ((SUCCESSFUL_CHECKS++))
    else
        log_info "WMI check requires credentials and Impacket"
        ((SUCCESSFUL_CHECKS++))
    fi
}

################################################################################
# 5. Registry Autoruns
################################################################################
check_registry_autoruns() {
    log_action "Checking registry autorun locations..."
    ((TOTAL_CHECKS++))
    
    if [ "$AUTH_TYPE" == "userpass" ] && command -v impacket-reg &>/dev/null; then
        log_info "Querying registry autorun keys..."
        
        # Common autorun registry keys
        local autorun_keys=(
            "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
            "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
            "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
            "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
        )
        
        for key in "${autorun_keys[@]}"; do
            impacket-reg "$DOMAIN/$USERNAME:$PASSWORD@$DC_IP" query -keyName "$key" >> lolbins/registry_autoruns.txt 2>&1
        done
        
        if [ -f lolbins/registry_autoruns.txt ] && [ -s lolbins/registry_autoruns.txt ]; then
            # Look for suspicious entries
            grep -i "temp\\|appdata\\|public\\|powershell\\|cmd\\|wscript" lolbins/registry_autoruns.txt > lolbins/suspicious_autoruns.txt 2>/dev/null
            
            local suspicious_autoruns=$(wc -l < lolbins/suspicious_autoruns.txt 2>/dev/null || echo 0)
            
            if [ $suspicious_autoruns -gt 0 ]; then
                add_finding "HIGH" "Suspicious Autoruns" \
                    "$suspicious_autoruns suspicious registry autorun entries" \
                    "Review: lolbins/suspicious_autoruns.txt"
            fi
            
            log_success "Registry autoruns enumerated"
            ((SUCCESSFUL_CHECKS++))
        else
            log_warning "Could not query registry"
            ((FAILED_CHECKS++))
        fi
    else
        log_info "Registry check requires credentials and Impacket"
        ((SUCCESSFUL_CHECKS++))
    fi
}

################################################################################
# 6. COM Hijacking Opportunities
################################################################################
check_com_hijacking() {
    log_action "Checking for COM hijacking opportunities..."
    ((TOTAL_CHECKS++))
    
    # This is complex and requires deep registry analysis
    # For now, flag areas to check manually
    
    cat > persistence/com_hijacking_guide.txt << 'EOFCOM'
╔══════════════════════════════════════════════════════════════════════╗
║  COM HIJACKING DETECTION GUIDE                                       ║
╚══════════════════════════════════════════════════════════════════════╝

COM hijacking allows persistence via registry manipulation.

KEY REGISTRY LOCATIONS:
────────────────────────────────────────────────────────────────────────
HKCU\Software\Classes\CLSID\{GUID}\InprocServer32
HKCU\Software\Classes\CLSID\{GUID}\LocalServer32

COMMON HIJACKABLE CLSIDs:
────────────────────────────────────────────────────────────────────────
{BCDE0395-E52F-467C-8E3D-C4579291692E} - MMDeviceEnumerator (audio)
{b5f8350b-0548-48b1-a6ee-88bd00b4a5e7} - PowerShell
{00021401-0000-0000-C000-000000000046} - ShellLink

DETECTION:
────────────────────────────────────────────────────────────────────────
1. Check for CLSID entries in HKCU that override HKLM
2. Verify DLL paths point to legitimate locations
3. Look for suspicious or non-standard DLL names

MANUAL CHECK COMMANDS:
────────────────────────────────────────────────────────────────────────
reg query "HKCU\Software\Classes\CLSID" /s | findstr "InprocServer32 LocalServer32"

Look for:
- Paths to temp directories
- Paths to user-writable locations
- Non-standard DLL names
EOFCOM
    
    log_info "COM hijacking requires manual registry analysis"
    add_finding "INFO" "COM Hijacking" \
        "Manual check recommended for COM object hijacking" \
        "Review: persistence/com_hijacking_guide.txt"
    
    ((SUCCESSFUL_CHECKS++))
}

################################################################################
# 7. DLL Search Order Hijacking
################################################################################
check_dll_search_order() {
    log_action "Checking DLL search order hijacking opportunities..."
    ((TOTAL_CHECKS++))
    
    # Check if we found writable shares in system paths
    if [ -f "shares/writable_shares.txt" ]; then
        # Look for writable shares that could be used for DLL planting
        grep -i "windows\\|system32\\|program files" shares/writable_shares.txt > persistence/dll_hijack_opportunities.txt 2>/dev/null
        
        local dll_opps=$(wc -l < persistence/dll_hijack_opportunities.txt 2>/dev/null || echo 0)
        
        if [ $dll_opps -gt 0 ]; then
            add_finding "CRITICAL" "DLL Hijacking Opportunity" \
                "$dll_opps writable locations in system paths - DLL hijacking possible" \
                "Review: persistence/dll_hijack_opportunities.txt | Fix permissions immediately"
        fi
    fi
    
    # Create DLL hijacking guide
    cat > persistence/dll_hijacking_guide.txt << 'EOFDLL'
╔══════════════════════════════════════════════════════════════════════╗
║  DLL SEARCH ORDER HIJACKING GUIDE                                    ║
╚══════════════════════════════════════════════════════════════════════╝

DLL search order in Windows:
1. The directory from which the application loaded
2. The system directory (C:\Windows\System32)
3. The 16-bit system directory
4. The Windows directory (C:\Windows)
5. The current directory
6. Directories in the PATH environment variable

EXPLOITATION:
────────────────────────────────────────────────────────────────────────
If you can write to any directory that:
1. Is searched before the legitimate DLL location
2. Is writable by low-privileged users
3. Contains executables that load DLLs

You can plant a malicious DLL that will be loaded instead.

COMMON TARGETS:
────────────────────────────────────────────────────────────────────────
- WLBSCTRL.dll (loaded by many apps, not present by default)
- VERSION.dll
- DWMAPI.dll
- UxTheme.dll

DETECTION:
────────────────────────────────────────────────────────────────────────
1. Check permissions on system directories
2. Look for writable directories in PATH
3. Monitor for DLLs loaded from unexpected locations

TOOLS:
────────────────────────────────────────────────────────────────────────
- Process Monitor (Sysinternals): Filter on "NAME NOT FOUND" DLL loads
- icacls: Check directory permissions
EOFDLL
    
    ((SUCCESSFUL_CHECKS++))
}

################################################################################
# BONUS: Generate Persistence Detection Report
################################################################################
generate_persistence_report() {
    cat > persistence/PERSISTENCE_SUMMARY.txt << 'EOFPERS'
╔══════════════════════════════════════════════════════════════════════╗
║  PERSISTENCE MECHANISMS - DETECTION SUMMARY                          ║
╚══════════════════════════════════════════════════════════════════════╝

This report summarizes potential persistence mechanisms in the environment.

CATEGORIES CHECKED:
────────────────────────────────────────────────────────────────────────
✓ Scheduled Tasks
✓ Startup Items / Logon Scripts
✓ Windows Services
✓ WMI Event Consumers
✓ Registry Autoruns
✓ COM Object Hijacking
✓ DLL Search Order Hijacking

HIGH-PRIORITY CHECKS:
────────────────────────────────────────────────────────────────────────
1. Review all scheduled tasks for suspicious commands
2. Validate service executables are in legitimate locations
3. Check WMI event consumers (rare in normal environments)
4. Verify registry autorun entries
5. Look for CLSID overrides in HKCU

TOOLS FOR DEEPER ANALYSIS:
────────────────────────────────────────────────────────────────────────
- Autoruns (Sysinternals): Comprehensive autostart analysis
- Process Monitor: Real-time persistence detection
- PowerShell: Get-ScheduledTask, Get-Service, Get-WmiObject

REMEDIATION:
────────────────────────────────────────────────────────────────────────
- Remove unauthorized scheduled tasks
- Disable suspicious services
- Delete malicious WMI consumers
- Clean registry autorun entries
- Fix directory permissions to prevent DLL hijacking
EOFPERS
}
