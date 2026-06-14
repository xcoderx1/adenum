#!/bin/bash
run_session_enum() {
    echo -e "${YELLOW}PHASE 9: Session Enumeration${NC}"

    mkdir -p sessions
    TOTAL_CHECKS=$((TOTAL_CHECKS+1))

    if [ "$AUTH_TYPE" != "userpass" ]; then
        log_warning "Session enumeration requires username/password"
        return
    fi

    # Pick the first available SMB enumeration tool.
    local cme=""
    if command -v crackmapexec &>/dev/null; then
        cme="crackmapexec"
    elif command -v netexec &>/dev/null; then
        cme="netexec"
    elif command -v nxc &>/dev/null; then
        cme="nxc"
    else
        log_warning "Session enumeration requires crackmapexec, netexec, or nxc (none found)"
        return
    fi

    log_action "Enumerating SMB sessions on $DC_IP with $cme"
    "$cme" smb "$DC_IP" -u "$USERNAME" -p "$PASSWORD" --sessions > sessions/sessions.txt 2>&1
    if [ $? -eq 0 ]; then SUCCESSFUL_CHECKS=$((SUCCESSFUL_CHECKS + 1)); else FAILED_CHECKS=$((FAILED_CHECKS + 1)); fi

    if grep -qi 'sessions\|[+]' sessions/sessions.txt 2>/dev/null; then
        log_success "Session enumeration permitted on $DC_IP"
        add_finding "INFO" "Session Enumeration" \
            "Session enumeration permitted on $DC_IP (enables user-hunting). Modern Windows restricts NetSessionEnum to administrators; if this succeeds, the SrvsvcSessionInfo permissions may be loosened." \
            "https://github.com/p0dalirius/windows-coerced-authentication-methods"
    else
        log_info "Session enumeration appears restricted on $DC_IP"
    fi

    # Best-effort logged-on users check (ignore failure).
    "$cme" smb "$DC_IP" -u "$USERNAME" -p "$PASSWORD" --loggedon-users > sessions/loggedon.txt 2>&1 || true

    echo ""
}
