#!/bin/bash
run_session_enum() {
    echo -e "${YELLOW}PHASE 9: Session Enumeration${NC}"
    if command -v crackmapexec &>/dev/null; then
        crackmapexec smb $DC_IP -u "$USERNAME" -p "$PASSWORD" --sessions > sessions/sessions.txt 2>&1
    fi
    echo ""
}