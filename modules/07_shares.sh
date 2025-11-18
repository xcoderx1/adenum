#!/bin/bash
run_share_enum() {
    echo -e "${YELLOW}PHASE 7: Share Enumeration${NC}"
    if command -v crackmapexec &>/dev/null; then
        crackmapexec smb $DC_IP -u "$USERNAME" -p "$PASSWORD" --shares > shares/shares.txt 2>&1
    fi
    echo ""
}