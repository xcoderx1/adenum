#!/bin/bash
################################################################################
# MODULE: Report Generation - FIXED VERSION
# Generates modern HTML dashboard and text reports
# FIX: Properly escapes pipe characters and HTML entities
################################################################################

# FIX: New function to escape HTML entities
escape_html() {
    local text="$1"
    # Escape HTML special characters
    text="${text//&/&amp;}"
    text="${text//</&lt;}"
    text="${text//>/&gt;}"
    text="${text//\"/&quot;}"
    text="${text//\'/&#39;}"
    echo "$text"
}

# FIX: New function to escape text for safe parsing
escape_for_storage() {
    local text="$1"
    # Replace pipe with unicode pipe to avoid parsing issues
    text="${text//|/│}"
    # Remove problematic characters
    text="${text//$'\n'/ }"
    text="${text//$'\r'/}"
    echo "$text"
}

generate_reports() {
    echo -e "${YELLOW}╔══════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${YELLOW}║  Generating Reports                                                   ║${NC}"
    echo -e "${YELLOW}╚══════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    log_action "Generating comprehensive reports..."
    
    # Generate HTML report
    generate_html_report
    
    # Generate text report
    generate_text_report
    
    log_success "Reports generated in reports/ directory"
}

generate_html_report() {
    local html_file="reports/ULTIMATE_REPORT.html"
    
    cat > "$html_file" << 'HTMLHEADER'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Ultimate AD Assessment Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            color: #333;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #2d3748 0%, #1a202c 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }
        
        .header .subtitle {
            font-size: 1.1em;
            opacity: 0.9;
        }
        
        .stats-container {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 30px;
            background: #f7fafc;
        }
        
        .stat-box {
            background: white;
            padding: 25px;
            border-radius: 10px;
            text-align: center;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            transition: transform 0.3s;
        }
        
        .stat-box:hover {
            transform: translateY(-5px);
        }
        
        .stat-number {
            font-size: 3em;
            font-weight: bold;
            margin-bottom: 10px;
        }
        
        .stat-label {
            font-size: 1.1em;
            color: #666;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .critical { color: #e53e3e; }
        .high { color: #dd6b20; }
        .medium { color: #d69e2e; }
        .info { color: #3182ce; }
        
        .controls {
            padding: 20px 30px;
            background: #edf2f7;
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
            align-items: center;
        }
        
        .search-box {
            flex: 1;
            min-width: 250px;
            padding: 12px 20px;
            border: 2px solid #cbd5e0;
            border-radius: 8px;
            font-size: 1em;
        }
        
        .filter-btn {
            padding: 12px 25px;
            border: none;
            border-radius: 8px;
            font-size: 1em;
            cursor: pointer;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            transition: all 0.3s;
        }
        
        .filter-btn:hover { transform: scale(1.05); }
        
        .btn-all { background: #4299e1; color: white; }
        .btn-critical { background: #e53e3e; color: white; }
        .btn-high { background: #dd6b20; color: white; }
        .btn-medium { background: #d69e2e; color: white; }
        .btn-info { background: #3182ce; color: white; }
        
        .findings {
            padding: 30px;
        }
        
        .finding-card {
            background: white;
            border-left: 5px solid;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 15px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            transition: all 0.3s;
        }
        
        .finding-card:hover {
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
            transform: translateX(5px);
        }
        
        .finding-card.critical { border-left-color: #e53e3e; background: #fff5f5; }
        .finding-card.high { border-left-color: #dd6b20; background: #fffaf0; }
        .finding-card.medium { border-left-color: #d69e2e; background: #fffff0; }
        .finding-card.info { border-left-color: #3182ce; background: #f0f9ff; }
        .finding-card.hidden { display: none; }
        
        .finding-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }
        
        .finding-level {
            display: inline-block;
            padding: 5px 15px;
            border-radius: 20px;
            font-weight: bold;
            font-size: 0.85em;
            text-transform: uppercase;
        }
        
        .level-critical { background: #e53e3e; color: white; }
        .level-high { background: #dd6b20; color: white; }
        .level-medium { background: #d69e2e; color: white; }
        .level-info { background: #3182ce; color: white; }
        
        .finding-category {
            color: #718096;
            font-size: 0.9em;
            font-weight: 600;
        }
        
        .finding-message {
            font-size: 1.1em;
            margin: 15px 0;
            line-height: 1.6;
        }
        
        .exploit-ref {
            background: #2d3748;
            color: #68d391;
            padding: 15px;
            border-radius: 6px;
            margin-top: 15px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            white-space: pre-wrap;
            word-wrap: break-word;
            overflow-wrap: break-word;
        }
        
        .exploit-ref strong {
            color: #fbb6ce;
        }
        
        .timestamp {
            color: #a0aec0;
            font-size: 0.85em;
            margin-top: 10px;
        }
        
        .footer {
            background: #2d3748;
            color: white;
            padding: 30px;
            text-align: center;
        }
        
        .no-results {
            text-align: center;
            padding: 40px;
            color: #718096;
            font-size: 1.2em;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🎯 Ultimate AD Security Assessment</h1>
            <p class="subtitle">Comprehensive Active Directory Enumeration & Exploitation Analysis</p>
            <p class="subtitle" style="margin-top: 10px;">
HTMLHEADER
    
    # Add dynamic content
    echo "                Domain: $DOMAIN | DC: $DC_IP | Generated: $(date)" >> "$html_file"
    echo "            </p>" >> "$html_file"
    echo "        </div>" >> "$html_file"
    echo "        " >> "$html_file"
    echo "        <div class=\"stats-container\">" >> "$html_file"
    
    # Stats boxes - Initialize variables if not set
    CRITICAL_FINDINGS="${CRITICAL_FINDINGS:-0}"
    HIGH_FINDINGS="${HIGH_FINDINGS:-0}"
    MEDIUM_FINDINGS="${MEDIUM_FINDINGS:-0}"
    INFO_FINDINGS="${INFO_FINDINGS:-0}"
    SUCCESSFUL_CHECKS="${SUCCESSFUL_CHECKS:-0}"
    
    cat >> "$html_file" << EOF
            <div class="stat-box">
                <div class="stat-number critical">$CRITICAL_FINDINGS</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat-box">
                <div class="stat-number high">$HIGH_FINDINGS</div>
                <div class="stat-label">High</div>
            </div>
            <div class="stat-box">
                <div class="stat-number medium">$MEDIUM_FINDINGS</div>
                <div class="stat-label">Medium</div>
            </div>
            <div class="stat-box">
                <div class="stat-number info">$INFO_FINDINGS</div>
                <div class="stat-label">Informational</div>
            </div>
            <div class="stat-box">
                <div class="stat-number" style="color: #48bb78;">$SUCCESSFUL_CHECKS</div>
                <div class="stat-label">Checks Run</div>
            </div>
        </div>
        
        <div class="controls">
            <input type="text" class="search-box" id="searchBox" placeholder="🔍 Search findings..." onkeyup="filterFindings()">
            <button class="filter-btn btn-all" onclick="filterByLevel('all')">All</button>
            <button class="filter-btn btn-critical" onclick="filterByLevel('critical')">Critical</button>
            <button class="filter-btn btn-high" onclick="filterByLevel('high')">High</button>
            <button class="filter-btn btn-medium" onclick="filterByLevel('medium')">Medium</button>
            <button class="filter-btn btn-info" onclick="filterByLevel('info')">Info</button>
        </div>
        
        <div class="findings" id="findingsContainer">
EOF
    
    # FIX: Parse findings file with proper handling of pipe characters
    if [ -f ".findings.tmp" ]; then
        # Use a more robust parsing method
        while IFS= read -r line; do
            # Split by pipe but handle escaped pipes (│)
            IFS='|' read -r level category message exploit_ref timestamp <<< "$line"
            
            # Skip empty lines
            [ -z "$level" ] && continue
            
            local level_lower=$(echo "$level" | tr '[:upper:]' '[:lower:]')
            
            # Escape HTML entities
            message=$(escape_html "$message")
            exploit_ref=$(escape_html "$exploit_ref")
            category=$(escape_html "$category")
            
            cat >> "$html_file" << EOF
            <div class="finding-card $level_lower" data-level="$level_lower">
                <div class="finding-header">
                    <span class="finding-level level-$level_lower">$level</span>
                    <span class="finding-category">$category</span>
                </div>
                <div class="finding-message">$message</div>
EOF
            
            if [ -n "$exploit_ref" ] && [ "$exploit_ref" != "" ] && [ "$exploit_ref" != "null" ]; then
                echo "                <div class=\"exploit-ref\"><strong>🎯 EXPLOITATION:</strong><br>$exploit_ref</div>" >> "$html_file"
            fi
            
            echo "                <div class=\"timestamp\">⏰ $timestamp</div>" >> "$html_file"
            echo "            </div>" >> "$html_file"
        done < ".findings.tmp"
    else
        echo "            <div class=\"no-results\">No findings generated</div>" >> "$html_file"
    fi
    
    # Close HTML and add JavaScript
    cat >> "$html_file" << 'HTMLFOOTER'
            <div class="no-results" id="noResults" style="display: none;">
                No findings match your search/filter
            </div>
        </div>
        
        <div class="footer">
            <p><strong>⚠️ DISCLAIMER</strong></p>
            <p>This tool is for authorized security assessments only.</p>
            <p>Always obtain proper authorization before testing.</p>
            <p style="margin-top: 10px;">Generated by Ultimate AD Enumeration Tool | Educational purposes only</p>
        </div>
    </div>
    
    <script>
        let currentFilter = 'all';
        
        function filterByLevel(level) {
            currentFilter = level;
            const cards = document.querySelectorAll('.finding-card');
            let visibleCount = 0;
            
            cards.forEach(card => {
                if (level === 'all' || card.dataset.level === level) {
                    card.classList.remove('hidden');
                    visibleCount++;
                } else {
                    card.classList.add('hidden');
                }
            });
            
            document.getElementById('noResults').style.display = visibleCount === 0 ? 'block' : 'none';
            
            // Apply search filter again
            filterFindings();
        }
        
        function filterFindings() {
            const searchTerm = document.getElementById('searchBox').value.toLowerCase();
            const cards = document.querySelectorAll('.finding-card');
            let visibleCount = 0;
            
            cards.forEach(card => {
                const text = card.textContent.toLowerCase();
                const matchesSearch = searchTerm === '' || text.includes(searchTerm);
                const matchesFilter = currentFilter === 'all' || card.dataset.level === currentFilter;
                
                if (matchesSearch && matchesFilter) {
                    card.classList.remove('hidden');
                    visibleCount++;
                } else {
                    card.classList.add('hidden');
                }
            });
            
            document.getElementById('noResults').style.display = visibleCount === 0 ? 'block' : 'none';
        }
    </script>
</body>
</html>
HTMLFOOTER
    
    log_success "HTML report → $html_file"
}

generate_text_report() {
    local text_file="reports/ULTIMATE_REPORT.txt"
    
    # Initialize variables if not set
    DOMAIN="${DOMAIN:-Unknown}"
    DC_IP="${DC_IP:-Unknown}"
    DNS_SERVER="${DNS_SERVER:-Unknown}"
    BASE_DN="${BASE_DN:-Unknown}"
    AUTH_TYPE="${AUTH_TYPE:-Unknown}"
    VERSION="${VERSION:-1.0}"
    TOTAL_CHECKS="${TOTAL_CHECKS:-0}"
    SUCCESSFUL_CHECKS="${SUCCESSFUL_CHECKS:-0}"
    FAILED_CHECKS="${FAILED_CHECKS:-0}"
    CRITICAL_FINDINGS="${CRITICAL_FINDINGS:-0}"
    HIGH_FINDINGS="${HIGH_FINDINGS:-0}"
    MEDIUM_FINDINGS="${MEDIUM_FINDINGS:-0}"
    INFO_FINDINGS="${INFO_FINDINGS:-0}"
    
    cat > "$text_file" << EOF
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║   ULTIMATE AD SECURITY ASSESSMENT REPORT                            ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝

Assessment Date: $(date)
Target Domain: $DOMAIN
Domain Controller: $DC_IP
DNS Server: $DNS_SERVER
Base DN: $BASE_DN
Authentication: $AUTH_TYPE
Tool Version: $VERSION

═══════════════════════════════════════════════════════════════════════

EXECUTIVE SUMMARY:
────────────────────────────────────────────────────────────────────────

Total Checks Performed:  $TOTAL_CHECKS
Successful Checks:       $SUCCESSFUL_CHECKS
Failed Checks:           $FAILED_CHECKS

Findings by Severity:
  🔴 CRITICAL:  $CRITICAL_FINDINGS
  🟠 HIGH:      $HIGH_FINDINGS
  🟡 MEDIUM:    $MEDIUM_FINDINGS
  🔵 INFO:      $INFO_FINDINGS

═══════════════════════════════════════════════════════════════════════

DETAILED FINDINGS:
────────────────────────────────────────────────────────────────────────

EOF
    
    # Add findings with proper parsing
    if [ -f ".findings.tmp" ]; then
        while IFS='|' read -r level category message exploit_ref timestamp; do
            # Skip empty lines
            [ -z "$level" ] && continue
            
            cat >> "$text_file" << EOF
[$level] $category
─────────────────────────────────────────────────────────────────
Finding: $message
Timestamp: $timestamp

EOF
            if [ -n "$exploit_ref" ] && [ "$exploit_ref" != "" ] && [ "$exploit_ref" != "null" ]; then
                echo "Exploitation Reference:" >> "$text_file"
                echo "$exploit_ref" >> "$text_file"
                echo "" >> "$text_file"
            fi
            
            echo "═══════════════════════════════════════════════════════════════════════" >> "$text_file"
            echo "" >> "$text_file"
        done < ".findings.tmp"
    fi
    
    # Add recommendations
    cat >> "$text_file" << 'EOFRECOMMEND'

REMEDIATION RECOMMENDATIONS:
────────────────────────────────────────────────────────────────────────

IMMEDIATE ACTIONS (Critical Priority):
1. Review and remediate all CRITICAL findings immediately
2. Reset KRBTGT password if older than 180 days
3. Add privileged accounts to Protected Users group
4. Fix AS-REP roastable accounts (enable pre-authentication)
5. Review Kerberoastable service accounts (use gMSA)

HIGH PRIORITY (Within 30 Days):
1. Review all delegation configurations
2. Remove unnecessary SPNs from user accounts
3. Disable reversible encryption where enabled
4. Review and remove dormant/test accounts
5. Implement LAPS for local admin passwords

MEDIUM PRIORITY (Within 90 Days):
1. Upgrade or decommission End-of-Life systems
2. Review SID History on accounts
3. Implement regular password rotation
4. Review and tighten GPO permissions
5. Monitor for new Kerberoastable accounts

═══════════════════════════════════════════════════════════════════════

FILES GENERATED:
────────────────────────────────────────────────────────────────────────
EOFRECOMMEND
    
    # List all generated files
    find . -type f \( -name "*.ldif" -o -name "*.txt" -o -name "*.json" -o -name "*.zip" -o -name "*.log" \) 2>/dev/null | while read file; do
        echo "  • $file" >> "$text_file"
    done
    
    cat >> "$text_file" << 'EOFNEXT'

═══════════════════════════════════════════════════════════════════════

NEXT STEPS:
────────────────────────────────────────────────────────────────────────
1. Review this report and prioritize findings
2. If BloodHound data was collected:
   - Import the ZIP into BloodHound GUI
   - Review bloodhound/bloodyad_EXPLOITATION_GUIDE.txt
   - Test exploitation commands in safe environment
3. Create detailed remediation plan with timelines
4. Get stakeholder approval for changes
5. Implement fixes in test environment first
6. Schedule follow-up assessment after remediation

═══════════════════════════════════════════════════════════════════════
EOFNEXT
    
    log_success "Text report → $text_file"
}
