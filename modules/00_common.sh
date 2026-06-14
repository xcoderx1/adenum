#!/bin/bash
################################################################################
# MODULE: Common Library (shared helpers)
#
# Sourced FIRST by ultimate_ad_enum.sh, before every other module. Provides the
# hardened, reusable primitives the rest of the toolkit relies on:
#
#   * run_ldap            - quoted, paged (RFC 2696) LDAP search with clean
#                           stderr separation and real exit-code handling
#   * ldif_unfold         - RFC 2849 line-fold reassembly
#   * ldif_values         - attribute extraction (folding- and base64-aware)
#   * ldif_count_dn       - reliable entry count for an LDIF file
#   * to_int              - coerce arbitrary text to a non-negative integer
#   * make_uac_filter     - build a userAccountControl bitwise LDAP filter
#   * recount_findings    - recompute severity counters from the findings file
#                           (subshell-proof; see note below)
#
# NOTE ON COUNTERS: add_finding() increments CRITICAL_FINDINGS/... but those
# increments are lost whenever add_finding is called inside a `cmd | while`
# pipeline (the loop body runs in a subshell). The findings *file* is always
# correct because it is appended to. recount_findings() rebuilds the in-memory
# counters from that file so reports never undercount.
################################################################################

# Guard against double-sourcing.
if [ -n "${ADENUM_COMMON_LOADED:-}" ]; then
    return 0 2>/dev/null || true
fi
ADENUM_COMMON_LOADED=1

# ---------------------------------------------------------------------------
# to_int <text>  -> echoes a non-negative integer (0 if no digits present)
# ---------------------------------------------------------------------------
to_int() {
    local v="${1//[^0-9]/}"
    [ -z "$v" ] && v=0
    # Strip leading zeros so the value is never treated as octal in arithmetic.
    printf '%d' "$((10#$v))" 2>/dev/null || printf '0'
}

# ---------------------------------------------------------------------------
# ldif_unfold <file>
#   Reassembles RFC 2849 folded lines (continuation lines begin with a single
#   space) so downstream extraction never splits a value mid-way.
# ---------------------------------------------------------------------------
ldif_unfold() {
    local file="$1"
    [ -f "$file" ] || return 0
    awk '
        NR == 1 { buf = $0; next }
        /^ / { buf = buf substr($0, 2); next }
        { print buf; buf = $0 }
        END { if (NR > 0) print buf }
    ' "$file" 2>/dev/null
}

# ---------------------------------------------------------------------------
# ldif_values <attr> <file>
#   Prints every value of <attr>, one per line. Handles folded lines and
#   base64-encoded values (the "attr:: <base64>" form ldapsearch emits for
#   values with non-ASCII / leading-space / special characters).
# ---------------------------------------------------------------------------
ldif_values() {
    local attr="$1" file="$2"
    [ -f "$file" ] || return 0
    ldif_unfold "$file" | awk -v a="$attr" '
        index($0, a ":: ") == 1 { print "B64\t" substr($0, length(a) + 4); next }
        index($0, a ": ")  == 1 { print "RAW\t" substr($0, length(a) + 3) }
    ' | while IFS=$'\t' read -r kind val; do
        if [ "$kind" = "B64" ]; then
            printf '%s' "$val" | base64 -d 2>/dev/null
            printf '\n'
        else
            printf '%s\n' "$val"
        fi
    done
}

# ---------------------------------------------------------------------------
# ldif_count_dn <file>  -> echoes the number of LDAP entries in the file
# ---------------------------------------------------------------------------
ldif_count_dn() {
    local file="$1"
    [ -f "$file" ] || { printf '0'; return 0; }
    to_int "$(grep -c '^dn:' "$file" 2>/dev/null)"
}

# ---------------------------------------------------------------------------
# make_uac_filter <decimal_bit> [extra_filter]
#   Builds a bitwise userAccountControl filter, e.g.
#     make_uac_filter 524288 '(objectClass=computer)'
#   ->  (&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))
# ---------------------------------------------------------------------------
make_uac_filter() {
    local bit="$1" extra="${2:-}"
    local uac="(userAccountControl:1.2.840.113556.1.4.803:=${bit})"
    if [ -n "$extra" ]; then
        printf '(&%s%s)' "$extra" "$uac"
    else
        printf '%s' "$uac"
    fi
}

# ---------------------------------------------------------------------------
# recount_findings [findings_file]
#   Recomputes CRITICAL_FINDINGS / HIGH_FINDINGS / MEDIUM_FINDINGS /
#   INFO_FINDINGS from the on-disk findings file so they are accurate even when
#   findings were appended from inside subshell pipelines.
# ---------------------------------------------------------------------------
recount_findings() {
    local ff="${1:-${FINDINGS_FILE:-.findings.tmp}}"
    [ -f "$ff" ] || return 0
    CRITICAL_FINDINGS=$(to_int "$(grep -c '^CRITICAL|' "$ff" 2>/dev/null)")
    HIGH_FINDINGS=$(to_int "$(grep -c '^HIGH|' "$ff" 2>/dev/null)")
    MEDIUM_FINDINGS=$(to_int "$(grep -c '^MEDIUM|' "$ff" 2>/dev/null)")
    LOW_FINDINGS=$(to_int "$(grep -c '^LOW|' "$ff" 2>/dev/null)")
    INFO_FINDINGS=$(to_int "$(grep -c '^INFO|' "$ff" 2>/dev/null)")
}

# ---------------------------------------------------------------------------
# resolve_wordlist
#   Echoes a usable cracking wordlist path on success (exit 0), or nothing on
#   failure (exit 1, with a hint on stderr). Honors $ADENUM_WORDLIST, otherwise
#   defaults to rockyou. On a fresh Kali rockyou ships GZIPPED
#   (rockyou.txt.gz), so the previous hard-coded path silently failed; we now
#   detect that case and tell the operator the one command that fixes it,
#   instead of launching hashcat against a non-existent file.
#   (Warnings go to stderr so command substitution captures only the path.)
# ---------------------------------------------------------------------------
resolve_wordlist() {
    local wl="${ADENUM_WORDLIST:-/usr/share/wordlists/rockyou.txt}"
    if [ -f "$wl" ]; then
        printf '%s' "$wl"
        return 0
    fi
    if [ -f "${wl}.gz" ]; then
        log_warning "Wordlist is gzipped - run 'gunzip ${wl}.gz' to enable auto-cracking" >&2
    else
        log_warning "Wordlist not found ($wl) - set ADENUM_WORDLIST to enable auto-cracking" >&2
    fi
    return 1
}

# ---------------------------------------------------------------------------
# _ldap_init_caps
#   Detects, once per run, which optional ldapsearch features this build
#   supports and stores them in the LDAP_BASE_OPTS array. Probing uses
#   "ldapsearch <opt> -VV", which parses options and exits without any network
#   I/O - so it reliably reports support via the exit code.
#     * -E pr=1000/noprompt : RFC 2696 simple paged results (defeats the
#                             server MaxPageSize ~1000-entry truncation).
#     * -o ldif-wrap=no     : disable 76-column line folding (older builds
#                             lack it; ldif_unfold handles folding regardless).
# ---------------------------------------------------------------------------
LDAP_BASE_OPTS=()
_ldap_caps_done=""
_ldap_init_caps() {
    [ -n "$_ldap_caps_done" ] && return 0
    _ldap_caps_done=1
    # Warn once if binding with a password over cleartext LDAP: a simple bind on
    # ldap:// sends the operator's password in the clear, sniffable on the wire.
    if [ "${LDAP_SCHEME:-ldap}" != "ldaps" ] && [ "$AUTH_TYPE" = "userpass" ]; then
        log_warning "Binding over cleartext LDAP - the password is sent unencrypted. Use --ldaps (LDAPS/636) where the DC supports it."
    fi
    LDAP_BASE_OPTS=()
    if ldapsearch -o ldif-wrap=no -VV >/dev/null 2>&1; then
        LDAP_BASE_OPTS+=(-o ldif-wrap=no)
    fi
    if ldapsearch -E 'pr=1000/noprompt' -VV >/dev/null 2>&1; then
        LDAP_BASE_OPTS+=(-E 'pr=1000/noprompt')
    fi
}

# ---------------------------------------------------------------------------
# run_ldap <filter> <output_file> <description> [space_separated_attributes]
#
#   Hardened LDAP search used by every enumeration module. Improvements over
#   the original:
#     * All expansions quoted ($DC_IP / $BASE_DN / $USERNAME / $PASSWORD) so
#       values containing spaces or shell metacharacters do not break the call.
#     * Requested attributes are split safely via a bash array instead of
#       relying on unquoted word-splitting.
#     * RFC 2696 simple paged results (pr=1000/noprompt) so large domains are
#       not silently truncated at the server's MaxPageSize (~1000 entries).
#     * stderr is captured to "<output>.err" instead of being merged into the
#       LDIF, keeping entry counts and value extraction clean.
#     * The real ldapsearch exit code is inspected (no pipeline masking).
#
#   Returns 0 on a successful query (even with zero results), 1 on failure.
# ---------------------------------------------------------------------------
run_ldap() {
    local filter="$1"
    local output="$2"
    local description="$3"
    local attributes="$4"

    log_action "$description"
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))

    # Split requested attributes intentionally (they are tool-controlled, never
    # user input). An empty list means "return all attributes".
    local -a attrs=()
    [ -n "$attributes" ] && read -r -a attrs <<< "$attributes"

    _ldap_init_caps   # one-time capability probe -> LDAP_BASE_OPTS

    local rc
    case "$AUTH_TYPE" in
        userpass)
            ldapsearch -x -H "${LDAP_SCHEME:-ldap}://$DC_IP" -D "$USERNAME@$DOMAIN" -w "$PASSWORD" \
                "${LDAP_BASE_OPTS[@]}" -b "$BASE_DN" "$filter" "${attrs[@]}" \
                > "$output" 2> "$output.err"
            rc=$?
            ;;
        anonymous)
            ldapsearch -x -H "${LDAP_SCHEME:-ldap}://$DC_IP" \
                "${LDAP_BASE_OPTS[@]}" -b "$BASE_DN" "$filter" "${attrs[@]}" \
                > "$output" 2> "$output.err"
            rc=$?
            ;;
        *)  # kerberos (GSSAPI via KRB5CCNAME)
            ldapsearch -H "${LDAP_SCHEME:-ldap}://$DC_IP" -Y GSSAPI \
                "${LDAP_BASE_OPTS[@]}" -b "$BASE_DN" "$filter" "${attrs[@]}" \
                > "$output" 2> "$output.err"
            rc=$?
            ;;
    esac

    # Keep output dirs tidy: drop the stderr sidecar when the query was clean.
    [ -s "$output.err" ] || rm -f "$output.err"

    if [ $rc -eq 0 ]; then
        local count
        count=$(ldif_count_dn "$output")
        if [ "$count" -gt 0 ]; then
            log_success "Found $count objects"
        else
            log_warning "No objects found"
        fi
        SUCCESSFUL_CHECKS=$((SUCCESSFUL_CHECKS + 1))
        return 0
    fi

    log_error "Query failed ($(head -1 "$output.err" 2>/dev/null))"
    FAILED_CHECKS=$((FAILED_CHECKS + 1))
    return 1
}
