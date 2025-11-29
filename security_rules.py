"""
Secure Policy Language (SPL) - Security Risk Patterns
University of Technology, Jamaica - CIT4004
Analysis of Programming Languages Project

Team Members:
- Javido Robinson - 1707486
- Athaliah Knight - 1804360
- Nathalea Evans - 2101707
- Shemmar Ricketts - 2005329
- Malik Morgan - 2007793

This module defines security risk patterns and scans the symbol table
for potential vulnerabilities in the defined policies.
"""

class SecurityScanner:
    def __init__(self, symbol_table):
        self.symtab = symbol_table
        self.risks = []

    def scan(self):
        """
        Scans the symbol table for security risks.
        Returns a list of risk warnings.
        """
        self.risks = []
        self._check_overly_permissive()
        self._check_conflicting_policies()
        # self._check_shadowing() # Future enhancement
        
        return self.risks

    def _check_overly_permissive(self):
        """
        Risk: Policies that allow '*' (all actions) on resources.
        Especially risky if the resource is sensitive (e.g., contains 'finance', 'admin').
        """
        for policy in self.symtab.policies:
            if policy['type'] == 'ALLOW' and '*' in policy['actions']:
                resource = policy['resource']
                line = policy.get('line', '?')
                
                # Check if resource is sensitive
                is_sensitive = False
                if 'finance' in resource.lower() or 'admin' in resource.lower() or 'confidential' in resource.lower():
                    is_sensitive = True
                
                risk_level = "HIGH" if is_sensitive else "MEDIUM"
                
                self.risks.append({
                    'line': line,
                    'level': risk_level,
                    'message': f"Overly Permissive Policy: ALLOW * on resource '{resource}'"
                })

    def _check_conflicting_policies(self):
        """
        Risk: Contradictory rules (ALLOW and DENY) for the same resource and action.
        DENY rules override ALLOW rules when both match.
        """
        # Group by resource
        resource_policies = {}
        for policy in self.symtab.policies:
            res = policy['resource']
            if res not in resource_policies:
                resource_policies[res] = []
            resource_policies[res].append(policy)

        for res, policies in resource_policies.items():
            # Check for overlaps
            for i, p1 in enumerate(policies):
                for j, p2 in enumerate(policies):
                    if i >= j: continue # Avoid duplicate pairs

                    # If types differ (ALLOW vs DENY)
                    if p1['type'] != p2['type']:
                        # Check action overlap
                        actions1 = set(p1['actions'])
                        actions2 = set(p2['actions'])
                        
                        # Handle wildcard
                        if '*' in actions1: actions1 = {'*'} 
                        if '*' in actions2: actions2 = {'*'}

                        overlap = False
                        overlapping_actions = []
                        if '*' in actions1 or '*' in actions2:
                            overlap = True
                            overlapping_actions = ['*']
                        else:
                            common = actions1.intersection(actions2)
                            if common:
                                overlap = True
                                overlapping_actions = list(common)
                        
                        if overlap:
                            # Determine which is DENY and which is ALLOW
                            if p1['type'] == 'DENY':
                                deny_line = p1.get('line', '?')
                                allow_line = p2.get('line', '?')
                            else:
                                deny_line = p2.get('line', '?')
                                allow_line = p1.get('line', '?')
                            
                            actions_str = ', '.join(overlapping_actions) if overlapping_actions else 'actions'
                            self.risks.append({
                                'line': f"{deny_line} & {allow_line}",
                                'level': "MEDIUM",
                                'message': f"Deny overrides Allow for '{res}' ({actions_str})"
                            })

# --- TEST HARNESS ---
if __name__ == "__main__":
    # Mock SymbolTable structure for testing
    class MockSymbolTable:
        def __init__(self):
            self.policies = []

    st = MockSymbolTable()
    st.policies = [
        {'type': 'ALLOW', 'actions': ['*'], 'resource': 'DB_Finance', 'line': 10},
        {'type': 'ALLOW', 'actions': ['read'], 'resource': 'PublicData', 'line': 12},
        {'type': 'ALLOW', 'actions': ['write'], 'resource': 'Logs', 'line': 15},
        {'type': 'DENY', 'actions': ['write'], 'resource': 'Logs', 'line': 16},
    ]

    scanner = SecurityScanner(st)
    risks = scanner.scan()
    
    print("--- Security Risks Found ---")
    for r in risks:
        print(f"[{r['level']}] Line {r['line']}: {r['message']}")

