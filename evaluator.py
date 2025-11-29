"""
Secure Policy Language (SPL) - Policy Evaluator
University of Technology, Jamaica - CIT4004
Analysis of Programming Languages Project

Team Members:
- Javido Robinson - 1707486
- Athaliah Knight - 1804360
- Nathalea Evans - 2101707
- Shemmar Ricketts - 2005329
- Malik Morgan - 2007793

This module implements the runtime evaluator for SPL policies.
It evaluates policy conditions against a provided context (environment).
"""

class PolicyEvaluator:
    def __init__(self, context=None, constants=None):
        """
        Initialize the evaluator with a context and constants.
        Context is a nested dictionary representing the environment.
        Constants is a dictionary of constant_name -> value.
        Example:
        {
            'time': {'hour': 14, 'minute': 30, 'day': 'Monday', 'month': 1, 'year': 2025},
            'user': {'role': 'admin', 'id': 123},
            'resource': {'owner': 'finance', 'size': 500}
        }
        constants = {'BUSINESS_HOURS_START': 9, 'BUSINESS_HOURS_END': 17}
        """
        self.context = context or {}
        self.constants = constants or {}

    def evaluate(self, node):
        """
        Recursively evaluate an AST node.
        Returns the computed value (int, str, bool).
        """
        if not isinstance(node, tuple):
            return node # Should not happen if AST is correct

        tag = node[0]

        if tag == 'BINARY_OP':
            return self.evaluate_binary_op(node)
        elif tag == 'UNARY_OP':
            return self.evaluate_unary_op(node)
        elif tag == 'ATTRIBUTE':
            return self.resolve_attribute(node)
        elif tag == 'NUM':
            return node[1]
        elif tag == 'STR':
            return node[1]
        elif tag == 'VAR':
            # For now, treat VAR same as string or look up in context if needed
            # In SPL, variables are usually attributes (user.role).
            # If a standalone variable is used, we check context or return identifier as string.
            val = self.resolve_variable(node[1])
            return val if val is not None else node[1]
        
        return None

    def evaluate_binary_op(self, node):
        _, op, left_node, right_node = node
        left = self.evaluate(left_node)
        right = self.evaluate(right_node)

        # Arithmetic
        if op == '+': return left + right
        if op == '-': return left - right
        if op == '*': return left * right
        if op == '/': return left / right # Python float division

        # Comparison
        if op == '>': return left > right
        if op == '<': return left < right
        if op == '>=': return left >= right
        if op == '<=': return left <= right
        if op == '==': 
            # Special handling for role comparison: if left is a list, check if right is in it
            if isinstance(left, list):
                return right in left
            return left == right
        if op == '!=': 
            # Special handling for role comparison: if left is a list, check if right is not in it
            if isinstance(left, list):
                return right not in left
            return left != right

        # Boolean Logic
        if op == 'AND': return bool(left) and bool(right)
        if op == 'OR': return bool(left) or bool(right)

        raise ValueError(f"Unknown binary operator: {op}")

    def evaluate_unary_op(self, node):
        _, op, operand_node = node
        val = self.evaluate(operand_node)

        if op == '-': return -val
        if op == 'NOT': return not val # If we had NOT operator

        raise ValueError(f"Unknown unary operator: {op}")

    def resolve_attribute(self, node):
        _, obj_name, attr_name = node
        
        obj = self.context.get(obj_name)
        if obj is None:
             raise ValueError(f"Runtime Error: Unknown object '{obj_name}'")
        
        val = obj.get(attr_name)
        if val is None:
             raise ValueError(f"Runtime Error: Unknown attribute '{obj_name}.{attr_name}'")
        
        # Special handling for user.role: support both single role and multiple roles
        # If user.roles exists (list), return it; otherwise return user.role (single value)
        if obj_name == 'user' and attr_name == 'role':
            # Check if user.roles exists (multiple roles)
            if 'roles' in obj:
                return obj['roles']  # Return list of roles
            # Otherwise return single role value
            return val
        
        return val

    def resolve_variable(self, var_name):
        # First check constants, then top-level context
        if var_name in self.constants:
            return self.constants[var_name]
        return self.context.get(var_name)

    def check_access(self, policy, request):
        """
        Check if a request is allowed by a specific policy.
        
        Args:
            policy: The policy AST node (POLICY_RULE)
            request: A dictionary containing request details:
                     {'action': 'read', 'resource': 'DB_Finance'}
        
        Returns:
            bool: True if policy applies and allows access, False otherwise.
            (Note: DENY policies logic handled by main engine, this just checks if THIS policy matches)
        """
        # 1. Check Resource Match
        if policy['resource'] != request['resource']:
            return False

        # 2. Check Action Match
        # Policy actions can be a list. Wildcard '*' matches everything.
        actions = policy['actions']
        req_action = request['action']
        
        action_match = False
        if '*' in actions:
            action_match = True
        elif req_action in actions:
            action_match = True
            
        if not action_match:
            return False

        # 3. Check Condition (if exists)
        condition = policy.get('condition')
        if condition:
            try:
                return self.evaluate(condition)
            except Exception as e:
                print(f"Evaluation Error: {e}")
                return False
        
        # If no condition, it's an unconditional match
        return True

# --- TEST HARNESS ---
if __name__ == "__main__":
    # Simulate an AST for: 
    # ALLOW read ON DB_Finance IF (time.hour > 9 AND user.role == "admin")
    
    policy_ast = {
        'type': 'ALLOW',
        'resource': 'DB_Finance',
        'actions': ['read'],
        'condition': ('BINARY_OP', 'AND', 
                      ('BINARY_OP', '>', ('ATTRIBUTE', 'time', 'hour'), ('NUM', 9)),
                      ('BINARY_OP', '==', ('ATTRIBUTE', 'user', 'role'), ('STR', 'admin'))
                     )
    }

    # Test Contexts
    ctx_allowed = {
        'time': {'hour': 14},
        'user': {'role': 'admin'}
    }

    ctx_denied_time = {
        'time': {'hour': 8}, # Too early
        'user': {'role': 'admin'}
    }

    ctx_denied_role = {
        'time': {'hour': 14},
        'user': {'role': 'guest'}
    }

    evaluator = PolicyEvaluator(ctx_allowed)
    print("Test 1 (Allowed):", evaluator.check_access(policy_ast, {'action': 'read', 'resource': 'DB_Finance'}))

    evaluator = PolicyEvaluator(ctx_denied_time)
    print("Test 2 (Denied Time):", evaluator.check_access(policy_ast, {'action': 'read', 'resource': 'DB_Finance'}))

    evaluator = PolicyEvaluator(ctx_denied_role)
    print("Test 3 (Denied Role):", evaluator.check_access(policy_ast, {'action': 'read', 'resource': 'DB_Finance'}))

    # PEMDAS Test
    # 3 + 4 * 2 = 11 (not 14)
    pemdas_ast = ('BINARY_OP', '+', ('NUM', 3), ('BINARY_OP', '*', ('NUM', 4), ('NUM', 2)))
    print("Test 4 (PEMDAS 3+4*2):", evaluator.evaluate(pemdas_ast))

