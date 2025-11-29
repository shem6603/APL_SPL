import ply.yacc as yacc
import pprint
from lexer import tokens, lexer

# --- PRECEDENCE ---
precedence = (
    ('left', 'OR'),
    ('left', 'AND'),
    ('right', 'NOT'),
    ('nonassoc', 'EQ', 'NE', 'GT', 'LT', 'GE', 'LE'),
    ('left', 'PLUS', 'MINUS'),
    ('left', 'TIMES', 'DIVIDE'),
    ('right', 'UMINUS'),
)

# --- GRAMMAR RULES ---

def p_program(p):
    'program : statements'
    p[0] = ('PROGRAM', p[1])

def p_statements_multiple(p):
    'statements : statement statements'
    p[0] = [p[1]] + p[2]

def p_statements_single(p):
    'statements : statement'
    p[0] = [p[1]]

def p_statement(p):
    '''statement : role_def
                 | user_def
                 | resource_def
                 | const_def
                 | call_def
                 | named_policy_def
                 | rule_def'''
    p[0] = p[1]

# --- DEFINITIONS (Capturing Line Numbers) ---

def p_role_def(p):
    'role_def : ROLE ID LBRACE CAN COLON action_list RBRACE'
    # action_list can be TIMES (wildcard) or a list of actions
    if p[6] == '*':
        scope = 'ALL'
    elif isinstance(p[6], list):
        scope = ', '.join(p[6])  # Store as comma-separated string
    else:
        scope = p[6]  # Single action
    p[0] = ('ROLE_DEF', {'name': p[2], 'scope': scope, 'line': p.lineno(1)})

def p_user_def(p):
    'user_def : USER ID LBRACE ROLE_KEY COLON id_list RBRACE'
    # id_list can be a single ID or multiple IDs separated by commas
    roles = p[6] if isinstance(p[6], list) else [p[6]]
    p[0] = ('USER_DEF', {'name': p[2], 'roles': roles, 'line': p.lineno(1)})

def p_resource_def(p):
    'resource_def : RESOURCE ID LBRACE resource_attr_list RBRACE'
    # resource_attr_list is a list of (key, value) pairs
    attrs = {}
    for key, value in p[4]:
        attrs[key] = value
    p[0] = ('RESOURCE_DEF', {'name': p[2], 'attributes': attrs, 'line': p.lineno(1)})

def p_const_def(p):
    'const_def : CONST ID ASSIGN const_value'
    # const_value can be NUMBER or STRING
    p[0] = ('CONST_DEF', {'name': p[2], 'value': p[4], 'line': p.lineno(1)})

def p_const_value_number(p):
    'const_value : NUMBER'
    p[0] = p[1]  # Store as int

def p_const_value_string(p):
    'const_value : STRING'
    p[0] = p[1]  # Store as string

def p_call_def(p):
    '''call_def : CALL ROLE
                | CALL ROLE ID
                | CALL RESOURCE
                | CALL RESOURCE ID
                | CALL USER
                | CALL USER ID
                | CALL CONST
                | CALL CONST ID
                | CALL POLICY
                | CALL POLICY ID'''
    # Handle different CALL variations
    if len(p) == 3:  # CALL ROLE, CALL RESOURCE, CALL USER, CALL CONST, CALL POLICY
        p[0] = ('CALL_DEF', {'type': p[2], 'name': None, 'line': p.lineno(1)})
    else:  # CALL ROLE ID, CALL RESOURCE ID, CALL USER ID, CALL CONST ID, CALL POLICY ID
        p[0] = ('CALL_DEF', {'type': p[2], 'name': p[3], 'line': p.lineno(1)})

def p_named_policy_def(p):
    'named_policy_def : POLICY ID LBRACE policy_body RBRACE'
    # policy_body is a list of statements (can be any statement type)
    p[0] = ('POLICY_DEF', {'name': p[2], 'body': p[4], 'line': p.lineno(1)})

def p_policy_body_multiple(p):
    'policy_body : statement policy_body'
    p[0] = [p[1]] + p[2]

def p_policy_body_single(p):
    'policy_body : statement'
    p[0] = [p[1]]

def p_policy_body_empty(p):
    'policy_body : empty'
    p[0] = []

def p_rule_def(p):
    '''rule_def : IF expression THEN policy_type action_clause ON resource_clause ELSE policy_type action_clause ON resource_clause
                | ALLOW action_clause ON resource_clause IF expression
                | DENY action_clause ON resource_clause IF expression
                | ALLOW action_clause ON resource_clause
                | DENY action_clause ON resource_clause'''
    if len(p) == 13:  # IF-THEN-ELSE form
        p[0] = ('POLICY_RULE', {
            'type': 'CONDITIONAL',
            'condition': p[2],
            'then_type': p[4],
            'then_actions': p[5],
            'then_resource': p[7],
            'else_type': p[9],
            'else_actions': p[10],
            'else_resource': p[12],
            'line': p.lineno(1)
        })
    elif len(p) == 7:  # Has IF condition
        p[0] = ('POLICY_RULE', {
            'type': p[1],
            'actions': p[2],
            'resource': p[4],
            'condition': p[6],
            'line': p.lineno(1)
        })
    else:  # No IF condition
        p[0] = ('POLICY_RULE', {
            'type': p[1],
            'actions': p[2],
            'resource': p[4],
            'condition': None,
            'line': p.lineno(1)
        })

# --- HELPERS ---
def p_policy_type(p):
    '''policy_type : ALLOW
                   | DENY'''
    p[0] = p[1]

def p_action_clause(p):
    'action_clause : ACTION COLON id_list'
    p[0] = p[3]

def p_resource_clause(p):
    'resource_clause : RESOURCE_KEY COLON ID'
    p[0] = p[3]

def p_id_list_multi(p):
    'id_list : ID COMMA id_list'
    p[0] = [p[1]] + p[3]

def p_id_list_single(p):
    '''id_list : ID
               | TIMES'''
    p[0] = [p[1]]  # Always return a list for consistency

# --- ACTION LISTS (for role definitions) ---
# Note: Order matters - more specific rules first

def p_action_list_wildcard(p):
    'action_list : TIMES'
    p[0] = '*'  # Return wildcard as string

def p_action_list_multi(p):
    'action_list : ID COMMA action_list'
    # p[3] will always be a list from p_action_list_single or recursive p_action_list_multi
    if isinstance(p[3], list):
        p[0] = [p[1]] + p[3]
    else:
        p[0] = [p[1], p[3]]

def p_action_list_single(p):
    'action_list : ID'
    p[0] = [p[1]]  # Return as list for consistency

# --- EXPRESSIONS ---
def p_expression_binop(p):
    '''expression : expression PLUS expression
                  | expression MINUS expression
                  | expression TIMES expression
                  | expression DIVIDE expression
                  | expression AND expression
                  | expression OR expression
                  | expression GT expression
                  | expression LT expression
                  | expression GE expression
                  | expression LE expression
                  | expression EQ expression
                  | expression NE expression'''
    p[0] = ('BINARY_OP', p[2], p[1], p[3])

def p_expression_uminus(p):
    'expression : MINUS expression %prec UMINUS'
    p[0] = ('UNARY_OP', '-', p[2])

def p_expression_group(p):
    'expression : LPAREN expression RPAREN'
    p[0] = p[2]

def p_expression_num(p):
    'expression : NUMBER'
    p[0] = ('NUM', p[1])

def p_expression_str(p):
    'expression : STRING'
    p[0] = ('STR', p[1])

def p_expression_id(p):
    'expression : ID'
    p[0] = ('VAR', p[1])

def p_expression_attr(p):
    '''expression : ID DOT ID
                  | ID DOT ROLE_KEY
                  | ID DOT RESOURCE_KEY
                  | ID DOT ACTION
                  | ID DOT CAN
                  | ID DOT PATH_KEY'''
    p[0] = ('ATTRIBUTE', p[1], p[3])

def p_path_expr(p):
    'path_expr : STRING'
    p[0] = p[1]

# --- RESOURCE ATTRIBUTES ---

def p_resource_attr_list_multi(p):
    'resource_attr_list : resource_attribute COMMA resource_attr_list'
    p[0] = [p[1]] + p[3]

def p_resource_attr_list_single(p):
    'resource_attr_list : resource_attribute'
    p[0] = [p[1]]

def p_resource_attribute_path(p):
    'resource_attribute : PATH_KEY COLON path_expr'
    # PATH_KEY token: p[1] is the token, p[1].value is 'path'
    p[0] = ('path', p[3])

def p_resource_attribute_other(p):
    'resource_attribute : ID COLON resource_value'
    # ID token: p[1] is the string value (owner, sensitivity, tags, etc.)
    attr_key = p[1] if isinstance(p[1], str) else getattr(p[1], 'value', str(p[1]))
    p[0] = (attr_key, p[3])

def p_resource_value(p):
    '''resource_value : STRING
                      | array_literal
                      | NUMBER'''
    p[0] = p[1]

def p_array_literal(p):
    'array_literal : LBRACKET array_elements RBRACKET'
    p[0] = p[2] if p[2] is not None else []

def p_array_elements_multi(p):
    'array_elements : STRING COMMA array_elements'
    p[0] = [p[1]] + (p[3] if isinstance(p[3], list) else [p[3]])

def p_array_elements_single(p):
    'array_elements : STRING'
    p[0] = [p[1]]

def p_array_elements_empty(p):
    'array_elements : empty'
    p[0] = []

def p_empty(p):
    'empty :'
    pass

# --- ERROR HANDLING ---
def p_error(p):
    if not p:
        print("(!) SYNTAX ERROR: Unexpected end of file (EOF) - incomplete statement.")
        return

    print(f"(!) SYNTAX ERROR at line {p.lineno}.")

_parser = yacc.yacc(debug=False, errorlog=yacc.NullLogger())

# Wrapper to reset lexer line number before each parse
class Parser:
    def parse(self, code):
        lexer.lineno = 1  # Reset line counter
        return _parser.parse(code, lexer=lexer)

parser = Parser()

if __name__ == "__main__":
    pp = pprint.PrettyPrinter(indent=2)
    # Test Data with comments
    code = """
      ROLE Admin {can: *} 
      RESOURCE DB_Finance {path: "/data/financial"}
      USER Jane { role: Admin } 
      ALLOW action: read, write ON resource: DB_Finance IF (time.hour > 9)"""
    print("--- SPL Parser Test (with comments) ---")
    result = parser.parse(code)
    pp.pprint(result)