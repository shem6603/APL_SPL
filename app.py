"""
Secure Policy Language (SPL) - Web IDE
University of Technology, Jamaica - CIT4004
Analysis of Programming Languages Project

Team Members:
- Javido Robinson - 1707486
- Athaliah Knight - 1804360
- Nathalea Evans - 2101707
- Shemmar Ricketts - 2005329

To run: streamlit run app.py
"""

import streamlit as st
import pandas as pd
import sys
import io
import os
from contextlib import redirect_stdout
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Import SPL Components
from parser import parser
from semantics import SemanticAnalyzer
from security_rules import SecurityScanner
from evaluator import PolicyEvaluator
from gemini_helper import get_gemini_helper

# --- 1. PAGE CONFIGURATION ---
st.set_page_config(
    page_title="SPL IDE",
    page_icon="💻",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# --- 2. IDE STYLING (Dark Mode) ---
st.markdown("""
<style>
    /* Main Background */
    .stApp {
        background-color: #1e1e1e;
        color: #d4d4d4;
    }
    
    /* Code Editor Area */
    .stTextArea textarea {
        background-color: #252526 !important;
        color: #d4d4d4 !important;
        font-family: 'Consolas', 'Courier New', monospace !important;
        border: 1px solid #3e3e42 !important;
        font-size: 14px;
    }
    
    /* Terminal/Console Area */
    .console-box {
        background-color: #000000;
        color: #00ff00;
        font-family: 'Consolas', 'Courier New', monospace;
        padding: 10px;
        border-radius: 5px;
        border: 1px solid #333;
        font-size: 12px;
        height: 200px;
        overflow-y: auto;
    }
    
    /* Buttons */
    .stButton button {
        background-color: #0e639c;
        color: white;
        border: none;
    }
    
    /* Headers */
    h1, h2, h3 {
        color: #569cd6 !important;
        font-family: 'Segoe UI', sans-serif;
    }
    
    /* Tabs */
    .stTabs [data-baseweb="tab-list"] {
        gap: 2px;
        background-color: #2d2d2d;
    }
    .stTabs [data-baseweb="tab"] {
        background-color: #2d2d2d;
        color: #969696;
        border: none;
    }
    .stTabs [aria-selected="true"] {
        background-color: #1e1e1e;
        color: #ffffff;
        border-top: 2px solid #0e639c;
    }
</style>
""", unsafe_allow_html=True)

# --- 3. SIDEBAR (File Explorer Mockup) ---
# File label mapping
file_labels = {
    "📋 Policy Demo": "policy.spl",
    "⚠️ Conflict Demo": "conflict.spl",
    "🔒 Risk Demo": "risk.spl",
    "🔍 Scope Demo": "scope.spl"
}

with st.sidebar:
    st.markdown("### 📂 Explorer")
    st.markdown("---")
    selected_label = st.radio(
        "FILES",
        list(file_labels.keys()),
        index=0
    )
    st.markdown("---")
    
    # AI Safety Check Configuration
    st.markdown("### 🛡️ AI Safety Check")
    st.markdown("---")
    
    # Initialize toggle state if not exists
    if 'ai_safety_enabled' not in st.session_state:
        st.session_state.ai_safety_enabled = False
    
    # Get API key from .env file
    gemini_api_key = os.getenv('GEMINI_API_KEY', '')
    
    # Toggle button for AI Safety Check
    ai_safety_enabled = st.toggle(
        "Enable AI Safety Check",
        value=st.session_state.ai_safety_enabled,
        help="Toggle to enable/disable AI-powered policy safety checking"
    )
    st.session_state.ai_safety_enabled = ai_safety_enabled
    
    if ai_safety_enabled:
        if gemini_api_key:
            try:
                gemini = get_gemini_helper(api_key=gemini_api_key)
                if gemini:
                    st.success("✅ AI Safety Check enabled")
            except Exception as e:
                st.error(f"❌ Error: {str(e)}")
                st.session_state.ai_safety_enabled = False
        else:
            st.warning("⚠️ GEMINI_API_KEY not found in .env file")
            st.session_state.ai_safety_enabled = False
    else:
        st.info("AI Safety Check disabled")
    
    st.markdown("---")
    st.info("Select a file to open it in the editor.")

# Get the selected file name (outside sidebar to ensure it's accessible)
example_option = file_labels[selected_label]

# Example Code Templates
examples = {
    "policy.spl": """// Basic Policy Demo - Simple access control policies

// Define roles with permissions
ROLE Admin {can: *}
ROLE Developer {can: read, write}
ROLE Viewer {can: read}

// Define resources with attributes
RESOURCE DB_Finance {path: "/data/financial", owner: "Finance", sensitivity: "high"}
RESOURCE DB_Logs {path: "/var/logs", owner: "IT", sensitivity: "low"}

// Assign roles to users
USER Jane { role: Admin, Developer }
USER Bob { role: Viewer }

// Define constants for business hours
CONST START_HOUR = 9
CONST END_HOUR = 17

// Simple policy: Allow read/write during business hours
ALLOW action: read, write ON resource: DB_Finance IF (time.hour >= START_HOUR AND time.hour <= END_HOUR)

// Policy with day restrictions
ALLOW action: read ON resource: DB_Logs IF (time.day != "Saturday" AND time.day != "Sunday")

// Conditional policy using IF-THEN-ELSE
// During business hours: allow write, otherwise deny
IF (time.hour >= START_HOUR AND time.hour <= END_HOUR) THEN ALLOW action: write ON resource: DB_Finance ELSE DENY action: write ON resource: DB_Finance

// Query what we've defined
CALL ROLE
CALL RESOURCE
CALL USER""",
    
    "conflict.spl": """// Policy Conflict Demo - Conflicting rules on same resource
// NOTE: DENY rules override ALLOW rules (Deny overrides Allow)

// Setup roles and resources
ROLE Developer {can: read, write}
ROLE Manager {can: *}
RESOURCE Logs {path: "/var/logs", owner: "IT"}

// User with Developer role
USER Bob { role: Developer }

// Time constants
CONST MORNING = 9
CONST NOON = 12
CONST EVENING = 18

// CONFLICT 1: Overlapping time windows
// At hour 10: ALLOW matches (10 > 9) AND DENY matches (10 < 12)
// Result: DENY overrides ALLOW, so access is DENIED
ALLOW action: write ON resource: Logs IF (time.hour > MORNING)
DENY action: write ON resource: Logs IF (time.hour < NOON)

// CONFLICT 2: Same action, different conditions
// On Monday at hour 10: ALLOW matches (10 < 18) AND DENY matches (Monday)
// Result: DENY overrides ALLOW, so access is DENIED
ALLOW action: read ON resource: Logs IF (time.hour < EVENING)
DENY action: read ON resource: Logs IF (time.day == "Monday")

// Query to see conflicts
CALL RESOURCE Logs
CALL USER Bob""",

    "risk.spl": """// Security Risk Demo - Dangerous policy patterns

// Limited role
ROLE Guest {can: read}
ROLE Admin {can: *}

// Sensitive resource
RESOURCE DB_Finance {path: "/data/financial", sensitivity: "high", owner: "Finance"}

// User with limited permissions
USER Alice { role: Guest }

// RISK 1: Wildcard action overrides role restrictions
// Guest role only allows 'read', but this allows ALL actions
ALLOW action: * ON resource: DB_Finance IF (time.hour > 0)

// RISK 2: Overly permissive time condition
// Allows access at any hour (condition always true)
ALLOW action: write ON resource: DB_Finance IF (time.hour >= 0)

// RISK 3: No time restrictions on sensitive resource
ALLOW action: read ON resource: DB_Finance

// Query to identify risks
CALL ROLE
CALL USER Alice
CALL RESOURCE DB_Finance""",
    
    "scope.spl": """// Scope and Binding Demo - Global vs Policy scope

// GLOBAL SCOPE - accessible everywhere
RESOURCE DB_Global {path: "/global"}
ROLE Admin {can: *}
CONST GLOBAL_CONST = 100

POLICY FinancePolicy {
    // POLICY SCOPE - local to this policy block
    RESOURCE DB_Local {path: "/local"}
    ROLE FinanceRole {can: read, write}
    CONST LOCAL_CONST = 200
    
    // Can access global scope from inside policy
    ALLOW action: read ON resource: DB_Global IF (time.hour > GLOBAL_CONST)
    
    // Can use local scope within policy
    ALLOW action: read ON resource: DB_Local IF (time.hour > LOCAL_CONST)
    
    // Query shows both global and local resources
    CALL RESOURCE
}

POLICY ITPolicy {
    // Another policy scope - separate from FinancePolicy
    RESOURCE DB_IT {path: "/it"}
    CONST IT_CONST = 300
    
    // Can access global scope
    ALLOW action: read ON resource: DB_Global IF (time.hour > GLOBAL_CONST)
    
    // Can use this policy's local scope
    ALLOW action: write ON resource: DB_IT IF (time.hour > IT_CONST)
}

// Back in GLOBAL SCOPE
// DB_Local and DB_IT are NOT accessible here (they're in policy scope)
ALLOW action: read ON resource: DB_Global IF (time.hour > 9)

// Query shows only global resources
CALL RESOURCE"""
}

# Initialize session state
if 'code' not in st.session_state:
    st.session_state.code = examples["policy.spl"]
if 'last_file' not in st.session_state:
    st.session_state.last_file = None

# Update code if file changed
if st.session_state.get('last_file') != example_option:
    st.session_state.code = examples[example_option]
    st.session_state.last_file = example_option

# --- 4. MAIN IDE LAYOUT ---

# Top Bar
c1, c2, c3 = st.columns([6, 1, 1])
with c1:
    st.caption(f"📝 Editing: **{example_option}**")
with c2:
    if st.button("▶ RUN", type="primary"):
        st.session_state.run_trigger = True
    else:
        st.session_state.run_trigger = False

# TOP: Code Editor
# Use file-based key so editor resets when file changes
code_input = st.text_area(
    "Code Editor", 
    value=st.session_state.code, 
    height=400, 
    key=f"editor_{example_option}", 
    label_visibility="collapsed"
)

# Sync editor content back to session state
st.session_state.code = code_input

st.markdown("---")

# BOTTOM: Output Panel
# Initialize logs variable
logs = ""

if st.session_state.run_trigger:
    # --- OUTPUT (Execution Result) ---
    st.markdown("#### Compilation Output")
    
    # Create a placeholder that we'll update progressively
    output_placeholder = st.empty()
    output_lines = []
    syntax_error = None
    analyzer = None
    risks = []
    
    def update_output():
        """Update the output display"""
        if syntax_error:
            output_placeholder.markdown(f'<div class="console-box" style="color: #ff6b6b;">{"<br>".join(output_lines)}</div>', unsafe_allow_html=True)
        elif analyzer and analyzer.errors:
            output_placeholder.markdown(f'<div class="console-box" style="color: #ff6b6b;">{"<br>".join(output_lines)}</div>', unsafe_allow_html=True)
        else:
            output_placeholder.markdown(f'<div class="console-box">{"<br>".join(output_lines)}</div>', unsafe_allow_html=True)
    
    # Step 1: Lexer Check
    output_lines.append("Lexer...")
    update_output()
    lexer_ok = False
    try:
        from lexer import lexer
        lexer.lineno = 1  # Reset
        lexer.input(code_input)
        tokens = list(lexer)
        lexer_ok = True
        output_lines[-1] = "✅ Lexer"
    except Exception as e:
        output_lines[-1] = "❌ Lexer"
        output_lines.append(f"   Error: {str(e)}")
    update_output()
    
    # Step 2: Parser Check (only if lexer passed)
    parser_ok = False
    if lexer_ok:
        output_lines.append("Parser...")
        update_output()
        try:
            from parser import parser
            import io
            from contextlib import redirect_stdout
            
            f = io.StringIO()
            with redirect_stdout(f):
                ast = parser.parse(code_input)
            
            parser_output = f.getvalue()
            if "SYNTAX ERROR" in parser_output:
                error_lines = [line.strip() for line in parser_output.split('\n') if "SYNTAX ERROR" in line]
                syntax_error = "\n".join(error_lines) if error_lines else "Syntax error detected."
                output_lines[-1] = "❌ Parser"
                output_lines.append(f"   {syntax_error}")
            elif ast:
                parser_ok = True
                output_lines[-1] = "✅ Parser"
            else:
                output_lines[-1] = "❌ Parser"
                output_lines.append("   Failed to parse")
        except Exception as e:
            output_lines[-1] = "❌ Parser"
            output_lines.append(f"   Error: {str(e)}")
        update_output()
    else:
        parser_ok = False
    
    # Step 3: Semantics Check (only if parser passed)
    semantics_ok = False
    if lexer_ok and parser_ok and not syntax_error:
        output_lines.append("Semantics...")
        update_output()
        try:
    f = io.StringIO()
    with redirect_stdout(f):
        analyzer = SemanticAnalyzer()
        analyzer.run(code_input)
        
            semantics_output = f.getvalue()
            semantics_ok = len(analyzer.errors) == 0
            if semantics_ok:
                output_lines[-1] = "✅ Semantics"
                update_output()  # Update to show Semantics check passed
                # Extract and display CALL results
                call_results = []
                for line in semantics_output.split('\n'):
                    if '[CALL' in line:  # Match [CALL] or [CALL ROLE], [CALL RESOURCE], etc.
                        call_results.append(line.strip())
                if call_results:
                    output_lines.append("")  # Add spacing
                    for result in call_results:
                        output_lines.append(result)
                    update_output()  # Update to show CALL results
            else:
                output_lines[-1] = "❌ Semantics"
                for err in analyzer.errors:
                    output_lines.append(f"   {err}")
        except Exception as e:
            output_lines[-1] = "❌ Semantics"
            output_lines.append(f"   Error: {str(e)}")
        update_output()
    
    # If all checks passed, show security scan and AI check
    ai_safety_passed = None  # None = not checked, True = passed, False = failed
    if lexer_ok and parser_ok and semantics_ok and analyzer:
        # Security scan
        scanner = SecurityScanner(analyzer.symtab)
        risks = scanner.scan()
            if risks:
                for r in risks:
                output_lines.append(f"⚠️ [RISK] Line {r['line']}: {r['message']}")
            update_output()
        
        # AI Policy Safety Check
        if st.session_state.get('ai_safety_enabled', False):
            gemini_api_key = os.getenv('GEMINI_API_KEY', '')
            gemini = get_gemini_helper(api_key=gemini_api_key) if gemini_api_key else None
            else:
            gemini = None
        
        if gemini:
            output_lines.append("")
            output_lines.append("🤖 AI Policy Safety Check...")
            update_output()
            try:
                safety_result = gemini.check_policy_safety(code_input)
                
                if safety_result.get('safe', False):
                    ai_safety_passed = True
                    output_lines.append("✅ Policy Check and Executed")
                    reason = safety_result.get('reason', 'Policy is safe to implement')
                    if reason:
                        output_lines.append(f"   Reason: {reason}")
                else:
                    ai_safety_passed = False
                    output_lines.append("❌ Policy Denied")
                    reason = safety_result.get('reason', 'Policy is not safe to implement')
                    if reason:
                        output_lines.append(f"   Reason: {reason}")
            except Exception as e:
                ai_safety_passed = False
                output_lines.append("⚠️ AI Safety Check Error")
                output_lines.append(f"   {str(e)}")
            update_output()
        else:
            # AI Safety Check disabled or not available
            if not st.session_state.get('ai_safety_enabled', False):
                ai_safety_passed = None  # Not checked (disabled)
                output_lines.append("")
                output_lines.append("ℹ️ AI Safety Check: Disabled")
        else:
                ai_safety_passed = False
                output_lines.append("")
                output_lines.append("ℹ️ AI Safety Check: Not available (GEMINI_API_KEY not found in .env)")
            update_output()
        
        # Build summary at the end - only if AI safety passed (or not checked)
        output_lines.append("")
        if ai_safety_passed is False:
            output_lines.append("❌ Build Failed.")
            output_lines.append("Policy denied by AI safety check. No policies loaded.")
        else:
            output_lines.append("✅ Build Succeeded.")
            output_lines.append(f"Loaded {len(analyzer.symtab.policies)} policies.")
        update_output()

if not st.session_state.get('run_trigger', False):
    st.markdown("#### Compilation Output")
        st.info("Ready. Click ▶ RUN to compile.")

