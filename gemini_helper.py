"""
Gemini LLM Integration for SPL IDE
Provides AI-powered code analysis, security scanning, and assistance
"""

import os
from google import genai
from typing import Optional, Dict, List

class GeminiHelper:
    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize Gemini helper.
        
        Args:
            api_key: Google Gemini API key. If None, will try to get from environment variable GEMINI_API_KEY
        """
        self.api_key = api_key or os.getenv('GEMINI_API_KEY')
        if not self.api_key:
            raise ValueError("Gemini API key not provided. Set GEMINI_API_KEY environment variable or pass api_key parameter.")
        
        # Initialize client with API key
        self.client = genai.Client(api_key=self.api_key)
        self.model_name = "gemini-2.5-flash"  # Use latest model
    
    def analyze_security(self, code: str) -> Dict[str, any]:
        """
        Analyze SPL code for security risks using Gemini.
        
        Args:
            code: SPL source code to analyze
            
        Returns:
            Dictionary with 'risks' (list of risk descriptions) and 'suggestions' (list of improvement suggestions)
        """
        prompt = f"""You are a security expert analyzing Secure Policy Language (SPL) code.

SPL Grammar:
- ROLE definitions: ROLE <name> {{can: <actions>}}
- USER definitions: USER <name> {{ role: <role_name> }}
- RESOURCE definitions: RESOURCE <name> {{path: "<path>"}}
- Policy rules: ALLOW/DENY action: <actions> ON resource: <resource> IF <condition>

Analyze the following SPL code for security risks:

```spl
{code}
```

Provide:
1. Security risks found (if any) - be specific about what's wrong and why
2. Suggestions for improvement (if any)

Format your response as:
RISKS:
- Risk 1 description
- Risk 2 description

SUGGESTIONS:
- Suggestion 1
- Suggestion 2

If no risks or suggestions, say "No security issues found."
"""
        
        try:
            response = self.client.models.generate_content(
                model=self.model_name,
                contents=prompt
            )
            result = self._parse_response(response.text)
            return result
        except Exception as e:
            return {
                'risks': [f"Error analyzing code: {str(e)}"],
                'suggestions': [],
                'error': str(e)
            }
    
    def explain_error(self, error_message: str, code: str, line_number: int) -> str:
        """
        Get AI explanation for a syntax or semantic error.
        
        Args:
            error_message: The error message from the parser
            code: The SPL source code
            line_number: Line number where error occurred
            
        Returns:
            Explanation and suggested fix
        """
        prompt = f"""You are helping a developer fix an error in Secure Policy Language (SPL) code.

Error: {error_message}
Line: {line_number}

Code:
```spl
{code}
```

Explain what the error means and suggest how to fix it. Be concise and helpful.
"""
        
        try:
            response = self.client.models.generate_content(
                model=self.model_name,
                contents=prompt
            )
            return response.text
        except Exception as e:
            return f"Error getting explanation: {str(e)}"
    
    def suggest_fix(self, code: str, error_message: str) -> str:
        """
        Get AI-suggested fix for code with errors.
        
        Args:
            code: The SPL source code with errors
            error_message: The error message
            
        Returns:
            Fixed code or explanation
        """
        prompt = f"""Fix the following SPL code that has an error.

Error: {error_message}

Code with error:
```spl
{code}
```

Provide the corrected code. Only return the fixed code, no explanations.
"""
        
        try:
            response = self.client.models.generate_content(
                model=self.model_name,
                contents=prompt
            )
            return response.text.strip()
        except Exception as e:
            return f"Error getting fix: {str(e)}"
    
    def check_policy_safety(self, code: str) -> Dict[str, any]:
        """
        Check if a policy is safe to implement. Only call this after code passes lexer, parser, and semantics.
        
        Args:
            code: The SPL source code that has already passed compilation
            
        Returns:
            Dictionary with 'safe' (bool), 'reason' (str), and 'details' (str)
        """
        prompt = f"""You are a security expert evaluating a Secure Policy Language (SPL) policy for implementation safety.

The following policy has already passed:
- Lexical analysis (tokenization) ✅
- Syntax parsing (grammar validation) ✅
- Semantic analysis (symbol validation) ✅

Now evaluate if this policy is SAFE TO IMPLEMENT in a production environment.

SPL Code:
```spl
{code}
```

Evaluate for:
- Security risks (overly permissive, missing restrictions)
- Best practices (time restrictions, least privilege)
- Potential vulnerabilities
- Implementation safety

Respond in EXACTLY this format (no other text):
SAFE: yes
REASON: [very short reason - max 15 words]

OR

SAFE: no
REASON: [very short reason - max 15 words]

Examples:
- SAFE: yes, REASON: Policy follows security best practices with time restrictions
- SAFE: no, REASON: Overly permissive - Guest role has all permissions
- SAFE: no, REASON: Missing time restrictions on sensitive resource
"""
        
        try:
            response = self.client.models.generate_content(
                model=self.model_name,
                contents=prompt
            )
            result = self._parse_safety_response(response.text)
            return result
        except Exception as e:
            return {
                'safe': False,
                'reason': f"Error checking safety: {str(e)}",
                'details': str(e)
            }
    
    def _parse_safety_response(self, text: str) -> Dict[str, any]:
        """Parse safety check response."""
        safe = False
        reason = "Unable to determine safety"
        
        lines = text.split('\n')
        for line in lines:
            line = line.strip()
            if line.upper().startswith('SAFE:'):
                safe_str = line.split(':', 1)[1].strip().lower()
                safe = safe_str in ['yes', 'true', '1', 'safe']
            elif line.upper().startswith('REASON:'):
                reason = line.split(':', 1)[1].strip()
                # Limit reason length
                if len(reason) > 100:
                    reason = reason[:97] + "..."
        
        return {
            'safe': safe,
            'reason': reason,
            'details': text
        }
    
    def explain_step(self, step_name: str, step_result: str, code_snippet: str = "") -> str:
        """
        Get a short LLM explanation of an execution step.
        
        Args:
            step_name: Name of the step (e.g., "Lexer", "Parser", "Semantics")
            step_result: Result of the step (e.g., "✅ Passed", "❌ Failed")
            code_snippet: Optional code snippet relevant to the step
            
        Returns:
            Short explanation (max 50 words)
        """
        prompt = f"""Explain what happened in this SPL compilation step in ONE SHORT SENTENCE (max 15 words):

Step: {step_name}
Result: {step_result}
{f'Code: {code_snippet[:200]}' if code_snippet else ''}

Provide only a brief explanation of what this step does and its result."""
        
        try:
            response = self.client.models.generate_content(
                model=self.model_name,
                contents=prompt
            )
            explanation = response.text.strip()
            
            if not explanation:
                return f"Step {step_name} completed with {step_result.lower()}"
            
            # Limit to 50 words
            words = explanation.split()
            if len(words) > 50:
                explanation = ' '.join(words[:50]) + '...'
            return explanation
        except Exception as e:
            # Return a fallback explanation instead of failing silently
            return f"Step {step_name} completed with {step_result.lower()}"
    
    def generate_code(self, description: str) -> str:
        """
        Generate SPL code from a natural language description.
        
        Args:
            description: Natural language description of the policy
            
        Returns:
            Generated SPL code
        """
        prompt = f"""Generate Secure Policy Language (SPL) code based on this description:

{description}

SPL Grammar:
- ROLE <name> {{can: <actions>}}
- USER <name> {{ role: <role_name> }}
- RESOURCE <name> {{path: "<path>"}}
- ALLOW/DENY action: <actions> ON resource: <resource> IF <condition>

Return only the SPL code, no explanations.
"""
        
        try:
            response = self.client.models.generate_content(
                model=self.model_name,
                contents=prompt
            )
            return response.text.strip()
        except Exception as e:
            return f"Error generating code: {str(e)}"
    
    def _parse_response(self, text: str) -> Dict[str, List[str]]:
        """Parse Gemini response into structured format."""
        risks = []
        suggestions = []
        
        lines = text.split('\n')
        current_section = None
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            if 'RISKS:' in line.upper() or 'RISK:' in line.upper():
                current_section = 'risks'
                continue
            elif 'SUGGESTIONS:' in line.upper() or 'SUGGESTION:' in line.upper():
                current_section = 'suggestions'
                continue
            elif line.startswith('-') or line.startswith('•'):
                content = line[1:].strip()
                if current_section == 'risks':
                    risks.append(content)
                elif current_section == 'suggestions':
                    suggestions.append(content)
            elif current_section == 'risks' and line:
                risks.append(line)
            elif current_section == 'suggestions' and line:
                suggestions.append(line)
        
        # If no structured format, treat entire response as risks
        if not risks and not suggestions:
            if 'no security issues' in text.lower() or 'no risks' in text.lower():
                return {'risks': [], 'suggestions': []}
            risks = [text]
        
        return {
            'risks': risks,
            'suggestions': suggestions
        }

# Singleton instance
_gemini_helper: Optional[GeminiHelper] = None

def get_gemini_helper(api_key: Optional[str] = None) -> Optional[GeminiHelper]:
    """
    Get or create Gemini helper instance.
    
    Args:
        api_key: Optional API key. If None and instance doesn't exist, will try environment variable.
        
    Returns:
        GeminiHelper instance or None if API key not available
    """
    global _gemini_helper
    
    if _gemini_helper is None:
        try:
            _gemini_helper = GeminiHelper(api_key=api_key)
        except ValueError:
            return None
    
    return _gemini_helper

