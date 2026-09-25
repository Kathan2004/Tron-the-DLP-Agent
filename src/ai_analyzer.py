import json
import os
from typing import Dict, Optional
import requests
from config.settings import Config
from src.file_scanner import redact_for_llm

class VertexAIAnalyzer:
    """Incident analysis using Google Generative AI (Gemini)"""
    
    def __init__(self):
        self.api_key = os.getenv("GOOGLE_GENAI_API_KEY") or Config.GOOGLE_GENAI_API_KEY
        self.model = "gemini-2.0-flash"
        self.api_url = "https://generativelanguage.googleapis.com/v1beta/models"
    
    def analyze_incident(
        self,
        incident_id: str,
        user: str,
        host: str,
        channel: str,
        pattern: str,
        alert_count: int,
        detections: str,
        events_summary: str
    ) -> Dict:
        """Analyze incident using Google Generative AI"""

        # Only redacted values may reach the external LLM.
        incident_id, user, host, channel, pattern, detections, events_summary = (
            redact_for_llm(str(v)) for v in
            (incident_id, user, host, channel, pattern, detections, events_summary)
        )

        prompt = f"""You are a DLP (Data Loss Prevention) security analyst. Analyze this security incident and provide JSON response ONLY with no markdown:

INCIDENT: {incident_id}
User: {user} | Host: {host} | Channel: {channel}
Pattern: {pattern} | Alerts: {alert_count} in 30min
Detections: {detections}
Events: {events_summary}

Respond with ONLY this JSON (no extra text):
{{"false_positive_probability": 0-100, "verdict": "LIKELY_THREAT|LIKELY_FP|NEEDS_REVIEW", "threat_pattern": "description", "recommended_action": "CLOSE|MONITOR|ESCALATE", "risk_score": 0-100, "reasoning": "brief"}}"""

        try:
            if not self.api_key:
                print("⚠️ GOOGLE_GENAI_API_KEY not set")
                return self._default_analysis()
            
            headers = {
                "Content-Type": "application/json",
                "x-goog-api-key": self.api_key,
            }
            
            payload = {
                "contents": [{
                    "parts": [{
                        "text": prompt
                    }]
                }]
            }
            
            url = f"{self.api_url}/{self.model}:generateContent"
            response = requests.post(url, json=payload, headers=headers, timeout=30)
            
            if response.status_code != 200:
                print(f"⚠️ Gemini API error: {response.status_code}")
                return self._default_analysis()
            
            result = response.json()
            
            # Check for Gemini 2.0 response format (candidates)
            if "candidates" in result and len(result["candidates"]) > 0:
                text_content = result["candidates"][0]["content"]["parts"][0]["text"]
                json_str = self._extract_json(text_content)
                
                try:
                    analysis = json.loads(json_str)
                    return analysis
                except json.JSONDecodeError:
                    print(f"⚠️ Could not parse AI response JSON")
                    return self._default_analysis()
            
            return self._default_analysis()
        
        except Exception as e:
            print(f"⚠️ AI analysis error: {e}")
            return self._default_analysis()
    
    def generate_rule_from_prompt(self, user_prompt: str) -> Dict:
        """Convert a natural language prompt into a structured DLP rule."""
        
        system_instructions = """You are a DLP Security Architect. Convert the user's natural language request into a JSON DLP rule.
Supported Rule Types:
1. 'regex': For text patterns (PII, secrets, etc.)
2. 'file_size': For blocking/monitoring large files. Parameters: 'max_size_mb' (int)
3. 'extension': For forbidden file types. Parameters: 'blocked_extensions' (list of strings)
4. 'network': For risky domains/IPs. Parameters: 'blocked_domains' (list)

Respond ONLY with JSON:
{
  "name": "SHORT_UPPERCASE_NAME",
  "description": "Clear description of what this rule does",
  "rule_type": "regex|file_size|extension|network",
  "rule_data": { 
     // for regex: {"pattern": "..."}
     // for file_size: {"max_size_mb": 10}
     // for extension: {"blocked_extensions": [".exe", ".zip"]}
     // for network: {"blocked_domains": ["risky.site"]}
  },
  "severity": "LOW|MEDIUM|HIGH|CRITICAL",
  "action": "monitor|warn|block"
}
"""
        
        prompt = f"{system_instructions}\n\nUSER REQUEST: {redact_for_llm(user_prompt)}\n\nJSON RULE:"
        
        try:
            if not self.api_key:
                return {"error": "API key not configured"}
                
            headers = {"Content-Type": "application/json", "x-goog-api-key": self.api_key}
            payload = {
                "contents": [{"parts": [{"text": prompt}]}]
            }
            
            url = f"{self.api_url}/{self.model}:generateContent"
            response = requests.post(url, json=payload, headers=headers, timeout=30)
            
            if response.status_code != 200:
                print(f"⚠️ Rule Generation failed: {response.status_code} - {response.text}")
                return {"error": f"AI Service error: {response.status_code}"}
                
            result = response.json()
            if "candidates" in result and len(result["candidates"]) > 0:
                text = result["candidates"][0]["content"]["parts"][0]["text"]
                json_str = self._extract_json(text)
                return json.loads(json_str)
                
            print(f"⚠️ Rule Generation empty response: {result}")
            return {"error": "AI could not generate a rule for this prompt. Try a more specific request."}
            
        except Exception as e:
            print(f"⚠️ Rule Generation exception: {e}")
            return {"error": f"Internal Error: {str(e)}"}

    def _extract_json(self, text: str) -> str:
        """Extract JSON from response"""
        start = text.find("{")
        end = text.rfind("}") + 1
        
        if start >= 0 and end > start:
            return text[start:end]
        
        return "{}"
    
    def _default_analysis(self) -> Dict:
        """Default analysis when API fails"""
        return {
            "false_positive_probability": 50,
            "verdict": "NEEDS_REVIEW",
            "threat_pattern": "Manual review needed",
            "recommended_action": "MONITOR",
            "risk_score": 50,
            "reasoning": "AI analysis unavailable. Please review manually."
        }


class FalsePositiveClassifier:
    """Classify incidents as false positive or threat"""
    
    def __init__(self, analyzer: VertexAIAnalyzer):
        self.analyzer = analyzer
    
    def classify(
        self,
        incident_id: str,
        user: str,
        host: str,
        channel: str,
        pattern: str,
        alert_count: int,
        detections: str,
        events_summary: str
    ) -> Dict:
        """Run analysis and classification"""
        
        analysis = self.analyzer.analyze_incident(
            incident_id=incident_id,
            user=user,
            host=host,
            channel=channel,
            pattern=pattern,
            alert_count=alert_count,
            detections=detections,
            events_summary=events_summary
        )
        
        # Add classification metadata
        fp_prob = analysis.get("false_positive_probability", 50)
        verdict = analysis.get("verdict", "NEEDS_REVIEW")
        
        analysis["auto_close"] = (fp_prob > Config.FP_AUTO_CLOSE_THRESHOLD)
        analysis["should_escalate"] = verdict == "LIKELY_THREAT"
        
        return analysis
