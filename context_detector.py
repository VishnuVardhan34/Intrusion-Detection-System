import re
from urllib.parse import unquote
import html

class ContextDetector:
    def __init__(self):
        self.contexts = {
            'html': re.compile(r'<[^>]+>'),
            'sql': re.compile(r'\b(SELECT|INSERT|UPDATE|DELETE|CREATE|DROP)\b', re.I),
            'shell': re.compile(r'[;&|`]|\$\('),
            'url': re.compile(r'%[0-9a-fA-F]{2}|https?://')
        }
        
    def detect_contexts(self, payload):
        return {
            name: pattern.search(payload) is not None 
            for name, pattern in self.contexts.items()
        }
        
    def preprocess(self, payload):
        """Normalize payload based on detected context"""
        contexts = self.detect_contexts(payload)
        processed = payload
        
        if contexts['url']:
            processed = unquote(processed)
        if contexts['html']:
            processed = html.unescape(processed)
            
        return processed.strip()