"""
Lightweight spam detector as fallback whe                         score += 2
            
        # Money patterns
        money_patterns = [  score += 3
            
        if re.search(r'[A-Z]{4,}', text): score += 2
            
        caps_ratio = sum(1 for c in text if c.isupper()) / max(len(text), 1) libraries are not available.
Uses rule-based approach with keyword matching and heuristics.
"""
import re
import logging
from config.settings import SPAM_CONFIG

logger = logging.getLogger(__name__)

class LightweightSpamDetector:
    """
    A lightweight spam detection system using rule-based heuristics.
    Used as fallback when ML libraries are not available.
    """
    
    def __init__(self):
        self.spam_keywords = SPAM_CONFIG['spam_keywords']
        self.ham_indicators = SPAM_CONFIG['ham_indicators']
        logger.info("Lightweight spam detector initialized")
    
    def count_keywords(self, text, keywords):
        """Count occurrences of keywords in text."""
        if not isinstance(text, str):
            return 0
            
        text_lower = text.lower()
        count = 0
        
        for keyword in keywords:
            # Count word boundaries to avoid partial matches
            pattern = r'\b' + re.escape(keyword.lower()) + r'\b'
            matches = re.findall(pattern, text_lower)
            count += len(matches)
            
        return count
    
    def check_suspicious_patterns(self, text):
        """Check for suspicious patterns commonly found in spam."""
        if not isinstance(text, str):
            return 0
            
        score = 0
        text_lower = text.lower()
        
        if text.count('!') > 3:
            score += 1
            
        # Excessive capital letters
        caps_ratio = sum(1 for c in text if c.isupper()) / max(len(text), 1)
        if caps_ratio > 0.3:
            score += 2
            
        # Multiple consecutive capital letters
        if re.search(r'[A-Z]{4,}', text):
            score += 1
            
        # Money-related patterns
        money_patterns = [
            r'\$\d+',  # $100
            r'\d+\s*dollars?',  # 100 dollars
            r'\d+\s*euros?',  # 100 euros
            r'free\s+money',  # free money
            r'cash\s+prize',  # cash prize
            r'win\s+\$',  # win $
        ]
        
        for pattern in money_patterns:
            if re.search(pattern, text_lower):
                score += 1
                
        # URL shorteners and suspicious domains
        url_patterns = [
            r'bit\.ly',
            r'tinyurl',
            r'goo\.gl',
            r't\.co',
            r'ow\.ly',
            r'is\.gd',
        ]
        
        for pattern in url_patterns:
            if re.search(pattern, text_lower):
                score += 1
                
        # Urgency indicators
        urgency_patterns = [
            r'urgent',
            r'immediate',
            r'expires?\s+(today|tomorrow|soon)',
            r'limited\s+time',
            r'act\s+now',
            r'hurry',
            r'don\'?t\s+wait',
        ]
        
        for pattern in urgency_patterns:
            if re.search(pattern, text_lower):
                score += 1
                
        # Suspicious characters and encoding
        if re.search(r'[^\x00-\x7F]', text):  # Non-ASCII characters
            score += 0.5
            
        # Excessive whitespace or formatting
        if re.search(r'\s{5,}', text):  # 5+ consecutive spaces
            score += 0.5
            
        return score
    
    def check_unsubscribe_patterns(self, text):
        """Check for legitimate unsubscribe patterns (positive indicator)."""
        if not isinstance(text, str):
            return 0
            
        text_lower = text.lower()
        score = 0
        
        # Legitimate unsubscribe patterns
        unsubscribe_patterns = [
            r'unsubscribe',
            r'opt\s+out',
            r'remove\s+me',
            r'stop\s+emails?',
            r'email\s+preferences',
            r'manage\s+subscription',
        ]
        
        for pattern in unsubscribe_patterns:
            if re.search(pattern, text_lower):
                score += 1
                
        return score
    
    def analyze_sender_reputation(self, sender_email):
        """Analyze sender reputation based on domain and patterns."""
        if not isinstance(sender_email, str):
            return 0
            
        score = 0
        email_lower = sender_email.lower()
        
        # Suspicious domains
        suspicious_domains = [
            'tempmail', 'guerrillamail', '10minutemail', 'mailinator',
            'throwaway', 'temp-mail', 'yopmail', 'getairmail'
        ]
        
        for domain in suspicious_domains:
            if domain in email_lower:
                score += 2
                
        # Random character patterns in email
        if re.search(r'[a-z]{1,2}\d{3,}@', email_lower):  # like ab123@
            score += 1
            
        if re.search(r'\d{5,}@', email_lower):  # numbers only before @
            score += 1
            
        # Legitimate domains (negative score - good)
        legitimate_domains = [
            'gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com',
            'aol.com', 'icloud.com', 'protonmail.com', 'company.com'
        ]
        
        for domain in legitimate_domains:
            if domain in email_lower:
                score -= 1
                
        return max(0, score)  # Don't go below 0
    
    def is_spam(self, text, sender_email=""):
        """
        Determine if text is spam using rule-based heuristics.
        Returns: dict with is_spam (bool) and confidence (float)
        """
        if not isinstance(text, str):
            return {"is_spam": False, "confidence": 0.0}
            
        # Count spam keywords
        spam_count = self.count_keywords(text, self.spam_keywords)
        
        # Count ham indicators
        ham_count = self.count_keywords(text, self.ham_indicators)
        
        # Check suspicious patterns
        suspicious_score = self.check_suspicious_patterns(text)
        
        # Check unsubscribe patterns (legitimate emails often have these)
        unsubscribe_score = self.check_unsubscribe_patterns(text)
        
        # Analyze sender if provided
        sender_score = self.analyze_sender_reputation(sender_email) if sender_email else 0
        
        # Calculate spam score
        spam_score = (spam_count * 2) + suspicious_score + sender_score - (ham_count * 1.5) - (unsubscribe_score * 0.5)
        
        # Text length factor (very short texts are more likely spam)
        text_length = len(text.strip())
        if text_length < 50:
            spam_score += 1
        elif text_length > 1000:
            spam_score -= 0.5  # Longer emails less likely to be spam
            
        # Determine if spam based on score
        is_spam = spam_score > 2.0
        
        # Calculate confidence based on score magnitude
        confidence = min(abs(spam_score) / 5.0, 1.0)  # Normalize to [0, 1]
        
        # Ensure minimum confidence
        confidence = max(confidence, 0.1)
        
        logger.debug(f"Spam analysis - Score: {spam_score:.2f}, Is spam: {is_spam}, Confidence: {confidence:.2f}")
        
        return {
            "is_spam": is_spam,
            "confidence": confidence,
            "spam_score": spam_score,
            "details": {
                "spam_keywords": spam_count,
                "ham_indicators": ham_count,
                "suspicious_patterns": suspicious_score,
                "unsubscribe_patterns": unsubscribe_score,
                "sender_reputation": sender_score,
                "text_length": text_length
            }
        }

# Example usage
if __name__ == "__main__":
    detector = LightweightSpamDetector()
    
    test_emails = [
        "Congratulations! You've won $1,000,000! Click here NOW to claim your prize!",
        "Hi team, please find attached the quarterly report for review.",
        "URGENT: Your account will be suspended! Act immediately!",
        "Meeting reminder: Project sync at 3pm tomorrow in conference room A.",
        "FREE MONEY!!! Get rich quick with this amazing opportunity!!!",
    ]
    
    for email in test_emails:
        result = detector.is_spam(email)
        print(f"Email: {email[:50]}...")
        print(f"Spam: {result['is_spam']}, Confidence: {result['confidence']:.2f}")
        print(f"Details: {result['details']}")
        print("-" * 60)
