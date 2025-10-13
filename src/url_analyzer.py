"""
URL analyzer with phishing detection and VirusTotal integration
"""
import re
import requests
import logging
import time
import hashlib
from urllib.parse import urlparse, urljoin
from typing import Dict, List, Tuple, Optional
import socket
from datetime import datetime
import json
import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from config.settings import URL_ANALYSIS_CONFIG, VIRUSTOTAL_CONFIG

logger = logging.getLogger(__name__)

class URLAnalyzer:
    """
    Comprehensive URL security analyzer with multiple detection methods.
    """
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': URL_ANALYSIS_CONFIG['user_agent']
        })
        self.vt_api_key = VIRUSTOTAL_CONFIG['api_key']
        self.phishing_keywords = URL_ANALYSIS_CONFIG['phishing_keywords']
        self.suspicious_tlds = URL_ANALYSIS_CONFIG['suspicious_tlds']
        self.last_vt_request = 0
        self._setup_vt_headers()
        
        logger.info("URL Analyzer initialized with security features")
    
    def _setup_vt_headers(self):
        """Setup VirusTotal API headers."""
        if self.vt_api_key:
            self.vt_headers = {
                'apikey': self.vt_api_key,
                'User-Agent': 'UnsubSpamBot/1.0'
            }
            logger.info("VirusTotal API configured")
        else:
            self.vt_headers = None
            logger.warning("VirusTotal API key not configured")
    
    def _rate_limit_vt(self):
        """Rate limit VirusTotal requests (free tier: 4 requests per minute)."""
        if not self.vt_api_key:
            return
            
        time_since_last = time.time() - self.last_vt_request
        min_interval = 60 / VIRUSTOTAL_CONFIG['max_requests_per_minute']
        
        if time_since_last < min_interval:
            sleep_time = min_interval - time_since_last
            logger.debug(f"Rate limiting VirusTotal request, sleeping {sleep_time:.2f}s")
            time.sleep(sleep_time)
            
        self.last_vt_request = time.time()
    
    def extract_urls_from_text(self, text: str) -> List[str]:
        """Extract URLs from text content."""
        if not isinstance(text, str):
            return []
            
        url_patterns = [
            r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',
            r'www\.(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',
            r'[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}'
        ]
        
        urls = []
        for pattern in url_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            urls.extend(matches)
        
        cleaned_urls = []
        for url in urls:
            if not url.startswith(('http://', 'https://')):
                if url.startswith('www.'):
                    url = 'https://' + url
                else:
                    url = 'https://' + url
            cleaned_urls.append(url)
        
        return list(set(cleaned_urls))  # Remove dupes
    
    def analyze_url_structure(self, url: str) -> Dict:
        """Analyze URL structure for suspicious patterns."""
        try:
            parsed = urlparse(url)
            analysis = {
                'domain': parsed.netloc.lower(),
                'path': parsed.path,
                'query': parsed.query,
                'fragment': parsed.fragment,
                'scheme': parsed.scheme,
                'suspicious_score': 0,
                'flags': []
            }
            
            domain = analysis['domain']
            path = analysis['path']
            
            # Check for suspicious TLDs
            for tld in self.suspicious_tlds:
                if domain.endswith(tld):
                    analysis['suspicious_score'] += 2
                    analysis['flags'].append(f'suspicious_tld_{tld}')
            
            # Check for IP addresses instead of domains
            try:
                socket.inet_aton(domain.replace('www.', ''))
                analysis['suspicious_score'] += 3
                analysis['flags'].append('ip_address_domain')
            except socket.error:
                pass  
            
            # Check for suspicious domain patterns
            if re.search(r'\d{3,}', domain):  # Many numbers in domain
                analysis['suspicious_score'] += 1
                analysis['flags'].append('numeric_domain')
            
            if len(domain.split('.')) > 4:  # Too many subdomains
                analysis['suspicious_score'] += 1
                analysis['flags'].append('excessive_subdomains')
            
            if re.search(r'[0-9a-f]{8,}', domain):  # Hex patterns
                analysis['suspicious_score'] += 2
                analysis['flags'].append('hex_domain')
            
            # Check for URL shorteners
            shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 
                         'buff.ly', 'adf.ly', 'short.link', 'tiny.cc']
            if any(shortener in domain for shortener in shorteners):
                analysis['suspicious_score'] += 2
                analysis['flags'].append('url_shortener')
            
            # Check path for suspicious patterns
            if re.search(r'[a-zA-Z0-9]{20,}', path):  # Long random strings
                analysis['suspicious_score'] += 1
                analysis['flags'].append('random_path')
            
            # Check for misleading domain patterns
            trusted_domains = ['google', 'microsoft', 'apple', 'amazon', 'paypal', 'bank']
            for trusted in trusted_domains:
                if trusted in domain and not domain.endswith(f'{trusted}.com'):
                    analysis['suspicious_score'] += 3
                    analysis['flags'].append(f'mimics_{trusted}')
            
            return analysis
            
        except Exception as e:
            logger.error(f"Error analyzing URL structure: {e}")
            return {'error': str(e)}
    
    def check_phishing_indicators(self, url: str, content: str = "") -> Dict:
        """Check for phishing indicators in URL and content."""
        indicators = {
            'phishing_score': 0,
            'indicators': [],
            'risk_level': 'low'
        }
        
        try:
            url_lower = url.lower()
            content_lower = content.lower() if content else ""
            
            # Check URL for phishing keywords
            for keyword in self.phishing_keywords:
                if keyword in url_lower:
                    indicators['phishing_score'] += 2
                    indicators['indicators'].append(f'url_keyword_{keyword}')
            
            # Check content for phishing keywords
            if content:
                for keyword in self.phishing_keywords:
                    if keyword in content_lower:
                        indicators['phishing_score'] += 1
                        indicators['indicators'].append(f'content_keyword_{keyword}')
            
            # Check for homograph attacks (similar looking characters)
            suspicious_chars = ['а', 'е', 'о', 'р', 'с', 'у', 'х']  # Cyrillic that look like Latin
            for char in suspicious_chars:
                if char in url_lower:
                    indicators['phishing_score'] += 3
                    indicators['indicators'].append('homograph_attack')
                    break
            
            # Check for typosquatting of popular domains
            popular_domains = ['google.com', 'facebook.com', 'microsoft.com', 'amazon.com', 
                             'paypal.com', 'apple.com', 'netflix.com', 'instagram.com']
            
            parsed_url = urlparse(url)
            domain = parsed_url.netloc.lower()
            
            for popular in popular_domains:
                # Check for character substitution
                if self._is_typosquat(domain, popular):
                    indicators['phishing_score'] += 4
                    indicators['indicators'].append(f'typosquat_{popular}')
            
            # Determine risk level
            if indicators['phishing_score'] >= 5:
                indicators['risk_level'] = 'high'
            elif indicators['phishing_score'] >= 3:
                indicators['risk_level'] = 'medium'
            else:
                indicators['risk_level'] = 'low'
            
            return indicators
            
        except Exception as e:
            logger.error(f"Error checking phishing indicators: {e}")
            return {'error': str(e)}
    
    def _is_typosquat(self, domain: str, target: str) -> bool:
        """Check if domain is a typosquat of target domain."""
        if len(domain) != len(target):
            if abs(len(domain) - len(target)) > 2:
                return False
        
        # Calculate Levenshtein distance
        distance = self._levenshtein_distance(domain, target)
        
        # 1-3 char difference = likely typosquat
        return 1 <= distance <= 3
    
    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        """Calculate Levenshtein distance between two strings."""
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)
        
        if len(s2) == 0:
            return len(s1)
        
        previous_row = list(range(len(s2) + 1))
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        return previous_row[-1]
    
    def follow_redirect_chain(self, url: str, max_redirects: int = None) -> Dict:
        """Follow redirect chain and analyze each step."""
        if max_redirects is None:
            max_redirects = URL_ANALYSIS_CONFIG['max_redirects']
        
        redirect_chain = []
        current_url = url
        
        try:
            for i in range(max_redirects):
                response = self.session.head(
                    current_url, 
                    allow_redirects=False,
                    timeout=URL_ANALYSIS_CONFIG['timeout']
                )
                
                redirect_info = {
                    'step': i + 1,
                    'url': current_url,
                    'status_code': response.status_code,
                    'headers': dict(response.headers),
                    'final': False
                }
                
                redirect_chain.append(redirect_info)
                
                if response.status_code in [301, 302, 303, 307, 308]:
                    next_url = response.headers.get('Location')
                    if next_url:
                        if not next_url.startswith('http'):
                            next_url = urljoin(current_url, next_url)
                        current_url = next_url
                    else:
                        break
                else:
                    redirect_chain[-1]['final'] = True
                    break
            
            # Analyze redirect chain for suspicious patterns
            analysis = self._analyze_redirect_chain(redirect_chain)
            
            return {
                'redirect_chain': redirect_chain,
                'final_url': current_url,
                'redirect_count': len(redirect_chain) - 1,
                'analysis': analysis
            }
            
        except Exception as e:
            logger.error(f"Error following redirect chain: {e}")
            return {'error': str(e)}
    
    def _analyze_redirect_chain(self, chain: List[Dict]) -> Dict:
        """Analyze redirect chain for suspicious patterns."""
        analysis = {
            'suspicious_score': 0,
            'flags': [],
            'risk_level': 'low'
        }
        
        if len(chain) > 5:
            analysis['suspicious_score'] += 2
            analysis['flags'].append('excessive_redirects')
        
        # Check for redirect loops
        urls = [step['url'] for step in chain]
        if len(urls) != len(set(urls)):
            analysis['suspicious_score'] += 3
            analysis['flags'].append('redirect_loop')
        
        # Check for suspicious domain changes
        domains = []
        for step in chain:
            domain = urlparse(step['url']).netloc
            domains.append(domain)
        
        unique_domains = set(domains)
        if len(unique_domains) > 3:
            analysis['suspicious_score'] += 2
            analysis['flags'].append('multiple_domain_redirects')
        
        # Check for protocol downgrades
        for i in range(1, len(chain)):
            prev_scheme = urlparse(chain[i-1]['url']).scheme
            curr_scheme = urlparse(chain[i]['url']).scheme
            
            if prev_scheme == 'https' and curr_scheme == 'http':
                analysis['suspicious_score'] += 3
                analysis['flags'].append('https_downgrade')
        
        # Determine risk level
        if analysis['suspicious_score'] >= 5:
            analysis['risk_level'] = 'high'
        elif analysis['suspicious_score'] >= 3:
            analysis['risk_level'] = 'medium'
        
        return analysis
    
    def check_virustotal(self, url: str) -> Dict:
        """Check URL against VirusTotal database."""
        if not self.vt_api_key:
            return {'error': 'VirusTotal API key not configured'}
        
        try:
            self._rate_limit_vt()
            
            # Submit URL for scanning
            scan_url = 'https://www.virustotal.com/vtapi/v2/url/scan'
            scan_params = {
                'apikey': self.vt_api_key,
                'url': url
            }
            
            scan_response = requests.post(scan_url, data=scan_params, 
                                        timeout=VIRUSTOTAL_CONFIG['timeout'])
            
            if scan_response.status_code != 200:
                return {'error': f'VirusTotal scan failed: {scan_response.status_code}'}
            
            scan_result = scan_response.json()
            resource = scan_result.get('resource')
            
            if not resource:
                return {'error': 'Failed to get scan resource'}
            
            # Wait a moment for scan to process
            time.sleep(2)
            
            # Get report
            report_url = 'https://www.virustotal.com/vtapi/v2/url/report'
            report_params = {
                'apikey': self.vt_api_key,
                'resource': resource
            }
            
            self._rate_limit_vt()
            report_response = requests.get(report_url, params=report_params,
                                         timeout=VIRUSTOTAL_CONFIG['timeout'])
            
            if report_response.status_code != 200:
                return {'error': f'VirusTotal report failed: {report_response.status_code}'}
            
            report_data = report_response.json()
            
            if report_data.get('response_code') == 0:
                return {'status': 'not_found', 'message': 'URL not found in VirusTotal database'}
            
            # Parse results
            positives = report_data.get('positives', 0)
            total = report_data.get('total', 0)
            scans = report_data.get('scans', {})
            
            # Calculate risk score
            risk_score = (positives / max(total, 1)) * 100 if total > 0 else 0
            
            # Determine risk level
            if risk_score >= 20:
                risk_level = 'high'
            elif risk_score >= 5:
                risk_level = 'medium'
            elif risk_score > 0:
                risk_level = 'low'
            else:
                risk_level = 'clean'
            
            return {
                'status': 'scanned',
                'positives': positives,
                'total': total,
                'risk_score': risk_score,
                'risk_level': risk_level,
                'scan_date': report_data.get('scan_date'),
                'permalink': report_data.get('permalink'),
                'detected_engines': [engine for engine, result in scans.items() 
                                   if result.get('detected', False)],
                'clean_engines': [engine for engine, result in scans.items() 
                                if not result.get('detected', False)]
            }
            
        except Exception as e:
            logger.error(f"VirusTotal check failed: {e}")
            return {'error': str(e)}
    
    def comprehensive_analysis(self, url: str, content: str = "") -> Dict:
        """Perform comprehensive URL security analysis."""
        logger.info(f"Starting comprehensive analysis of: {url}")
        
        analysis_result = {
            'url': url,
            'timestamp': datetime.now().isoformat(),
            'structure_analysis': {},
            'phishing_check': {},
            'redirect_analysis': {},
            'virustotal_check': {},
            'overall_risk_score': 0,
            'overall_risk_level': 'unknown',
            'recommendations': []
        }
        
        try:
            # URL structure analysis
            logger.debug("Analyzing URL structure...")
            analysis_result['structure_analysis'] = self.analyze_url_structure(url)
            
            # Phishing indicators check
            logger.debug("Checking phishing indicators...")
            analysis_result['phishing_check'] = self.check_phishing_indicators(url, content)
            
            # Redirect chain analysis
            logger.debug("Following redirect chain...")
            analysis_result['redirect_analysis'] = self.follow_redirect_chain(url)
            
            # VirusTotal check
            if self.vt_api_key:
                logger.debug("Checking VirusTotal...")
                analysis_result['virustotal_check'] = self.check_virustotal(url)
            else:
                analysis_result['virustotal_check'] = {'status': 'skipped', 'reason': 'API key not configured'}
            
            # Calculate overall risk score
            analysis_result['overall_risk_score'] = self._calculate_overall_risk(analysis_result)
            analysis_result['overall_risk_level'] = self._determine_risk_level(analysis_result['overall_risk_score'])
            analysis_result['recommendations'] = self._generate_recommendations(analysis_result)
            
            logger.info(f"Analysis complete. Risk level: {analysis_result['overall_risk_level']}")
            return analysis_result
            
        except Exception as e:
            logger.error(f"Comprehensive analysis failed: {e}")
            analysis_result['error'] = str(e)
            return analysis_result
    
    def _calculate_overall_risk(self, analysis: Dict) -> float:
        """Calculate overall risk score from all analysis components."""
        score = 0.0
        
        # Structure analysis score
        structure = analysis.get('structure_analysis', {})
        if 'suspicious_score' in structure:
            score += structure['suspicious_score'] * 0.3
        
        # Phishing score
        phishing = analysis.get('phishing_check', {})
        if 'phishing_score' in phishing:
            score += phishing['phishing_score'] * 0.4
        
        # Redirect analysis score
        redirect = analysis.get('redirect_analysis', {})
        if 'analysis' in redirect and 'suspicious_score' in redirect['analysis']:
            score += redirect['analysis']['suspicious_score'] * 0.2
        
        # VirusTotal score
        vt = analysis.get('virustotal_check', {})
        if 'risk_score' in vt:
            score += (vt['risk_score'] / 100) * 10 * 0.1  # Normalize to 0-1 scale then to 0-10
        
        return min(score, 10.0)  # Cap at 10
    
    def _determine_risk_level(self, score: float) -> str:
        """Determine risk level from score."""
        if score >= 7:
            return 'critical'
        elif score >= 5:
            return 'high'
        elif score >= 3:
            return 'medium'
        elif score >= 1:
            return 'low'
        else:
            return 'minimal'
    
    def _generate_recommendations(self, analysis: Dict) -> List[str]:
        """Generate security recommendations based on analysis."""
        recommendations = []
        
        risk_level = analysis.get('overall_risk_level', 'unknown')
        
        if risk_level in ['critical', 'high']:
            recommendations.append("⚠️ DO NOT CLICK this link - high security risk detected")
            recommendations.append("Block this URL and report as malicious")
            recommendations.append("Warn other users about this threat")
        elif risk_level == 'medium':
            recommendations.append("⚠️ Exercise caution with this link")
            recommendations.append("Verify the source before clicking")
            recommendations.append("Consider using URL scanning services")
        elif risk_level == 'low':
            recommendations.append("Use standard web security practices")
            recommendations.append("Verify the website's legitimacy if unsure")
        else:
            recommendations.append("✅ URL appears to be safe")
            recommendations.append("Follow standard security practices")
        
        # Add specific recommendations based on flags
        structure = analysis.get('structure_analysis', {})
        flags = structure.get('flags', [])
        
        if 'url_shortener' in flags:
            recommendations.append("URL shortener detected - expand URL to see final destination")
        
        if 'ip_address_domain' in flags:
            recommendations.append("IP address used instead of domain - potentially suspicious")
        
        phishing = analysis.get('phishing_check', {})
        if phishing.get('risk_level') == 'high':
            recommendations.append("Phishing indicators detected - verify sender authenticity")
        
        return recommendations
    
    def analyze_email_urls(self, email_content: str) -> Dict:
        """Analyze all URLs found in email content."""
        urls = self.extract_urls_from_text(email_content)
        
        if not urls:
            return {
                'urls_found': 0,
                'analyses': [],
                'highest_risk_level': 'none',
                'summary': 'No URLs found in email content'
            }
        
        analyses = []
        risk_scores = []
        
        for url in urls:
            analysis = self.comprehensive_analysis(url, email_content)
            analyses.append(analysis)
            risk_scores.append(analysis.get('overall_risk_score', 0))
        
        # Calculate summary statistics
        max_risk_score = max(risk_scores) if risk_scores else 0
        avg_risk_score = sum(risk_scores) / len(risk_scores) if risk_scores else 0
        
        # Determine highest risk level
        highest_risk_level = 'minimal'
        for analysis in analyses:
            current_level = analysis.get('overall_risk_level', 'minimal')
            level_priority = {'critical': 5, 'high': 4, 'medium': 3, 'low': 2, 'minimal': 1}
            
            if level_priority.get(current_level, 1) > level_priority.get(highest_risk_level, 1):
                highest_risk_level = current_level
        
        # Generate summary
        high_risk_count = sum(1 for a in analyses if a.get('overall_risk_level') in ['critical', 'high'])
        summary = f"Found {len(urls)} URLs. {high_risk_count} high-risk URLs detected." if high_risk_count > 0 else f"Found {len(urls)} URLs. No high-risk URLs detected."
        
        return {
            'urls_found': len(urls),
            'analyses': analyses,
            'max_risk_score': max_risk_score,
            'average_risk_score': avg_risk_score,
            'highest_risk_level': highest_risk_level,
            'high_risk_urls': [a for a in analyses if a.get('overall_risk_level') in ['critical', 'high']],
            'summary': summary
        }

if __name__ == "__main__":
    analyzer = URLAnalyzer()
    
    test_urls = [
        "https://google.com",
        "https://bit.ly/suspicious",
        "http://phishing-example.tk",
        "https://paypal-security.com/verify",
    ]
    
    for url in test_urls:
        print(f"\nAnalyzing: {url}")
        result = analyzer.comprehensive_analysis(url)
        print(f"Risk Level: {result['overall_risk_level']}")
        print(f"Risk Score: {result['overall_risk_score']:.2f}")
        print("Recommendations:")
        for rec in result['recommendations']:
            print(f"  - {rec}")
        print("-" * 60)
