"""
Email management with spam detection
"""
import imaplib
import email
import smtplib
import logging
import time
import re
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Tuple
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.header import decode_header
import json
import sqlite3
from pathlib import Path
import asyncio
import concurrent.futures
from dataclasses import dataclass
import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from config.settings import EMAIL_CONFIG, DATABASE_CONFIG, LOGS_DIR
from src.spam_detector import SpamDetector
from src.url_analyzer import URLAnalyzer

logger = logging.getLogger(__name__)

@dataclass
class EmailData:
    """Data class for email information."""
    uid: str
    sender: str
    subject: str
    content: str
    received_date: datetime
    has_unsubscribe: bool
    spam_score: float
    confidence: float
    urls: List[str]
    url_analysis: Dict

@dataclass
class ProcessingStats:
    """Statistics for email processing session."""
    total_processed: int = 0
    spam_detected: int = 0
    unsubscribe_attempts: int = 0
    successful_unsubscribes: int = 0
    failed_unsubscribes: int = 0
    errors: int = 0
    processing_time: float = 0.0
    
class EmailManager:
    """
    Comprehensive email management system with spam detection and unsubscription.
    """
    
    def __init__(self, imap_server: str = None, smtp_server: str = None, 
                 username: str = None, password: str = None):
        self.imap_server = imap_server
        self.smtp_server = smtp_server
        self.username = username
        self.password = password
        
        self.spam_detector = SpamDetector()
        self.url_analyzer = URLAnalyzer()
        
        self.imap_connection = None
        self.smtp_connection = None
        
        self.db_path = LOGS_DIR / "email_processing.db"
        self._init_database()
        
        self.batch_size = EMAIL_CONFIG['batch_size']
        self.max_retries = EMAIL_CONFIG['max_retries']
        self.processing_timeout = EMAIL_CONFIG['timeout']
        
        logger.info("Email Manager initialized for batch processing")
    
    def _init_database(self):
        """Initialize SQLite database for tracking processed emails."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS processed_emails (
                        uid TEXT PRIMARY KEY,
                        sender TEXT,
                        subject TEXT,
                        processed_date DATETIME,
                        is_spam BOOLEAN,
                        spam_confidence REAL,
                        unsubscribe_attempted BOOLEAN,
                        unsubscribe_successful BOOLEAN,
                        url_count INTEGER,
                        high_risk_urls INTEGER
                    )
                ''')
                
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS unsubscribe_attempts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        email_uid TEXT,
                        sender TEXT,
                        unsubscribe_url TEXT,
                        attempt_date DATETIME,
                        success BOOLEAN,
                        error_message TEXT,
                        FOREIGN KEY (email_uid) REFERENCES processed_emails (uid)
                    )
                ''')
                
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS processing_sessions (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        session_date DATETIME,
                        total_processed INTEGER,
                        spam_detected INTEGER,
                        unsubscribe_attempts INTEGER,
                        successful_unsubscribes INTEGER,
                        processing_time REAL
                    )
                ''')
                
                conn.commit()
                logger.info("Database initialized successfully")
                
        except Exception as e:
            logger.error(f"Failed to initialize database: {e}")
    
    def connect_imap(self) -> bool:
        """Connect to IMAP server."""
        try:
            self.imap_connection = imaplib.IMAP4_SSL(self.imap_server)
            self.imap_connection.login(self.username, self.password)
            self.imap_connection.select('INBOX')
            logger.info("IMAP connection established")
            return True
        except Exception as e:
            logger.error(f"Failed to connect to IMAP: {e}")
            return False
    
    def connect_smtp(self) -> bool:
        """Connect to SMTP server."""
        try:
            self.smtp_connection = smtplib.SMTP_SSL(self.smtp_server)
            self.smtp_connection.login(self.username, self.password)
            logger.info("SMTP connection established")
            return True
        except Exception as e:
            logger.error(f"Failed to connect to SMTP: {e}")
            return False
    
    def disconnect(self):
        """Disconnect from email servers."""
        if self.imap_connection:
            try:
                self.imap_connection.close()
                self.imap_connection.logout()
            except:
                pass
        
        if self.smtp_connection:
            try:
                self.smtp_connection.quit()
            except:
                pass
        
        logger.info("Email connections closed")
    
    def get_email_batch(self, batch_size: int = None, days_back: int = 7) -> List[str]:
        """Get a batch of email UIDs for processing."""
        if batch_size is None:
            batch_size = self.batch_size
        
        try:
            # Search for emails from the last few days
            since_date = (datetime.now() - timedelta(days=days_back)).strftime("%d-%b-%Y")
            
            # Search for emails (you can modify criteria as needed)
            search_criteria = f'(SINCE "{since_date}")'
            
            status, email_ids = self.imap_connection.search(None, search_criteria)
            
            if status != 'OK':
                logger.error("Failed to search emails")
                return []
            
            email_list = email_ids[0].split()
            
            # Limit to batch size
            if len(email_list) > batch_size:
                email_list = email_list[-batch_size:]  # Get most recent emails
            
            logger.info(f"Retrieved {len(email_list)} emails for processing")
            return [uid.decode() for uid in email_list]
            
        except Exception as e:
            logger.error(f"Error getting email batch: {e}")
            return []
    
    def fetch_email_data(self, uid: str) -> Optional[EmailData]:
        """Fetch and parse email data."""
        try:
            status, email_data = self.imap_connection.fetch(uid, '(RFC822)')
            
            if status != 'OK':
                logger.error(f"Failed to fetch email {uid}")
                return None
            
            raw_email = email_data[0][1]
            email_message = email.message_from_bytes(raw_email)
            
            sender = self._decode_header(email_message['From'])
            subject = self._decode_header(email_message['Subject'])
            date_header = email_message['Date']
            
            try:
                received_date = email.utils.parsedate_to_datetime(date_header)
            except:
                received_date = datetime.now()
            
            content = self._extract_email_content(email_message)
            
            has_unsubscribe = self._has_unsubscribe_link(content, email_message)
            
            urls = self.url_analyzer.extract_urls_from_text(content)
            
            url_analysis = self.url_analyzer.analyze_email_urls(content) if urls else {}
            
            prediction, confidence = self.spam_detector.predict(content)
            spam_score = prediction if prediction is not None else 0
            
            return EmailData(
                uid=uid,
                sender=sender,
                subject=subject,
                content=content,
                received_date=received_date,
                has_unsubscribe=has_unsubscribe,
                spam_score=spam_score,
                confidence=confidence,
                urls=urls,
                url_analysis=url_analysis
            )
            
        except Exception as e:
            logger.error(f"Error fetching email {uid}: {e}")
            return None
    
    def _decode_header(self, header: str) -> str:
        """Decode email header."""
        if not header:
            return ""
        
        try:
            decoded_parts = decode_header(header)
            decoded_header = ""
            
            for part, encoding in decoded_parts:
                if isinstance(part, bytes):
                    if encoding:
                        decoded_header += part.decode(encoding)
                    else:
                        decoded_header += part.decode('utf-8', errors='ignore')
                else:
                    decoded_header += part
            
            return decoded_header
        except Exception as e:
            logger.warning(f"Failed to decode header: {e}")
            return str(header)
    
    def _extract_email_content(self, email_message) -> str:
        """Extract text content from email."""
        content = ""
        
        try:
            if email_message.is_multipart():
                for part in email_message.walk():
                    content_type = part.get_content_type()
                    content_disposition = str(part.get("Content-Disposition"))
                    
                    if content_type == "text/plain" and "attachment" not in content_disposition:
                        payload = part.get_payload(decode=True)
                        if payload:
                            content += payload.decode('utf-8', errors='ignore') + "\n"
                    elif content_type == "text/html" and "attachment" not in content_disposition:
                        payload = part.get_payload(decode=True)
                        if payload:
                            # Simple HTML to text conversion
                            html_content = payload.decode('utf-8', errors='ignore')
                            text_content = re.sub(r'<[^>]+>', '', html_content)
                            content += text_content + "\n"
            else:
                payload = email_message.get_payload(decode=True)
                if payload:
                    content = payload.decode('utf-8', errors='ignore')
        
        except Exception as e:
            logger.warning(f"Error extracting email content: {e}")
        
        return content.strip()
    
    def _has_unsubscribe_link(self, content: str, email_message) -> bool:
        """Check if email has unsubscribe mechanism."""
        # Check List-Unsubscribe header
        if email_message.get('List-Unsubscribe'):
            return True
        
        # Check content for unsubscribe patterns
        unsubscribe_patterns = [
            r'unsubscribe',
            r'opt[\s-]?out',
            r'remove[\s-]?me',
            r'stop[\s-]?emails?',
            r'email[\s-]?preferences',
            r'manage[\s-]?subscription'
        ]
        
        content_lower = content.lower()
        return any(re.search(pattern, content_lower) for pattern in unsubscribe_patterns)
    
    def extract_unsubscribe_urls(self, content: str, email_message) -> List[str]:
        """Extract unsubscribe URLs from email."""
        unsubscribe_urls = []
        
        # Check List-Unsubscribe header
        list_unsubscribe = email_message.get('List-Unsubscribe')
        if list_unsubscribe:
            # Extract URLs from header
            url_matches = re.findall(r'<(https?://[^>]+)>', list_unsubscribe)
            unsubscribe_urls.extend(url_matches)
        
        # Extract from content
        all_urls = self.url_analyzer.extract_urls_from_text(content)
        
        # Filter for unsubscribe-related URLs
        unsubscribe_keywords = ['unsubscribe', 'opt-out', 'remove', 'stop', 'preferences']
        
        for url in all_urls:
            url_lower = url.lower()
            if any(keyword in url_lower for keyword in unsubscribe_keywords):
                unsubscribe_urls.append(url)
        
        return list(set(unsubscribe_urls))  # Remove duplicates
    
    def attempt_unsubscribe(self, email_data: EmailData) -> Tuple[bool, str]:
        """Attempt to unsubscribe from email sender."""
        if not email_data.has_unsubscribe:
            return False, "No unsubscribe mechanism found"
        
        try:
            # Get unsubscribe URLs
            unsubscribe_urls = self.extract_unsubscribe_urls(
                email_data.content, 
                None  # Would need to pass email message object for header
            )
            
            if not unsubscribe_urls:
                return False, "No unsubscribe URLs found"
            
            # Try each unsubscribe URL
            for url in unsubscribe_urls:
                try:
                    # Analyze URL safety first
                    url_analysis = self.url_analyzer.comprehensive_analysis(url)
                    
                    if url_analysis.get('overall_risk_level') in ['critical', 'high']:
                        logger.warning(f"Skipping high-risk unsubscribe URL: {url}")
                        continue
                    
                    # Make unsubscribe request
                    response = self.url_analyzer.session.get(
                        url, 
                        timeout=self.processing_timeout,
                        allow_redirects=True
                    )
                    
                    if response.status_code == 200:
                        # Log successful attempt
                        self._log_unsubscribe_attempt(
                            email_data.uid, email_data.sender, url, True, None
                        )
                        logger.info(f"Successfully unsubscribed from {email_data.sender}")
                        return True, f"Unsubscribed via {url}"
                    
                except Exception as url_error:
                    logger.warning(f"Failed to access unsubscribe URL {url}: {url_error}")
                    self._log_unsubscribe_attempt(
                        email_data.uid, email_data.sender, url, False, str(url_error)
                    )
                    continue
            
            return False, "All unsubscribe attempts failed"
            
        except Exception as e:
            error_msg = f"Unsubscribe attempt failed: {e}"
            logger.error(error_msg)
            return False, error_msg
    
    def _log_unsubscribe_attempt(self, email_uid: str, sender: str, url: str, 
                                success: bool, error_message: str):
        """Log unsubscribe attempt to database."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO unsubscribe_attempts 
                    (email_uid, sender, unsubscribe_url, attempt_date, success, error_message)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (email_uid, sender, url, datetime.now(), success, error_message))
                conn.commit()
        except Exception as e:
            logger.error(f"Failed to log unsubscribe attempt: {e}")
    
    def process_email_batch(self, days_back: int = 7, 
                           auto_unsubscribe: bool = True) -> ProcessingStats:
        """Process a batch of emails with spam detection and unsubscription."""
        stats = ProcessingStats()
        start_time = time.time()
        
        try:
            # Connect to email server
            if not self.connect_imap():
                logger.error("Failed to connect to IMAP server")
                return stats
            
            # Get email batch
            email_uids = self.get_email_batch(days_back=days_back)
            stats.total_processed = len(email_uids)
            
            if not email_uids:
                logger.info("No emails to process")
                return stats
            
            logger.info(f"Processing {len(email_uids)} emails...")
            
            # Process emails
            for i, uid in enumerate(email_uids, 1):
                try:
                    logger.debug(f"Processing email {i}/{len(email_uids)} (UID: {uid})")
                    
                    # Check if already processed
                    if self._is_email_processed(uid):
                        logger.debug(f"Email {uid} already processed, skipping")
                        continue
                    
                    # Fetch and analyze email
                    email_data = self.fetch_email_data(uid)
                    if not email_data:
                        stats.errors += 1
                        continue
                    
                    # Check if spam
                    is_spam = self.spam_detector.is_spam(email_data.content)
                    if is_spam:
                        stats.spam_detected += 1
                        logger.info(f"Spam detected from {email_data.sender}")
                    
                    # Attempt unsubscribe for spam emails
                    unsubscribe_success = False
                    if is_spam and auto_unsubscribe and email_data.has_unsubscribe:
                        stats.unsubscribe_attempts += 1
                        success, message = self.attempt_unsubscribe(email_data)
                        if success:
                            stats.successful_unsubscribes += 1
                            unsubscribe_success = True
                        else:
                            stats.failed_unsubscribes += 1
                        
                        logger.info(f"Unsubscribe result for {email_data.sender}: {message}")
                    
                    # Log to database
                    self._log_processed_email(email_data, is_spam, unsubscribe_success)
                    
                    # Rate limiting
                    time.sleep(0.1)  # Small delay between emails
                    
                except Exception as email_error:
                    logger.error(f"Error processing email {uid}: {email_error}")
                    stats.errors += 1
                    continue
            
            # Calculate processing time
            stats.processing_time = time.time() - start_time
            
            # Log session stats
            self._log_processing_session(stats)
            
            logger.info(f"Batch processing complete: {stats.total_processed} emails, "
                       f"{stats.spam_detected} spam, {stats.successful_unsubscribes} unsubscribed")
            
        except Exception as e:
            logger.error(f"Batch processing failed: {e}")
            stats.errors += 1
            stats.processing_time = time.time() - start_time
        
        finally:
            self.disconnect()
        
        return stats
    
    def _is_email_processed(self, uid: str) -> bool:
        """Check if email has already been processed."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT 1 FROM processed_emails WHERE uid = ?', (uid,))
                return cursor.fetchone() is not None
        except Exception as e:
            logger.error(f"Failed to check if email processed: {e}")
            return False
    
    def _log_processed_email(self, email_data: EmailData, is_spam: bool, 
                           unsubscribe_success: bool):
        """Log processed email to database."""
        try:
            high_risk_urls = len(email_data.url_analysis.get('high_risk_urls', []))
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT OR REPLACE INTO processed_emails 
                    (uid, sender, subject, processed_date, is_spam, spam_confidence,
                     unsubscribe_attempted, unsubscribe_successful, url_count, high_risk_urls)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    email_data.uid, email_data.sender, email_data.subject,
                    datetime.now(), is_spam, email_data.confidence,
                    email_data.has_unsubscribe, unsubscribe_success,
                    len(email_data.urls), high_risk_urls
                ))
                conn.commit()
        except Exception as e:
            logger.error(f"Failed to log processed email: {e}")
    
    def _log_processing_session(self, stats: ProcessingStats):
        """Log processing session statistics."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO processing_sessions 
                    (session_date, total_processed, spam_detected, unsubscribe_attempts,
                     successful_unsubscribes, processing_time)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    datetime.now(), stats.total_processed, stats.spam_detected,
                    stats.unsubscribe_attempts, stats.successful_unsubscribes,
                    stats.processing_time
                ))
                conn.commit()
        except Exception as e:
            logger.error(f"Failed to log processing session: {e}")
    
    def get_processing_stats(self, days: int = 30) -> Dict:
        """Get processing statistics for the last N days."""
        try:
            since_date = datetime.now() - timedelta(days=days)
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Overall stats
                cursor.execute('''
                    SELECT 
                        COUNT(*) as total_emails,
                        SUM(CASE WHEN is_spam THEN 1 ELSE 0 END) as spam_count,
                        SUM(CASE WHEN unsubscribe_successful THEN 1 ELSE 0 END) as unsubscribe_count,
                        AVG(spam_confidence) as avg_confidence,
                        SUM(high_risk_urls) as total_high_risk_urls
                    FROM processed_emails 
                    WHERE processed_date >= ?
                ''', (since_date,))
                
                overall_stats = cursor.fetchone()
                
                # Session stats
                cursor.execute('''
                    SELECT 
                        COUNT(*) as session_count,
                        SUM(total_processed) as total_processed,
                        AVG(processing_time) as avg_processing_time
                    FROM processing_sessions 
                    WHERE session_date >= ?
                ''', (since_date,))
                
                session_stats = cursor.fetchone()
                
                return {
                    'period_days': days,
                    'total_emails_processed': overall_stats[0] or 0,
                    'spam_detected': overall_stats[1] or 0,
                    'successful_unsubscribes': overall_stats[2] or 0,
                    'average_spam_confidence': overall_stats[3] or 0.0,
                    'high_risk_urls_found': overall_stats[4] or 0,
                    'processing_sessions': session_stats[0] or 0,
                    'average_processing_time': session_stats[2] or 0.0,
                    'spam_percentage': (overall_stats[1] / max(overall_stats[0], 1)) * 100,
                    'unsubscribe_success_rate': (overall_stats[2] / max(overall_stats[1], 1)) * 100 if overall_stats[1] else 0
                }
                
        except Exception as e:
            logger.error(f"Failed to get processing stats: {e}")
            return {}
    
    def run_continuous_monitoring(self, interval_hours: int = 1):
        """Run continuous email monitoring and processing."""
        logger.info(f"Starting continuous monitoring (checking every {interval_hours} hours)")
        
        while True:
            try:
                logger.info("Starting scheduled email processing...")
                stats = self.process_email_batch()
                
                logger.info(f"Scheduled processing complete. Processed: {stats.total_processed}, "
                           f"Spam: {stats.spam_detected}, Unsubscribed: {stats.successful_unsubscribes}")
                
                # Sleep until next check
                sleep_seconds = interval_hours * 3600
                logger.info(f"Sleeping for {interval_hours} hours...")
                time.sleep(sleep_seconds)
                
            except KeyboardInterrupt:
                logger.info("Continuous monitoring stopped by user")
                break
            except Exception as e:
                logger.error(f"Error in continuous monitoring: {e}")
                time.sleep(300)  # Sleep 5 minutes before retrying

# Example usage
if __name__ == "__main__":
    # Initialize email manager
    email_manager = EmailManager(
        imap_server="imap.gmail.com",
        smtp_server="smtp.gmail.com",
        username="your_email@gmail.com",
        password="your_app_password"
    )
    
    # Process email batch
    stats = email_manager.process_email_batch(days_back=7, auto_unsubscribe=True)
    
    print(f"Processing Results:")
    print(f"Total Processed: {stats.total_processed}")
    print(f"Spam Detected: {stats.spam_detected}")
    print(f"Unsubscribe Attempts: {stats.unsubscribe_attempts}")
    print(f"Successful Unsubscribes: {stats.successful_unsubscribes}")
    print(f"Processing Time: {stats.processing_time:.2f} seconds")
    
    # Get overall statistics
    overall_stats = email_manager.get_processing_stats(days=30)
    print(f"\n30-Day Statistics:")
    for key, value in overall_stats.items():
        print(f"{key}: {value}")
