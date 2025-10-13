"""
UnsubSpamBot - Intelligent Email Management System
Main application orchestrator for automated spam detection and unsubscription management.

Features:
- Ensemble ML models (Naive Bayes, Random Forest, Logistic Regression)
- Comprehensive URL security analysis with VirusTotal integration
- Phishing detection and redirect chain analysis
- Batch processing of 100+ emails per run
- Automated unsubscription from spam senders
- MongoDB integration for data storage
- Real-time monitoring and statistics
"""

import argparse
import logging
import sys
import os
from pathlib import Path
import time
from datetime import datetime
import json

# Add project root directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import from parent directory
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from config.settings import LOGGING_CONFIG, EMAIL_CONFIG, DATABASE_CONFIG
from src.spam_detector import SpamDetector
from src.url_analyzer import URLAnalyzer
from src.email_manager import EmailManager, ProcessingStats
from src.lightweight_spam_detector import LightweightSpamDetector

# Configure logging
import logging.config
logging.config.dictConfig(LOGGING_CONFIG)
logger = logging.getLogger(__name__)

class UnsubSpamBot:
    """
    Main application class for the UnsubSpamBot system.
    Coordinates all components for intelligent email management.
    """
    
    def __init__(self, config_file: str = None):
        """Initialize the UnsubSpamBot system."""
        self.config = self._load_config(config_file)
        self.email_manager = None
        self.spam_detector = None
        self.url_analyzer = None
        
        logger.info("🚀 UnsubSpamBot - Intelligent Email Management System")
        logger.info("=" * 60)
        
        self._initialize_components()
    
    def _load_config(self, config_file: str = None) -> dict:
        """Load configuration from file or use environment variables."""
        config = {
            'email': {
                'imap_server': os.getenv('IMAP_SERVER', 'imap.gmail.com'),
                'smtp_server': os.getenv('SMTP_SERVER', 'smtp.gmail.com'),
                'username': os.getenv('EMAIL_USERNAME', ''),
                'password': os.getenv('EMAIL_PASSWORD', ''),
                'port_imap': int(os.getenv('IMAP_PORT', 993)),
                'port_smtp': int(os.getenv('SMTP_PORT', 465))
            },
            'processing': {
                'batch_size': EMAIL_CONFIG['batch_size'],
                'confidence_threshold': EMAIL_CONFIG['confidence_threshold'],
                'auto_unsubscribe': os.getenv('AUTO_UNSUBSCRIBE', 'true').lower() == 'true',
                'days_back': int(os.getenv('DAYS_BACK', 7)),
                'continuous_mode': os.getenv('CONTINUOUS_MODE', 'false').lower() == 'true',
                'check_interval_hours': int(os.getenv('CHECK_INTERVAL_HOURS', 1))
            },
            'features': {
                'use_ensemble_models': os.getenv('USE_ENSEMBLE', 'true').lower() == 'true',
                'url_analysis': os.getenv('URL_ANALYSIS', 'true').lower() == 'true',
                'virustotal_enabled': bool(os.getenv('VIRUSTOTAL_API_KEY', '')),
                'phishing_detection': os.getenv('PHISHING_DETECTION', 'true').lower() == 'true'
            }
        }
        
        if config_file and Path(config_file).exists():
            try:
                with open(config_file, 'r') as f:
                    file_config = json.load(f)
                    # Merge file config with default config
                    config.update(file_config)
                logger.info(f"Configuration loaded from {config_file}")
            except Exception as e:
                logger.warning(f"Failed to load config file: {e}, using defaults")
        
        return config
    
    def _initialize_components(self):
        """Initialize all system components."""
        try:
            # Initialize spam detector
            logger.info("📧 Initializing spam detection system...")
            self.spam_detector = SpamDetector()
            
            # Check if pre-trained model exists
            from config.settings import MODEL_PATHS
            if MODEL_PATHS['spam_classifier'].exists():
                logger.info("✅ Pre-trained spam model found and loaded")
            else:
                logger.warning("⚠️ No pre-trained model found, using fallback detection")
            
            # Initialize URL analyzer
            logger.info("🔗 Initializing URL security analyzer...")
            self.url_analyzer = URLAnalyzer()
            
            if self.config['features']['virustotal_enabled']:
                logger.info("✅ VirusTotal integration enabled")
            else:
                logger.warning("⚠️ VirusTotal API key not configured")
            
            # Initialize email manager
            logger.info("📨 Initializing email manager...")
            self.email_manager = EmailManager(
                imap_server=self.config['email']['imap_server'],
                smtp_server=self.config['email']['smtp_server'],
                username=self.config['email']['username'],
                password=self.config['email']['password']
            )
            
            logger.info("✅ All components initialized successfully")
            self._display_system_info()
            
        except Exception as e:
            logger.error(f"❌ Failed to initialize components: {e}")
            raise
    
    def _display_system_info(self):
        """Display system information and capabilities."""
        logger.info("\n" + "=" * 60)
        logger.info("📊 SYSTEM CAPABILITIES")
        logger.info("=" * 60)
        
        # ML capabilities
        ml_status = "✅ Ensemble ML Models" if self.spam_detector.ml_available else "⚠️ Lightweight Detection"
        logger.info(f"🧠 Spam Detection: {ml_status}")
        
        if self.spam_detector.ml_available:
            logger.info("   • Naive Bayes Classifier")
            logger.info("   • Random Forest Classifier") 
            logger.info("   • Logistic Regression")
            logger.info("   • Ensemble Voting System")
        
        # URL analysis capabilities
        logger.info("🔗 URL Security Analysis:")
        logger.info("   • Phishing Detection")
        logger.info("   • Redirect Chain Analysis")
        logger.info("   • Malicious Domain Detection")
        
        if self.config['features']['virustotal_enabled']:
            logger.info("   • VirusTotal Integration ✅")
        else:
            logger.info("   • VirusTotal Integration ❌")
        
        # Processing capabilities
        logger.info(f"⚡ Email Processing:")
        logger.info(f"   • Batch Size: {self.config['processing']['batch_size']} emails")
        logger.info(f"   • Confidence Threshold: {self.config['processing']['confidence_threshold']*100}%")
        logger.info(f"   • Auto-Unsubscribe: {'✅' if self.config['processing']['auto_unsubscribe'] else '❌'}")
        
        logger.info("=" * 60 + "\n")
    
    def process_emails(self, days_back: int = None, auto_unsubscribe: bool = None) -> ProcessingStats:
        """Process emails with spam detection and unsubscription."""
        if days_back is None:
            days_back = self.config['processing']['days_back']
        
        if auto_unsubscribe is None:
            auto_unsubscribe = self.config['processing']['auto_unsubscribe']
        
        logger.info(f"🔄 Starting email processing...")
        logger.info(f"   • Days back: {days_back}")
        logger.info(f"   • Auto-unsubscribe: {'✅' if auto_unsubscribe else '❌'}")
        
        start_time = time.time()
        
        try:
            # Validate email credentials
            if not self.config['email']['username'] or not self.config['email']['password']:
                logger.error("❌ Email credentials not configured")
                logger.info("💡 Set EMAIL_USERNAME and EMAIL_PASSWORD environment variables")
                return ProcessingStats()
            
            # Process emails
            stats = self.email_manager.process_email_batch(
                days_back=days_back,
                auto_unsubscribe=auto_unsubscribe
            )
            
            # Display results
            self._display_processing_results(stats)
            
            return stats
            
        except Exception as e:
            logger.error(f"❌ Email processing failed: {e}")
            return ProcessingStats()
    
    def _display_processing_results(self, stats: ProcessingStats):
        """Display processing results in a formatted way."""
        logger.info("\n" + "=" * 60)
        logger.info("📊 PROCESSING RESULTS")
        logger.info("=" * 60)
        
        logger.info(f"📧 Total Emails Processed: {stats.total_processed}")
        logger.info(f"🚫 Spam Detected: {stats.spam_detected}")
        
        if stats.total_processed > 0:
            spam_rate = (stats.spam_detected / stats.total_processed) * 100
            logger.info(f"📈 Spam Rate: {spam_rate:.1f}%")
        
        logger.info(f"🔄 Unsubscribe Attempts: {stats.unsubscribe_attempts}")
        logger.info(f"✅ Successful Unsubscribes: {stats.successful_unsubscribes}")
        logger.info(f"❌ Failed Unsubscribes: {stats.failed_unsubscribes}")
        
        if stats.unsubscribe_attempts > 0:
            success_rate = (stats.successful_unsubscribes / stats.unsubscribe_attempts) * 100
            logger.info(f"📈 Unsubscribe Success Rate: {success_rate:.1f}%")
        
        logger.info(f"⏱️ Processing Time: {stats.processing_time:.2f} seconds")
        
        if stats.errors > 0:
            logger.warning(f"⚠️ Errors: {stats.errors}")
        
        logger.info("=" * 60 + "\n")
    
    def analyze_url(self, url: str) -> dict:
        """Analyze a single URL for security threats."""
        logger.info(f"🔗 Analyzing URL: {url}")
        
        try:
            result = self.url_analyzer.comprehensive_analysis(url)
            
            logger.info(f"📊 Analysis Results:")
            logger.info(f"   • Risk Level: {result.get('overall_risk_level', 'unknown').upper()}")
            logger.info(f"   • Risk Score: {result.get('overall_risk_score', 0):.2f}/10")
            
            recommendations = result.get('recommendations', [])
            if recommendations:
                logger.info("💡 Recommendations:")
                for rec in recommendations[:3]:  # Show first 3 recommendations
                    logger.info(f"   • {rec}")
            
            return result
            
        except Exception as e:
            logger.error(f"❌ URL analysis failed: {e}")
            return {}
    
    def test_spam_detection(self, text: str) -> dict:
        """Test spam detection on provided text."""
        logger.info("🧠 Testing spam detection...")
        
        try:
            prediction, confidence = self.spam_detector.predict(text)
            is_spam = self.spam_detector.is_spam(text)
            
            result = {
                'text_preview': text[:100] + "..." if len(text) > 100 else text,
                'prediction': prediction,
                'confidence': confidence,
                'is_spam': is_spam,
                'threshold': EMAIL_CONFIG['confidence_threshold']
            }
            
            logger.info(f"📊 Detection Results:")
            logger.info(f"   • Prediction: {'SPAM' if prediction == 1 else 'HAM'}")
            logger.info(f"   • Confidence: {confidence:.2f}")
            logger.info(f"   • Above Threshold: {'✅' if is_spam else '❌'}")
            
            return result
            
        except Exception as e:
            logger.error(f"❌ Spam detection test failed: {e}")
            return {}
    
    def get_statistics(self, days: int = 30) -> dict:
        """Get processing statistics for the last N days."""
        logger.info(f"📊 Getting statistics for last {days} days...")
        
        try:
            stats = self.email_manager.get_processing_stats(days=days)
            
            if stats:
                logger.info(f"📈 Statistics Summary:")
                logger.info(f"   • Total Emails: {stats.get('total_emails_processed', 0)}")
                logger.info(f"   • Spam Detected: {stats.get('spam_detected', 0)}")
                logger.info(f"   • Successful Unsubscribes: {stats.get('successful_unsubscribes', 0)}")
                logger.info(f"   • Spam Rate: {stats.get('spam_percentage', 0):.1f}%")
                logger.info(f"   • Unsubscribe Success Rate: {stats.get('unsubscribe_success_rate', 0):.1f}%")
            else:
                logger.warning("⚠️ No statistics available")
            
            return stats
            
        except Exception as e:
            logger.error(f"❌ Failed to get statistics: {e}")
            return {}
    
    def run_continuous_monitoring(self):
        """Run continuous email monitoring."""
        interval_hours = self.config['processing']['check_interval_hours']
        
        logger.info(f"🔄 Starting continuous monitoring...")
        logger.info(f"   • Check interval: {interval_hours} hours")
        logger.info(f"   • Press Ctrl+C to stop")
        
        try:
            self.email_manager.run_continuous_monitoring(interval_hours=interval_hours)
        except KeyboardInterrupt:
            logger.info("🛑 Continuous monitoring stopped by user")
        except Exception as e:
            logger.error(f"❌ Continuous monitoring failed: {e}")
    
    def train_model(self, dataset_path: str) -> bool:
        """Train spam detection model with provided dataset."""
        logger.info(f"🧠 Training spam detection model...")
        logger.info(f"   • Dataset: {dataset_path}")
        
        if not Path(dataset_path).exists():
            logger.error(f"❌ Dataset file not found: {dataset_path}")
            return False
        
        try:
            success = self.spam_detector.train_model(dataset_path, model_type='ensemble')
            
            if success:
                logger.info("✅ Model training completed successfully")
            else:
                logger.error("❌ Model training failed")
            
            return success
            
        except Exception as e:
            logger.error(f"❌ Model training failed: {e}")
            return False

def create_parser():
    """Create command line argument parser."""
    parser = argparse.ArgumentParser(
        description="UnsubSpamBot - Intelligent Email Management System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s process                          # Process emails with default settings
  %(prog)s process --days 14 --no-unsub    # Process 14 days without unsubscribing
  %(prog)s analyze-url https://example.com # Analyze URL security
  %(prog)s test-spam "Your text here"       # Test spam detection
  %(prog)s stats --days 30                 # Get 30-day statistics
  %(prog)s monitor                         # Start continuous monitoring
  %(prog)s train data/spam_dataset.csv     # Train model with dataset
        """
    )
    
    # Subcommands
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Process emails command
    process_parser = subparsers.add_parser('process', help='Process emails')
    process_parser.add_argument('--days', type=int, default=7, 
                               help='Number of days back to process (default: 7)')
    process_parser.add_argument('--no-unsub', action='store_true',
                               help='Disable automatic unsubscription')
    process_parser.add_argument('--config', type=str,
                               help='Path to configuration file')
    
    # URL analysis command
    url_parser = subparsers.add_parser('analyze-url', help='Analyze URL security')
    url_parser.add_argument('url', help='URL to analyze')
    
    # Spam detection test command
    spam_parser = subparsers.add_parser('test-spam', help='Test spam detection')
    spam_parser.add_argument('text', help='Text to test for spam')
    
    # Statistics command
    stats_parser = subparsers.add_parser('stats', help='Get processing statistics')
    stats_parser.add_argument('--days', type=int, default=30,
                             help='Number of days for statistics (default: 30)')
    
    # Continuous monitoring command
    subparsers.add_parser('monitor', help='Start continuous monitoring')
    
    # Training command
    train_parser = subparsers.add_parser('train', help='Train spam detection model')
    train_parser.add_argument('dataset', help='Path to training dataset (CSV)')
    
    # Configuration command
    config_parser = subparsers.add_parser('config', help='Show configuration')
    
    return parser

def main():
    """Main application entry point."""
    parser = create_parser()
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    try:
        # Initialize the bot
        config_file = getattr(args, 'config', None)
        bot = UnsubSpamBot(config_file=config_file)
        
        # Execute command
        if args.command == 'process':
            auto_unsubscribe = not args.no_unsub
            bot.process_emails(days_back=args.days, auto_unsubscribe=auto_unsubscribe)
            
        elif args.command == 'analyze-url':
            bot.analyze_url(args.url)
            
        elif args.command == 'test-spam':
            bot.test_spam_detection(args.text)
            
        elif args.command == 'stats':
            bot.get_statistics(days=args.days)
            
        elif args.command == 'monitor':
            bot.run_continuous_monitoring()
            
        elif args.command == 'train':
            bot.train_model(args.dataset)
            
        elif args.command == 'config':
            logger.info("📋 Current Configuration:")
            logger.info(json.dumps(bot.config, indent=2))
    
    except KeyboardInterrupt:
        logger.info("🛑 Operation cancelled by user")
    except Exception as e:
        logger.error(f"❌ Application error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
