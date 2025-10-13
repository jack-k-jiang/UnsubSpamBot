import re
import string
import logging
import sys
import os
from pathlib import Path

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

import pandas as pd
import numpy as np
from config.settings import MODEL_PATHS, DATA_DIR, SPAM_CONFIG, EMAIL_CONFIG

# Try ML libraries first, fall back if needed
try:
    from sklearn.model_selection import train_test_split
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.naive_bayes import MultinomialNB
    from sklearn.linear_model import LogisticRegression
    from sklearn.ensemble import RandomForestClassifier, VotingClassifier
    from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
    from sklearn.pipeline import Pipeline
    import joblib
    import nltk
    from nltk.corpus import stopwords
    from nltk.tokenize import word_tokenize
    from nltk.stem import PorterStemmer
    ML_AVAILABLE = True
    logger = logging.getLogger(__name__)
    logger.info("Full ML libraries available")
except ImportError as e:
    ML_AVAILABLE = False
    logger = logging.getLogger(__name__)
    logger.warning(f"ML libraries not available: {e}")
    logger.info("Falling back to lightweight detection")

# Import lightweight detector as fallback
try:
    from .lightweight_spam_detector import LightweightSpamDetector
except ImportError:
    try:
        from lightweight_spam_detector import LightweightSpamDetector
    except ImportError:
        logger.error("Lightweight spam detector not found")

class SpamDetector:
    """
    A comprehensive spam detection system using machine learning.
    Falls back to lightweight detection if ML libraries are not available.
    """
    
    def __init__(self):
        self.model = None
        self.ensemble_model = None
        self.vectorizer = None
        self.ml_available = ML_AVAILABLE
        self.individual_models = {}
        self.ensemble_weights = SPAM_CONFIG['ensemble_weights']
        
        if self.ml_available:
            try:
                self.stemmer = PorterStemmer()
                self.stop_words = set(stopwords.words('english'))
                
                # Try to load pre-trained model
                self.load_model()
                logger.info("ML-based spam detector initialized")
            except:
                logger.warning("NLTK data not available, downloading...")
                try:
                    import nltk
                    nltk.download('stopwords', quiet=True)
                    nltk.download('punkt', quiet=True)
                    self.stemmer = PorterStemmer()
                    self.stop_words = set(stopwords.words('english'))
                    
                    # Try to load pre-trained model
                    self.load_model()
                    logger.info("ML-based spam detector initialized with downloaded NLTK data")
                except:
                    logger.error("Failed to download NLTK data, using lightweight detector")
                    self.ml_available = False
        
        # Initialize fallback detector
        if not self.ml_available or self.model is None:
            self.lightweight_detector = LightweightSpamDetector()
            logger.info("Using lightweight spam detector")
    
    def create_ensemble_model(self):
        """
        Create an ensemble model combining Naive Bayes, Random Forest, and Logistic Regression.
        """
        if not self.ml_available:
            return None
            
        # Individual models
        nb_model = MultinomialNB(alpha=1.0)
        rf_model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
        lr_model = LogisticRegression(random_state=42, max_iter=1000)
        
        ensemble = VotingClassifier(
            estimators=[
                ('naive_bayes', nb_model),
                ('random_forest', rf_model),
                ('logistic_regression', lr_model)
            ],
            voting='soft'  # Use probability predictions
        )
        
        return ensemble
    
    def get_weighted_prediction(self, text):
        """
        Get weighted prediction from individual models if ensemble is not available.
        """
        if not self.individual_models:
            return self.predict(text)
            
        predictions = {}
        confidences = {}
        
        for model_name, model in self.individual_models.items():
            try:
                processed_text = self.preprocess_text(text)
                text_tfidf = self.vectorizer.transform([processed_text])
                
                pred_proba = model.predict_proba(text_tfidf)[0]
                predictions[model_name] = np.argmax(pred_proba)
                confidences[model_name] = np.max(pred_proba)
            except Exception as e:
                logger.warning(f"Error in {model_name} prediction: {e}")
                continue
        
        if not predictions:
            return None, 0.0
            
        # Calculate weighted average
        weighted_confidence = 0.0
        weighted_prediction = 0.0
        total_weight = 0.0
        
        for model_name, pred in predictions.items():
            weight = self.ensemble_weights.get(model_name, 1.0)
            confidence = confidences[model_name]
            
            weighted_prediction += pred * weight * confidence
            weighted_confidence += confidence * weight
            total_weight += weight
        
        if total_weight > 0:
            final_prediction = 1 if weighted_prediction / total_weight > 0.5 else 0
            final_confidence = weighted_confidence / total_weight
            return final_prediction, final_confidence
        
        return None, 0.0
        
    def preprocess_text(self, text):
        """
        Preprocess email text for machine learning.
        """
        if not self.ml_available:
            return text  # Lightweight detector handles its own preprocessing
            
        if not isinstance(text, str):
            return ""
            
        text = text.lower()
        
        # Remove HTML tags
        text = re.sub(r'<[^>]+>', '', text)
        
        text = re.sub(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', '', text)
        
        # Remove email addresses
        text = re.sub(r'\S+@\S+', '', text)
        
        text = text.translate(str.maketrans('', '', string.punctuation))
        
        text = re.sub(r'\d+', '', text)
        
        # Tokenize
        try:
            tokens = word_tokenize(text)
            
            # Remove stopwords and stem
            tokens = [self.stemmer.stem(token) for token in tokens if token not in self.stop_words]
            
            return ' '.join(tokens)
        except:
            # Fallback if NLTK fails
            return ' '.join(text.split())
    
    def load_dataset(self, file_path):
        """
        Load and preprocess the spam dataset.
        Expected format: CSV with 'text' and 'label' columns
        """
        try:
            df = pd.read_csv(file_path)
            
            # Assuming the CSV has columns like 'v1' (label) and 'v2' (text) from common spam datasets
            if 'v1' in df.columns and 'v2' in df.columns:
                df = df.rename(columns={'v1': 'label', 'v2': 'text'})
            
            # Convert labels to binary (0 for ham, 1 for spam)
            df['label'] = df['label'].map({'ham': 0, 'spam': 1})
            
            # Remove any rows with missing values
            df = df.dropna()
            
            logger.info(f"Loaded dataset with {len(df)} samples")
            logger.info(f"Spam ratio: {df['label'].mean():.2%}")
            
            return df
            
        except Exception as e:
            logger.error(f"Error loading dataset: {e}")
            return None
    
    def train_model(self, dataset_path, model_type='ensemble'):
        """
        Train the spam detection model with ensemble approach.
        """
        if not self.ml_available:
            logger.warning("ML libraries not available, cannot train model")
            return False
            
        try:
            # Load dataset
            df = self.load_dataset(dataset_path)
            if df is None:
                return False
            
            # Preprocess text
            logger.info("Preprocessing text data...")
            df['processed_text'] = df['text'].apply(self.preprocess_text)
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                df['processed_text'], df['label'], 
                test_size=0.2, random_state=42, stratify=df['label']
            )
            
            # Create TF-IDF vectorizer
            self.vectorizer = TfidfVectorizer(
                max_features=5000,
                ngram_range=(1, 2),
                min_df=2,
                max_df=0.95
            )
            
            # Fit vectorizer and transform training data
            X_train_tfidf = self.vectorizer.fit_transform(X_train)
            X_test_tfidf = self.vectorizer.transform(X_test)
            
            if model_type == 'ensemble':
                # Train ensemble model
                logger.info("Training ensemble model with Naive Bayes, Random Forest, and Logistic Regression...")
                self.ensemble_model = self.create_ensemble_model()
                self.ensemble_model.fit(X_train_tfidf, y_train)
                self.model = self.ensemble_model
                
                # Also train individual models for weighted prediction fallback
                models = {
                    'naive_bayes': MultinomialNB(alpha=0.1),
                    'random_forest': RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1),
                    'logistic_regression': LogisticRegression(random_state=42, max_iter=1000)
                }
                
                for name, model in models.items():
                    logger.info(f"Training individual {name} model...")
                    model.fit(X_train_tfidf, y_train)
                    self.individual_models[name] = model
                    
            else:
                # Train single model
                if model_type == 'naive_bayes':
                    self.model = MultinomialNB(alpha=0.1)
                elif model_type == 'logistic_regression':
                    self.model = LogisticRegression(random_state=42, max_iter=1000)
                elif model_type == 'random_forest':
                    self.model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
                
                logger.info(f"Training {model_type} model...")
                self.model.fit(X_train_tfidf, y_train)
            
            # Evaluate model
            y_pred = self.model.predict(X_test_tfidf)
            accuracy = accuracy_score(y_test, y_pred)
            
            logger.info(f"Model trained successfully!")
            logger.info(f"Accuracy: {accuracy:.4f}")
            logger.info("\nClassification Report:")
            logger.info(classification_report(y_test, y_pred))
            logger.info("\nConfusion Matrix:")
            logger.info(confusion_matrix(y_test, y_pred))
            
            # Save model
            self.save_model()
            return True
            
        except Exception as e:
            logger.error(f"Error training model: {e}")
            return False
    
    def save_model(self):
        """
        Save the trained model, vectorizer, and individual models.
        """
        if not self.ml_available:
            logger.warning("ML libraries not available, cannot save model")
            return
            
        try:
            # Save main model (ensemble or single)
            joblib.dump(self.model, MODEL_PATHS['spam_classifier'])
            
            # Save vectorizer
            if self.vectorizer:
                joblib.dump(self.vectorizer, MODEL_PATHS['vectorizer'])
            
            # Save individual models if they exist
            if self.individual_models:
                joblib.dump(self.individual_models, MODEL_PATHS['ensemble_models'])
            
            logger.info("Model components saved successfully")
        except Exception as e:
            logger.error(f"Error saving model: {e}")
    
    def load_model(self):
        """
        Load the trained model, vectorizer, and individual models.
        """
        if not self.ml_available:
            logger.info("ML libraries not available, using lightweight detector")
            return True  # Lightweight detector doesn't need to load models
            
        try:
            # Check if main model exists
            if MODEL_PATHS['spam_classifier'].exists():
                self.model = joblib.load(MODEL_PATHS['spam_classifier'])
                logger.info("Main model loaded successfully")
            else:
                logger.warning("No pre-trained model found")
                return False
            
            # Load vectorizer
            if MODEL_PATHS['vectorizer'].exists():
                self.vectorizer = joblib.load(MODEL_PATHS['vectorizer'])
                logger.info("Vectorizer loaded successfully")
            
            # Load individual models if they exist
            if MODEL_PATHS['ensemble_models'].exists():
                self.individual_models = joblib.load(MODEL_PATHS['ensemble_models'])
                logger.info("Individual ensemble models loaded successfully")
            
            return True
        except Exception as e:
            logger.warning(f"Could not load ML model: {e}")
            logger.info("Falling back to lightweight detector")
            self.ml_available = False
            self.lightweight_detector = LightweightSpamDetector()
            return True
    
    def predict(self, text):
        """
        Predict if a text is spam or not using ensemble approach when available.
        Returns: (prediction, confidence)
        """
        if not self.ml_available:
            result = self.lightweight_detector.is_spam(text)
            return (1 if result['is_spam'] else 0, result['confidence'])
            
        if self.model is None or self.vectorizer is None:
            if not self.load_model():
                # Fall back to lightweight detector if model loading fails
                result = self.lightweight_detector.is_spam(text)
                return (1 if result['is_spam'] else 0, result['confidence'])
        
        try:
            # Preprocess text
            processed_text = self.preprocess_text(text)
            
            # Vectorize
            text_tfidf = self.vectorizer.transform([processed_text])
            
            # Use ensemble prediction if available, otherwise use main model
            if self.individual_models and len(self.individual_models) > 1:
                # Use weighted ensemble prediction
                weighted_prediction, weighted_confidence = self.get_weighted_prediction(text)
                if weighted_prediction is not None:
                    return weighted_prediction, weighted_confidence
            
            # Fallback to main model prediction
            prediction = self.model.predict(text_tfidf)[0]
            
            # Get confidence from probability prediction
            if hasattr(self.model, 'predict_proba'):
                proba = self.model.predict_proba(text_tfidf)[0]
                confidence = np.max(proba)
            else:
                # For models without predict_proba, use decision function if available
                if hasattr(self.model, 'decision_function'):
                    decision = self.model.decision_function(text_tfidf)[0]
                    confidence = abs(decision) / (abs(decision) + 1)  # Normalize to [0,1]
                else:
                    confidence = 0.5  # Default confidence
            
            return prediction, confidence
            
        except Exception as e:
            logger.error(f"Error making ML prediction: {e}")
            logger.info("Falling back to lightweight detector")
            result = self.lightweight_detector.is_spam(text)
            return (1 if result['is_spam'] else 0, result['confidence'])
    
    def is_spam(self, text, threshold=None):
        """
        Check if text is spam with confidence threshold.
        Uses configuration threshold if none provided.
        """
        if threshold is None:
            threshold = EMAIL_CONFIG['confidence_threshold']
            
        prediction, confidence = self.predict(text)
        
        if prediction is None:
            return False
        
        return prediction == 1 and confidence >= threshold

if __name__ == "__main__":
    nltk.download('stopwords', quiet=True)
    nltk.download('punkt', quiet=True)
    
    detector = SpamDetector()
    
    # Example predictions
    test_emails = [
        "Congratulations! You've won $1,000,000! Click here to claim now!",
        "Hi, this is a reminder about our meeting tomorrow at 3pm.",
        "URGENT: Your account will be closed! Act now to prevent suspension!",
        "Thank you for your recent purchase. Your order has been shipped."
    ]
    
    for email in test_emails:
        is_spam = detector.is_spam(email)
        prediction, confidence = detector.predict(email)
        print(f"Email: {email[:50]}...")
        print(f"Spam: {is_spam}, Confidence: {confidence:.2f}\n")
