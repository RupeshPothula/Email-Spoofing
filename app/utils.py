import pickle
import dns.resolver
from email.utils import parseaddr

def load_model(model_path):
    try:
        with open(model_path, 'rb') as file:
            model = pickle.load(file)
        return model
    except FileNotFoundError:
        class DummyModel:
            def predict(self, X):
                return [1 if any(features) else 0 for features in X]
        return DummyModel()

def check_spoof(headers):
    from_email = parseaddr(headers.get('From', ''))[1]
    reply_to_email = parseaddr(headers.get('Reply-To', ''))[1]
    return_path_email = parseaddr(headers.get('Return-Path', ''))[1]
    if from_email != reply_to_email and from_email != return_path_email:
        return True
    return False

def check_dmarc(domain):
    try:
        dmarc_record = f'_dmarc.{domain}'
        answers = dns.resolver.resolve(dmarc_record, 'TXT')
        for rdata in answers:
            if 'v=DMARC1' in str(rdata):
                return "Pass"
        return "Fail"
    except dns.resolver.NoAnswer:
        return "Fail"
    except dns.resolver.NXDOMAIN:
        return "Invalid Domain"
    except Exception as e:
        return f"Error: {str(e)}"

def predict_spoof_using_model(email_content, model):
    features = extract_features(email_content)
    return model.predict([features])[0]

def extract_features(email_content):
    suspicious_keywords = ['urgent', 'confirm', 'click here', 'account suspended', 'password reset']
    return [1 if keyword.lower() in email_content.lower() else 0 for keyword in suspicious_keywords]
