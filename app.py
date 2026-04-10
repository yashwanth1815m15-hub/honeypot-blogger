import os
import time
from datetime import datetime
from functools import wraps
from flask import Flask, request, render_template, jsonify, redirect, session, url_for
from authlib.integrations.flask_client import OAuth
import requests
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv

# Load environment variables securely from .env
load_dotenv()

app = Flask(__name__)
# Crucial for securing the session cookies
app.secret_key = os.getenv('FLASK_SECRET', 'fallback_secret_key_for_dev')

# Configure SQLite Database
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'honeypot.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# --- Google OAuth Sandbox Configuration ---
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=os.getenv('GOOGLE_CLIENT_ID'),
    client_secret=os.getenv('GOOGLE_CLIENT_SECRET'),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid email profile' # Request access to verify identity
    }
)

# --- Database Models ---
class LogEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.String(50), nullable=False)
    ip_address = db.Column(db.String(50), nullable=False)
    location = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(100), nullable=False) # Stores OAuth email or Fake attempt
    password = db.Column(db.String(100), nullable=False, default='[REDACTED]')
    user_agent = db.Column(db.String(255), nullable=False)

    def to_dict(self):
        return {
            "timestamp": self.timestamp,
            "ip": self.ip_address,
            "location": self.location,
            "username": self.username,
            "password": self.password, # Will either be [REDACTED] or [GOOGLE_OAUTH]
            "user_agent": self.user_agent
        }

# --- Authentication Module ---
def requires_auth(f):
    """Protects routes by checking if an OAuth session exists"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user' not in session:
            # Not authenticated, redirect to root login
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated

# --- Helpers ---
def get_location(ip):
    if ip == '127.0.0.1' or ip == '::1':
        return "Localhost (Testing)"
    try:
        response = requests.get(f'http://ip-api.com/json/{ip}', timeout=2)
        if response.status_code == 200:
            data = response.json()
            if data['status'] == 'success':
                return f"{data.get('city', 'Unknown')}, {data.get('country', 'Unknown')}"
        return "Location Unavailable"
    except Exception as e:
        return f"Error Fetching Location: {str(e)}"

# --- Routes ---
@app.route('/', methods=['GET'])
def index():
    if 'user' in session:
        return redirect(url_for('view_logs'))
    return render_template('login.html')

# -- Google OAuth Flow --
@app.route('/google-login')
def google_login():
    """Trigger Google OAuth sequence"""
    redirect_uri = url_for('authorize', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/auth')
def authorize():
    """Callback route that Google hits after the user accepts the sign in"""
    try:
        token = google.authorize_access_token()
        user_info = token.get('userinfo')
        
        if user_info:
            session['user'] = user_info
            
            # Extract real IP from proxy chain
            ip = request.headers.get('X-Forwarded-For', request.remote_addr)
            if ip and ',' in ip:
                ip = ip.split(',')[0].strip()
                
            user_agent = request.headers.get('User-Agent', 'Unknown')
            location = get_location(ip)
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            # Log legitimate Google login
            new_log = LogEntry(
                timestamp=timestamp,
                ip_address=ip,
                location=location,
                username=user_info.get('email', 'Unknown OAuth User'),
                password="[GOOGLE_OAUTH_SSO]", # Explicitly mark as safe SSO token
                user_agent=user_agent
            )
            db.session.add(new_log)
            db.session.commit()

        return redirect(url_for('view_logs'))
    except Exception as e:
        print(f"OAuth Exception: {e}")
        return redirect(url_for('index', error="Authentication failed. Check your API credentials."))

# -- Honeypot Traditional Fallback Flow --
@app.route('/login', methods=['POST'])
def login():
    """Traditional login attempt handler (Safe Logging Honeypot)"""
    username = request.form.get('username', '')
    password = request.form.get('password', '[Blank]') # Capture real password
    
    # Extract real IP from proxy chain
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    if ip and ',' in ip:
        ip = ip.split(',')[0].strip()
        
    user_agent = request.headers.get('User-Agent', 'Unknown')
    
    # Simulate processing delay to mimic real database crypto hashing
    time.sleep(2)
    
    location = get_location(ip)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Insert safely into database
    new_log = LogEntry(
        timestamp=timestamp,
        ip_address=ip,
        location=location,
        username=f"[Attempt] {username}",
        password=password, # Log the real plaintext password
        user_agent=user_agent
    )
    db.session.add(new_log)
    db.session.commit()
    
    return jsonify({"error": "Invalid credentials. Please try again or use Single Sign-On."}), 401


# -- Dashboard -- 
@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('index'))

@app.route('/logs', methods=['GET'])
@requires_auth
def view_logs():
    return render_template('dashboard.html', user=session.get('user'))

@app.route('/api/logs', methods=['GET'])
@requires_auth
def api_logs():
    logs = LogEntry.query.order_by(LogEntry.id.desc()).all()
    return jsonify([log.to_dict() for log in logs])

# --- Initialize Database ---
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True, port=5001, host='0.0.0.0')
