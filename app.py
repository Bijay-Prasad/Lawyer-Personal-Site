# Python standard libraries
import json
import os
import requests
from flask import Flask, render_template, request, redirect, url_for, flash, session, abort
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from functools import wraps
from oauthlib.oauth2 import WebApplicationClient
from flask_mail import Mail, Message
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Flask app setup
app = Flask(__name__)

# Configuration for Flask-Mail (Secure Credentials)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = os.getenv("MAIL_USERNAME")  # Use environment variable
app.config['MAIL_PASSWORD'] = os.getenv("MAIL_PASSWORD")  # Use environment variable
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
mail = Mail(app)

# Google OAuth Configuration (Secure Credentials)
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"

# Database Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///usersdata.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv("FLASK_SECRET_KEY")  # Secure with .env
db = SQLAlchemy(app)

# Flask-Login Configuration
login_manager = LoginManager()
login_manager.init_app(app)

# OAuth Client Setup
client = WebApplicationClient(GOOGLE_CLIENT_ID)

# User Model
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    profile_pic = db.Column(db.String(200), nullable=True)

# Initialize the database
with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def send_email(to, subject, template):
    msg = Message(subject, recipients=[to], html=template, sender=app.config['MAIL_USERNAME'])
    mail.send(msg)

def get_google_provider_cfg():
    return requests.get(GOOGLE_DISCOVERY_URL).json()

# ---------------- ROUTES ----------------

@app.route("/")
def index():
    return render_template('index.html', title="Consultancy Services", user=current_user)

@app.route("/register", methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        if User.query.filter_by(email=request.form.get('email')).first():
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for('login'))

        formPassword = request.form.get('password')
        hash_and_salted_password = generate_password_hash(formPassword, method='pbkdf2:sha256', salt_length=8)

        new_user = User(
            name=request.form.get('name'),
            email=request.form.get('email'),
            password=hash_and_salted_password
        )

        db.session.add(new_user)
        db.session.commit()
        
        # Send email confirmation
        html = render_template('register_mail.html', name=new_user.name, email=new_user.email, password=formPassword)
        send_email(new_user.email, "Successfully registered", html)

        login_user(new_user)
        flash("You have successfully registered. Please log in.")
        return redirect(url_for("login"))

    return render_template('register.html', title="Register", user=current_user)

@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        if not user:
            flash("That email does not exist. Please try again.")
            return redirect(url_for('login'))
        elif not check_password_hash(user.password, password):
            flash("Incorrect password. Please try again.")
            return redirect(url_for('login'))
        else:
            login_user(user)
            return redirect(url_for('home'))

    return render_template('login.html', title="Login", user=current_user)

# ---------------- GOOGLE AUTH ----------------

@app.route('/login/google')
def login_google():
    google_provider_cfg = get_google_provider_cfg()
    authorization_endpoint = google_provider_cfg["authorization_endpoint"]

    request_uri = client.prepare_request_uri(
        authorization_endpoint,
        redirect_uri=url_for('google_authorize', _external=True),  # ✅ Dynamic Redirect
        scope=["openid", "email", "profile"],
    )
    return redirect(request_uri)

@app.route('/login/google/callback')
def google_authorize():
    code = request.args.get("code")
    google_provider_cfg = get_google_provider_cfg()
    token_endpoint = google_provider_cfg["token_endpoint"]

    token_url, headers, body = client.prepare_token_request(
        token_endpoint,
        authorization_response=request.url,
        redirect_url=url_for('google_authorize', _external=True),  # ✅ Consistent Redirect
        code=code
    )
    token_response = requests.post(token_url, headers=headers, data=body, auth=(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET))
    client.parse_request_body_response(json.dumps(token_response.json()))

    # Get user info
    userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]
    uri, headers, body = client.add_token(userinfo_endpoint)
    userinfo_response = requests.get(uri, headers=headers, data=body)

    if userinfo_response.json().get("email_verified"):
        users_email = userinfo_response.json()["email"]
        users_name = userinfo_response.json()["name"]
        profile_pic = userinfo_response.json()["picture"]
    else:
        return "User email not available or not verified by Google.", 400

    user = User.query.filter_by(email=users_email).first()

    if not user:
        new_user = User(name=users_name, email=users_email, password=generate_password_hash(users_email, method='pbkdf2:sha256', salt_length=8), profile_pic=profile_pic)
        db.session.add(new_user)
        db.session.commit()

        # Send email confirmation
        html = render_template('register_google_mail.html', name=new_user.name, email=new_user.email)
        send_email(new_user.email, "Successfully registered", html)

        login_user(new_user)
        return redirect(url_for('home'))
    else:
        login_user(user)
        return redirect(url_for('home'))

@app.route("/home")
@login_required
def home():
    return render_template('home.html', title="Home", user=current_user)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# Admin-Only Decorator
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.id != 1:
            return abort(403)
        return f(*args, **kwargs)
    return decorated_function

@app.route('/admin')
@login_required
@admin_only
def admin():
    all_users = User.query.all()
    return render_template('admin.html', users=all_users)

# Run Flask App
if __name__ == "__main__":
    app.run(debug=False)
