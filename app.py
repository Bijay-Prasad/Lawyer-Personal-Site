# Python standard libraries
import json
import os
from flask_sqlalchemy import SQLAlchemy

# Third-party libraries
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from functools import wraps
from flask import abort
from oauthlib.oauth2 import WebApplicationClient
import requests
from flask_mail import Mail, Message
from dotenv import load_dotenv


load_dotenv()
# Configuration

GOOGLE_CLIENT_ID = '155242781760-8fct15otl4cepmmje6adsplkgssku21u.apps.googleusercontent.com'
GOOGLE_CLIENT_SECRET = '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'
GOOGLE_DISCOVERY_URL = (
    "https://accounts.google.com/.well-known/openid-configuration"
)

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'


# Flask app setup
app = Flask(__name__)





# configuration of mail
app.config['MAIL_SERVER']='smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'indradipchakraborty12'
app.config['MAIL_PASSWORD'] = 'ejeexljnkqfwnxtx'
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
app.config['DEBUG']=True
app.config['MAIL_SUPPERS_SEND']=False
app.config['TESTING']= False
mail = Mail(app)

def send_email(to, subject, template):
    msg = Message(
        subject,
        recipients=[to],
        html=template,
        sender='indradipchakraborty12@gmail.com'
    )
    # msg.body = 'Hello, This is a testing Mail'
    mail.send(msg)


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///usersdata.db'
app.config['SECRET_KEY'] = 'saredevelopersbhaihai404'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = '0df660dd7e2503a4e4ddbc2b0768e1c2749fb5d96cf38d0ef95f6a38b4615260'



db = SQLAlchemy(app)


login_manager = LoginManager()
login_manager.init_app(app)


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=False, nullable=False)
    email = db.Column(db.String(50), unique=False, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    profile_pic = db.Column(db.String(200), nullable=True)
# db.create_all()

# OAuth 2 client setup
client = WebApplicationClient(GOOGLE_CLIENT_ID)


# Flask-Login helper to retrieve a user from our db
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def get_google_provider_cfg():
    return requests.get(GOOGLE_DISCOVERY_URL).json()

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
        hash_and_salted_password = generate_password_hash(
            formPassword,
            method='pbkdf2:sha256',
            salt_length=8
        )

        new_user = User(
            name = request.form.get('name'),
            email = request.form.get('email'),
            password = hash_and_salted_password
        )

        db.session.add(new_user)
        db.session.commit()
        html = render_template('register_mail.html',name=new_user.name, email=new_user.email, password=formPassword)

        send_email(new_user.email, "Successfully registered to Indradip Chakraborty", html)
        login_user(new_user)

        flash("You have successfully registered, Now Please! use your registered Email and Password to login")
        return redirect(url_for("login"))
        
    return render_template('register.html', title="Register", user=current_user)

@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()
        print(user)

        if not user:
            flash("That email does not exist, please try again.")
            return redirect(url_for('login'))
        
        elif not check_password_hash(user.password, password):
            flash("Password incorrect, please try again.")
            return redirect(url_for('login'))

        else:
            # send_email(email, "Hello - Tester")
            login_user(user)
            return redirect(url_for('home'))

    return render_template('login.html', title="Login page", user=current_user)

@app.route('/login/google')
def login_google():
    # Find out what URL to hit for Google login
    google_provider_cfg = get_google_provider_cfg()
    authorization_endpoint = google_provider_cfg["authorization_endpoint"]

    # Use library to construct the request for Google login and provide
    # scopes that let you retrieve user's profile from Google
    request_uri = client.prepare_request_uri(
        authorization_endpoint,
        redirect_uri=request.base_url + "/callback",
        scope=["openid", "email", "profile"],
    )
    return redirect(request_uri)


@app.route('/login/google/callback')
def google_authorize():
    # Get authorization code Google sent back to you
    code = request.args.get("code")

    # Find out what URL to hit to get tokens that allow you to ask for
    # things on behalf of a user
    google_provider_cfg = get_google_provider_cfg()
    token_endpoint = google_provider_cfg["token_endpoint"]

    # Prepare and send a request to get tokens! Yay tokens!
    token_url, headers, body = client.prepare_token_request(
        token_endpoint,
        authorization_response=request.url,
        redirect_url=request.base_url,
        code=code
    )
    token_response = requests.post(
        token_url,
        headers=headers,
        data=body,
        auth=(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET),
    )

    # Parse the tokens!
    client.parse_request_body_response(json.dumps(token_response.json()))


    # Now that you have tokens (yay) let's find and hit the URL
    # from Google that gives you the user's profile information,
    # including their Google profile image and email
    userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]
    uri, headers, body = client.add_token(userinfo_endpoint)
    userinfo_response = requests.get(uri, headers=headers, data=body)

    # You want to make sure their email is verified.
    # The user authenticated with Google, authorized your
    # app, and now you've verified their email through Google!
    if userinfo_response.json().get("email_verified"):
        unique_id = userinfo_response.json()["sub"]
        users_email = userinfo_response.json()["email"]
        picture = userinfo_response.json()["picture"]
        users_name = userinfo_response.json()["name"]
    else:
        return "User email not available or not verified by Google.", 400


    hash_and_salted_password = generate_password_hash(
        users_email,
        method='pbkdf2:sha256',
        salt_length=8
    )

    user = User.query.filter_by(email=users_email).first()

    # Doesn't exist? Add it to the database.
    if not user:
        # Create a user in your db with the information provided by Google
        new_user = User(
            name = users_name,
            email = users_email,
            password = hash_and_salted_password,
            profile_pic = picture
        )

        db.session.add(new_user)
        db.session.commit()

        html = render_template('register_google_mail.html',name=new_user.name, email=new_user.email)
        send_email(new_user.email, "Successfully registered to Indradip Chakraborty", html)

        # Login user
        login_user(new_user)
        return redirect(url_for('home'))
    
    elif not check_password_hash(user.password, users_email):
        flash("You already have an account, Please! use your registered Email and Password to login")
        return redirect(url_for('login'))
    else:
        # Login user
        login_user(user)
        return redirect(url_for('home'))


@app.route("/home", methods=['GET', 'POST'])
@login_required
def home():
    if request.method == 'POST':
        fname = request.form['fname']
        lname = request.form['lname']
        email = request.form['email']
        phone = request.form['phone']
        message = request.form['message']

        html = render_template('query_mail.html',name=fname, surname=lname, email=email, phone=phone, message=message)

        send_email("indradipchakraborty10@gmail.com", f"{fname} sent you a query mail", html)
        send_email(email, "You queried to Indradip Chakraborty", html)
    return render_template('home.html', title="Home page", user=current_user)


@app.route("/contact", methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        fullname = request.form['fullname']
        email = request.form['email']
        message = request.form['message']

        html = render_template('contact_mail.html',name=fullname, email=email, message=message)

        send_email("indradipchakraborty10@gmail.com", f"{fullname} wants to contact you", html)
        # send_email(email, "You conc to Indradip Chakraborty", html)
    return render_template ('contact.html', title="Contact Us", user=current_user)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/')

#Create admin-only decorator
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        #If id is not 1 then return abort with 403 error
        if current_user.id != 1:
            return abort(403)
        #Otherwise continue with the route function
        return f(*args, **kwargs)        
    return decorated_function

@app.route('/admin')
@login_required
@admin_only
def admin():
    allUser = User.query.all()
    return render_template('admin.html', users=allUser)



if __name__ == "__main__":
    app.run(debug=False)
