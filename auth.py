import os
import pathlib
import requests
from flask import Blueprint, render_template, flash, url_for, session, abort, redirect, request,Flask
from models import User
from werkzeug.security import generate_password_hash, check_password_hash
from __init__ import db   
from flask_login import login_user, login_required, logout_user, current_user
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
import google.auth.transport.requests
import random
import string
from pip._vendor import cachecontrol
from flask_migrate import Migrate
import jwt
from time import time
import finnhub

app = Flask("__name__")


auth = Blueprint('auth', __name__)
app.secret_key = 'eefsefsfefe efsfefesttu'
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
migrate = Migrate(app, db)


client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")
finnhub_client = finnhub.Client(api_key="cmd9ra1r01qip5t7i7o0cmd9ra1r01qip5t7i7og")


GOOGLE_CLIENT_ID = "724949503986-fo1k68hojv53c88rprpk0f1fcgkq098p.apps.googleusercontent.com"
GOOGLE_CLIENT_SECRET = "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"



flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri="http://127.0.0.1:5000/callback",
)



def login_is_required(function):
    def wrapper(*args, **kwargs):
        if "google_id" not in session:
            return abort(401)  # Authorization required
        else:
            return function()



    return wrapper


@auth.route('/login', methods=['GET', 'POST'])
def login():

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash('Logged in successfully!', category='success')
                login_user(user, remember=True)
                return redirect(url_for('views.home'))
            else:
                flash('Incorrect password, try again.', category='error')
        else:
            flash('Email does not exist.', category='error')

    return render_template("login.html", user=current_user)


@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email')
        first_name = request.form.get('firstName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')
        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already exists.', category='error')
        elif len(email) < 4:
            flash('Email must be greater than 3 characters.', category='error')
        elif len(first_name) < 2:
            flash('First name must be greater than 1 character.', category='error')
        elif password1 != password2:
            flash('Passwords don\'t match.', category='error')
        elif len(password1) < 7:
            flash('Password must be at least 7 characters.', category='error')
        else:
            new_user = User(email=email, first_name=first_name, password=generate_password_hash(
                password1, method='pbkdf2:sha256'))
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user, remember=True)
            flash('Account created!', category='success')
            return redirect(url_for('views.home'))



    return render_template("sign_up.html", user=current_user)

@auth.route('/login-by-google')
def login_bygoogle():

    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)



@auth.route('/callback')
def callback():



    flow.fetch_token(authorization_response=request.url)



    if not session["state"] == request.args["state"]:
        abort(500)  



    credentials = flow.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    

    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID
        
    )
    session["google_id"] = id_info.get("sub")
    session["name"] = id_info.get("name")
    session["email"] = id_info.get("email")
    user = User.query.filter_by(email=session["email"]).first()
    if not user:
        plain_password = ''.join(random.choice(string.ascii_letters) for i in range(10))
        hashed_password = generate_password_hash(plain_password, method='pbkdf2:sha256')



        new_user = User(
            email=session["email"],
            first_name=session["name"],
            password=hashed_password
        )
        db.session.add(new_user)
        db.session.commit()
        user = new_user
    flash('Logged in successfully!', category='success')
    login_user(user, remember=True)
    return redirect(url_for('views.home'))  



@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))


@auth.route('/login-by-apple')
def login_by_apple():
    authorize_url = 'https://appleid.apple.com/auth/authorize'
    token_url = 'https://appleid.apple.com/auth/token'

    client_id = 'YOUR.APPLE.CLIENT.ID'
    redirect_uri = 'YOUR REDIRECT URI AFTER SUCCESSFUL LOGIN'

    state = ''.join(random.choice(string.ascii_letters) for i in range(10))
    session['state'] = state

    request_uri = f'{authorize_url}?response_type=code&client_id={client_id}&redirect_uri={redirect_uri}&state={state}'

    return redirect(request_uri)


@auth.route('/callback-from-apple')
def callback_from_apple():
    code = request.args.get('code')
    state = request.args.get('state')

    if state != session.pop('state', None):
        abort(403)

    token_payload = {
        'iss': 'YOUR APPLE TEAM ID',
        'iat': time(),
        'exp': time() + 3600,
        'aud': 'https://appleid.apple.com',
        'sub': 12554884565654,
    }

    client_secret = jwt.encode(
        token_payload,
        'YOUR PRIVATE KEY FROM APPLE',
        algorithm='ES256',
        headers={
            'kid': 'edsgwr44wtwfcxxaerer-cafdeff',
        }
    ).decode('utf-8')


    return redirect(url_for('views.home'))

