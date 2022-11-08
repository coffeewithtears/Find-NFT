
from flask import  render_template, request, make_response
from flask_sqlalchemy import SQLAlchemy

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager

from flask import render_template, request
from flask_login import login_required, current_user

import requests
import json


from flask_login import UserMixin
from sqlalchemy.sql import func
from sqlalchemy.dialects.postgresql import JSON

from flask import Blueprint, render_template, request, flash, redirect, url_for

from werkzeug.security import generate_password_hash, check_password_hash

from flask_login import login_user, login_required, logout_user, current_user



db = SQLAlchemy()
DB_NAME = "testdb"



def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'hello'
    app.config['SQLALCHEMY_DATABASE_URI'] = f"postgresql://postgres:postgres@localhost:5432/{DB_NAME}"


    db.init_app(app)

    with app.app_context():
        db.create_all()

    login_manager = LoginManager(app)
    login_manager.login_view = 'login'
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(id):
        return UserInfo.query.get(int(id))

    return app

  
app = create_app()


db.init_app(app)
class nft_information(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    description = db.Column(db.String, nullable=False)

    def addToDb(self):
        db.session.add(self)
        db.session.commit()

    @classmethod
    def checkInDb(cls, nft_address):
        return cls.query.filter_by(address=nft_address).first()

class UserInfo(db.Model, UserMixin):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key = True)
    email = db.Column(db.String(150), unique = True)
    password = db.Column(db.String(150))
    username = db.Column(db.String(150))








@app.route('/')
def home():
    return render_template('home.html', user=current_user)


@app.route('/nft', methods=[ 'GET', 'POST'])
def nft():
    args = request.args['nftaddr']

    url = f"https://solana-gateway.moralis.io/nft/mainnet/{args}/metadata"

    headers = {

        "accept": "application/json",

        "X-API-Key": "S77RJTmiMoBbTQTEed5MExSDfHQ2HolnDEXy7GZRoo3Eah6t1YAR20dfdGIJASaT"

    }

    response = requests.get(url, headers=headers)

    nft = nft_information()
    db_exist = nft.checkInDb(args)

    if db_exist:
        payload = db_exist
        return make_response(render_template('index.html', payload=payload))

    response2 = response.json()

    payload = {

        "name": response2["name"],
        "description": response2["metaplex"]["metadataUri"]

    }

    nft = nft_information(**payload)

    nft.addToDb()

    return make_response(render_template('index.html', payload=payload))

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        username = request.form.get('username')
        user = UserInfo.query.filter_by(email = email, username = username).first()
        if user:
            if check_password_hash(user.password, password):
                login_user(user, remember = True)
                return redirect(url_for('views.nft'))
            else:
                flash('Incorrect password, try again', category='error')
        else:
            flash('Try again, email or username doesn\'t exist', category='error')
    
    return render_template("login.html", user=current_user)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('app.home1'))


@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        username = request.form.get('username')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        user = UserInfo.query.filter_by(email = email).first()
        if user:
            flash('Email already exists', category='error')
        elif len(email) < 4:
            flash('Email must be greater than 3 characters.', category = 'error')
        elif len(username) < 2:
            flash('First name must be greater than 1 characters.', category = 'error')
        elif password1 != password2:
            flash('Passwords don\'t match', category = 'error')
        elif len(password1)  < 7:
            flash('Password must be at least than 7 characters.', category = 'error')
        else:
            print(email, username, password1)
            new_user =UserInfo(email=email, username=username, password=generate_password_hash(password1, method = 'sha256'))
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user, remember=True)
            return redirect(url_for('views.nft'))

    return render_template("register.html",user=current_user)


if __name__ == '__main__':

    app.run(debug=True)

