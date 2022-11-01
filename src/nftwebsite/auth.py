
from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import UserInfo
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from flask_login import login_user, login_required, logout_user, current_user



auth = Blueprint('auth' , '__name__')

@auth.route('/login', methods=['GET','POST'])
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

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.home'))

@auth.route('/home')
def home():
    return render_template("home.html")

@auth.route('/register', methods=['GET','POST'])
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


