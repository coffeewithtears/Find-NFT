
from flask import  render_template, request,Blueprint
from flask_sqlalchemy import SQLAlchemy

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager

from flask import Blueprint, render_template, request
from flask_login import login_required, current_user
import psycopg2
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
views = Blueprint('views', '__name__') 
auth = Blueprint('auth' , '__name__')

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'hello'
    app.config['SQLALCHEMY_DATABASE_URI'] = f"postgresql://postgres:postgres@localhost:5432/{DB_NAME}"


    db.init_app(app)

    app.register_blueprint(views, url_prefix = '/')
    app.register_blueprint(auth, url_prefix = '/')

    from nftwebsite.models import UserInfo

    with app.app_context():
        db.create_all()

    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(id):
        return UserInfo.query.get(int(id))

    return app

  
app = create_app()


class nft_information(db.Model):
    nft_addr = db.Column(db.String(100), primary_key = True)
    info = db.Column(db.JSON)



class UserInfo(db.Model, UserMixin):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key = True)
    email = db.Column(db.String(150), unique = True)
    password = db.Column(db.String(150))
    username = db.Column(db.String(150))


conn = psycopg2.connect(host='127.0.0.1',
                            database='testdb',
                            user="postgres",
                            password="postgres",
                            port = "5432")
cur = conn.cursor()






@views.route('/')
@login_required
def home():
        return render_template('home.html', user=current_user)


@views.route('/nft', methods=[ 'GET', 'POST'])
@login_required
def nft():
        nft_address = request.args.get('nftaddr')
        if nft_address:   
            cur.execute("SELECT * from nft_information WHERE NFT_ADDR=%s", (nft_address,))
            conn.commit()
            if cur.fetchall(): 
                url =f"https://solana-gateway.moralis.io/nft/mainnet/{nft_address}/metadata"
                headers = {
                            "accept": "application/json",
                            "X-API-Key": "FzA6L5hendGEXQzNFOFcOAQfAqWbVNaMs8mLQNWVk1diN6nNN0DpeQWJB2HEbdsY"
                        }
                response = requests.get(url, headers=headers)
                query_sql1 = """ UPDATE nft_information SET info = (%s)  WHERE nft_addr = (%s); """
                somth = response.json
                rep = json.dumps(somth())        
                cur.execute(query_sql1, (rep,nft_address,))
                conn.commit()
                cur.execute (" select info -> 'name' from nft_information WHERE nft_addr = (%s)", (nft_address,))
                name_of_nft = cur.fetchone()
                print(name_of_nft)
                cur.execute (" select info -> 'metaplex' -> 'metadataUri' from nft_information WHERE nft_addr = (%s)", (nft_address,))
                nft_img_url = cur.fetchone()
                print()
                cur.execute (" select info -> 'mint'  from nft_information WHERE nft_addr = (%s)", (nft_address,))
                nft_mint = cur.fetchone()
                return render_template('index.html', nm=name_of_nft[0], imgurl = nft_img_url[0], mint = nft_mint[0], user=current_user)
            else:
                cur.execute("INSERT INTO nft_information (NFT_ADDR) VALUES (%s)", (nft_address,))
                conn.commit()
                return render_template('create.html', user=current_user)
        return render_template('create.html', user=current_user)



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


if __name__ == '__main__':

    app.run(debug=True)

