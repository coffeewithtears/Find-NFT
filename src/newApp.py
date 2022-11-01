
from flask import  render_template, request
from flask_sqlalchemy import SQLAlchemy
from nftwebsite import create_app, views

app = create_app()

if __name__ == '__main__':

    app.run(debug=True)

