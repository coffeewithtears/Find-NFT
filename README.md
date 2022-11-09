# Find-NFT
#  Implement a WebService for collecting information about NFTs with Authentication and Authorization features
NFTSearcher - user provides an NFT address and clicks a button, it should display information about that NFT and store all data in a Postgres database.

# Installation
### 1.1 Before you begin, you will need to have the installed on your computer:

+ [Git](https://git-scm.com/)
+ [Python](https://www.python.org/)
+ [Flask](https://palletsprojects.com/p/flask/)
+ [FlaskSQLAlchemy](https://flask-sqlalchemy.palletsprojects.com/en/3.0.x/)

To install README "NFT", follow these steps:
```
# Clone this repository
$ git clone https://github.com/coffeewithtears/NFTSearhcer.git

# Create a virtual environment:
$ python -m venv venv

# Activating the virtual environment:
$ source venv/bin/activate

# Install requirements:
$ pip install -r requirements.txt 

# Go to src directory:
$ cd src

# Run it:
$ flask --app app.py run
```

# Usage
Open your code editor with python and run our code.
The second step is to open the link http://127.0.0.1:5000/  and register on our website.

# Examples

1.1 First, you need to register on our website http://127.0.0.1:5000/

![photo1667128860](https://user-images.githubusercontent.com/91626983/198875948-02bcbe3a-b27a-4805-89db-8437d0d2e080.jpeg)

1.2 Login to an existing account 

![photo1667128848](https://user-images.githubusercontent.com/91626983/198875951-9e679da6-036c-4f7a-be6f-206b33057b09.jpeg)

1.3 If you can't log in, then you don't have an account or the password is wrong. 
Try to register again

![photo1667128874](https://user-images.githubusercontent.com/91626983/198875957-cdcc404f-0abb-4f84-abeb-24433de45b8b.jpeg)

1.4 If logged in, then information about NFT addresses

![photo1667128903](https://user-images.githubusercontent.com/91626983/198875955-b57140e3-7754-4553-b7b4-d9e4a2327060.jpeg)
![photo1667128925](https://user-images.githubusercontent.com/91626983/198875953-f0b3a57c-9290-4ac0-8ccc-cf5b99d940ed.jpeg)

# LICENSE

https://choosealicense.com/licenses/mit/
