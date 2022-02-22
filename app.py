from flask import Flask, request, session, flash, render_template, jsonify, make_response
from flask_restful import Api, Resource, reqparse, abort, fields, marshal_with
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
import jwt
import datetime
from functools import wraps

app = Flask(__name__)
api = Api(app)
app.config['SECRET_KEY'] = 'thisissecret'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:1234@localhost/postgres'


db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    api_key = db.Column(db.String(50), unique=True)
    username = db.Column(db.String(1000), nullable=False)
    password = db.Column(db.String(1000), nullable=False)


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        
        token =  request.args.get('api_key')

        if not token:
            return jsonify({'error' : 'API key is missing!'}), 403

        try: 
            data = jwt.decode(token, app.config['SECRET_KEY'])
        except:
            return jsonify({'error' : 'Invalid API key!'}), 401

        return f(*args, **kwargs)

    return decorated


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/signup', methods=['POST'])
def signup():

    data = request.get_json()
    username = data['username']
    password = data['password']

    hashed_password = generate_password_hash(password, method='sha256')

    token = jwt.encode({
            'user': username,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=1200)
            },
            app.config['SECRET_KEY'])

    new_user = User(api_key=str(uuid.uuid4()), username=username, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'Yey, New account ! Here is my token :' : token.decode('utf-8')})


@app.route('/login', methods=['POST'])
def login():
    token = request.form['api_key']
    username = request.form['username']
    password = request.form['password']
    
    if not token:
        return jsonify({'error' : 'API key is missing.'}), 403

    if not username:
        return jsonify({'error' : 'Please provide username.'}), 400

    if not password:
        return jsonify({'error' : 'Please provide password.'}), 400

    user = User.query.filter_by(username=username).first()

    if not user or not check_password_hash(user.password, password):
        return jsonify({'error' : 'Incorrect username or password.'}), 401
    
    if username and password:
        return jsonify({'auth_key': token})

    return jsonify({'error' : 'Something went wrong. Please try again later.'}), 500


@app.route('/decision')
@token_required
def authorised():
    return 'Decision making : '


if __name__ == "__main__":
	app.run(debug=True)
    