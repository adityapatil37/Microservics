import os
import logging
from flask import Flask, jsonify, request
from werkzeug.security import generate_password_hash, check_password_hash
from flask_bcrypt import Bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import jwt
import datetime
from dotenv import load_dotenv
from pymongo import MongoClient
from flask_talisman import Talisman
from flask_cors import CORS

# Load environment variables from a .env file
load_dotenv()

app = Flask(__name__)
bcrypt = Bcrypt(app)

# Configuring MongoDB
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/userdb")
client = MongoClient(MONGO_URI)
db = client.userdb
users_collection = db.users

# Secret key for JWT encoding/decoding
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY", "yoursecretkey")

# Configure rate limiting
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Apply rate limiting to all routes
limiter.init_app(app)

# Configure logging
logging.basicConfig(level=logging.INFO)

# Configure Talisman for security headers
Talisman(app)

# Enable CORS for all routes
CORS(app)

# Utility function to enforce strong password policy
def is_strong_password(password):
    if len(password) < 8:
        return False
    if not any(char.isdigit() for char in password):
        return False
    if not any(char.isupper() for char in password):
        return False
    if not any(char.islower() for char in password):
        return False
    if not any(char in "!@#$%^&*()_+-=[]{};':\"\\|,.<>/?`~" for char in password):
        return False
    return True

@app.route('/signup', methods=['POST'])
@limiter.limit("5 per minute")
def signup():
    try:
        data = request.json
        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            return jsonify({"error": "Username and password required"}), 400

        if not is_strong_password(password):
            return jsonify({"error": "Password must be at least 8 characters long, include an uppercase letter, a lowercase letter, a number, and a special character"}), 400

        # Check if user already exists
        user = users_collection.find_one({'username': username})
        if user:
            return jsonify({"error": "User already exists"}), 400

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        users_collection.insert_one({'username': username, 'password': hashed_password})

        return jsonify({"message": "User registered successfully"}), 201
    except Exception as e:
        logging.error("Error in signup: %s", e)
        return jsonify({"error": "Internal server error"}), 500

@app.route('/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    try:
        data = request.json
        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            return jsonify({"error": "Username and password required"}), 400

        user = users_collection.find_one({'username': username})
        if not user or not bcrypt.check_password_hash(user['password'], password):
            return jsonify({"error": "Invalid username or password"}), 401

        token = jwt.encode({
            'username': username,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        }, app.config['SECRET_KEY'], algorithm="HS256")

        return jsonify({'token': token}), 200
    except Exception as e:
        logging.error("Error in login: %s", e)
        return jsonify({"error": "Internal server error"}), 500

@app.route('/profile', methods=['GET'])
@limiter.limit("10 per minute")
def profile():
    try:
        token = request.headers.get('Authorization')

        if not token:
            return jsonify({"error": "Token is missing"}), 403

        try:
            token = token.split(" ")[1]
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            user = users_collection.find_one({'username': data['username']})
            if not user:
                return jsonify({"error": "User not found"}), 404
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token has expired"}), 403
        except jwt.InvalidTokenError:
            return jsonify({"error": "Token is invalid"}), 403

        return jsonify({"username": user['username']}), 200
    except Exception as e:
        logging.error("Error in profile: %s", e)
        return jsonify({"error": "Internal server error"}), 500

if __name__ == '__main__':
    context = ('cert.pem', 'key.pem')
    app.run(host='0.0.0.0', port=5801, ssl_context=context)


#172.25.252.61