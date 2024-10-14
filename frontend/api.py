from flask import Flask, request, jsonify, render_template
import sqlite3
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import re

app = Flask(__name__)
CORS(app)
app.config['JWT_SECRET_KEY'] = 'your_secret_key'  # Change this to a strong secret key
jwt = JWTManager(app)

def db_connection():
    connection = sqlite3.connect('database.db')
    connection.row_factory = sqlite3.Row
    return connection

def get_user(email):
    connection = db_connection()
    cursor = connection.cursor()
    cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
    user = cursor.fetchone()
    connection.close()
    return user

def validate_password(password):
    """
    Validates the password based on the following criteria:
    - At least 8 characters long
    - Contains at least one lowercase letter
    - Contains at least one uppercase letter
    - Contains at least one digit
    - Contains at least one special character (!@#$%^&*()-_+=<>?)
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one digit."
    if not re.search(r'[!@#$%^&*()\-_=+<>?]', password):
        return False, "Password must contain at least one special character."
    return True, "Password is valid."

def create_table():
    connection = db_connection()
    cursor = connection.cursor()
    cursor.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, email VARCHAR(60) UNIQUE, password VARCHAR(255))')
    connection.commit()
    connection.close()

def sanitize_table_name(email):
    sanitized_name = re.sub(r'\W+', '_', email)
    return sanitized_name

def create_table_userdata(email):
    stripped_email = sanitize_table_name(email)
    connection = db_connection()
    cursor = connection.cursor()
    cursor.execute(f'''CREATE TABLE IF NOT EXISTS {stripped_email}
                       (part_number INTEGER PRIMARY KEY,
                        part_name VARCHAR(60) NOT NULL,
                        description VARCHAR(255) NOT NULL,
                        oem_number VARCHAR(255) NOT NULL UNIQUE,
                        mmc_number VARCHAR(255) NOT NULL UNIQUE,
                        price DECIMAL(10,2) NOT NULL,
                        quantity INTEGER NOT NULL,
                        min_stock INTEGER NOT NULL,
                        location VARCHAR(255) NOT NULL,
                        manufacturer VARCHAR(255) NOT NULL,
                        notes TEXT NOT NULL)''')
    connection.commit()
    connection.close()

@app.route('/register', methods=['POST'])
def add_user():
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')

        if not email or not password:
            return jsonify({'error': 'Invalid email or password provided'}), 400

        if get_user(email):
            return jsonify({'error': 'User already exists'}), 400

        is_valid, message = validate_password(password)
        if not is_valid:
            return jsonify({'error': message}), 400

        hashed_password = generate_password_hash(password)

        connection = db_connection()
        cursor = connection.cursor()
        cursor.execute('INSERT INTO users (email, password) VALUES (?, ?)', (email, hashed_password))
        connection.commit()
        connection.close()
        create_table_userdata(email)

        return jsonify({'message': 'User registered successfully!'}), 201

    except Exception as e:
        return jsonify({'error': 'Something went wrong'}), 500

@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')

        user = get_user(email)
        if not user or not check_password_hash(user['password'], password):
            return jsonify({'error': 'Invalid credentials'}), 401

        access_token = create_access_token(identity=email)
        return jsonify({'access_token': access_token}), 200

    except Exception as e:
        return jsonify({'error': 'Something went wrong'}), 500

@app.route('/add_part', methods=['POST'])
@jwt_required()
def add_part():
    try:
        current_user = get_jwt_identity()  # Get the logged-in user's email from the token

        data = request.get_json()
        part_name = data.get('part_name')
        description = data.get('description')
        oem_number = data.get('oem_number')
        mmc_number = data.get('mmc_number')
        price = data.get('price')
        quantity = data.get('quantity')
        min_stock = data.get('min_stock')
        location = data.get('location')
        manufacturer = data.get('manufacturer')
        notes = data.get('notes')

        if not all([part_name, description, oem_number, mmc_number, price, quantity, min_stock, location, manufacturer, notes]):
            return jsonify({'error': 'Invalid part data provided'}), 400

        stripped_email = sanitize_table_name(current_user)

        connection = db_connection()
        cursor = connection.cursor()
        cursor.execute(f'''INSERT INTO {stripped_email} 
                           (part_name, description, oem_number, mmc_number, price, quantity, min_stock, location, manufacturer, notes) 
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                       (part_name, description, oem_number, mmc_number, price, quantity, min_stock, location, manufacturer, notes))
        connection.commit()
        connection.close()

        return jsonify({'message': 'Part added successfully!'}), 201

    except Exception as e:
        return jsonify({'error': 'Something went wrong', 'details': str(e)}), 500
    
@app.route('/delete_part', methods=['DELETE'])
@jwt_required()
def delete_part():
    try:
        current_user = get_jwt_identity()  # Get the logged-in user's email from the token

        data = request.get_json()
        partnumber = data.get("part_number")

        if not partnumber:
            return jsonify({'error': 'Invalid part number provided'}), 400
        
        stripped_email = sanitize_table_name(current_user)

        connection = db_connection()
        cursor = connection.cursor()

        if partnumber:
            cursor.execute(f'SELECT * FROM {stripped_email} WHERE part_number = ?', (partnumber,))
            part = cursor.fetchone()
            if not part:
                return jsonify({'error': 'Part not found'}), 404

        if partnumber:
            cursor.execute(f'DELETE FROM {stripped_email} WHERE part_number = ?', (partnumber,))

        connection.commit()
        connection.close()

        return jsonify({'message': 'Part deleted successfully!'}), 200
    
    except Exception as e:
        return jsonify({'error': 'Something went wrong', 'details': str(e)}), 500
    
@app.route('/update_part', methods=['PUT'])
@jwt_required()
def update_part():
    try:
        current_user = get_jwt_identity()  # Get the logged-in user's email from the token

        data = request.get_json()
        partnumber = data.get("part_number")
        part_name = data.get('part_name')
        description = data.get('description')
        oem_number = data.get('oem_number')
        mmc_number = data.get('mmc_number')
        price = data.get('price')
        quantity = data.get('quantity')
        min_stock = data.get('min_stock')
        location = data.get('location')
        manufacturer = data.get('manufacturer')
        notes = data.get('notes')

        if not all([partnumber, part_name, description, oem_number, mmc_number, price, quantity, min_stock, location, manufacturer, notes]):
            return jsonify({'error': 'Invalid part data provided'}), 400

        stripped_email = sanitize_table_name(current_user)

        connection = db_connection()
        cursor = connection.cursor()
        cursor.execute(f'''UPDATE {stripped_email} 
                           SET part_name = ?, description = ?, oem_number = ?, mmc_number = ?, price = ?, quantity = ?, min_stock = ?, location = ?, manufacturer = ?, notes = ? 
                           WHERE part_number = ?''',
                       (part_name, description, oem_number, mmc_number, price, quantity, min_stock, location, manufacturer, notes, partnumber))
        connection.commit()
        connection.close()

        return jsonify({'message': 'Part updated successfully!'}), 200

    except Exception as e:
        return jsonify({'error': 'Something went wrong', 'details': str(e)}), 500

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register')
def register():
    return render_template('register.html')

if __name__ == '__main__':
    create_table()
    app.run(debug=True)
