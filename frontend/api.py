import mysql.connector
from flask import Flask, request, jsonify, render_template, redirect, url_for
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity,
    set_access_cookies, unset_jwt_cookies
)
import re
import logging

app = Flask(__name__)

# =======================
# JWT Configuration
# =======================
app.config['JWT_SECRET_KEY'] = 'Jettson1245!'  # Change this to a strong secret key
app.config['JWT_TOKEN_LOCATION'] = ['cookies']
app.config['JWT_ACCESS_COOKIE_PATH'] = '/'
app.config['JWT_COOKIE_SECURE'] = True  # Set to True in production with HTTPS
app.config['JWT_COOKIE_CSRF_PROTECT'] = True  # Set to True to enable CSRF protection

jwt = JWTManager(app)

# =======================
# CORS Configuration
# =======================
CORS(app, supports_credentials=True, origins=['http://localhost:5000'])

# =======================
# Logging Configuration
# =======================
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# =======================
# Database Functions
# =======================

def db_connection():
    """Establishes a connection to the MySQL database."""
    try:
        connection = mysql.connector.connect(
            host="db",             # MySQL service name in docker-compose.yml
            user="admin",       # MySQL username
            password="1245",  # MySQL password
            database="inventory_db"   # MySQL database name
        )
        return connection
    except mysql.connector.Error as e:
        logger.error(f"Database connection error: {e}")
        return None

def get_user(email):
    """Retrieves a user from the database by email."""
    connection = db_connection()
    if not connection:
        return None
    try:
        cursor = connection.cursor(dictionary=True)
        cursor.execute('SELECT * FROM users WHERE email = %s', (email,))
        user = cursor.fetchone()
        connection.close()
        return user
    except mysql.connector.Error as e:
        logger.error(f"Error retrieving user {email}: {e}")
        connection.close()
        return None

def validate_password(password):
    """Validates the password based on security criteria."""
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

def create_users_table():
    """Creates the users table if it doesn't exist."""
    connection = db_connection()
    if not connection:
        logger.error("Failed to create users table due to database connection error.")
        return
    try:
        cursor = connection.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                email VARCHAR(60) UNIQUE,
                password VARCHAR(255)
            )
        ''')
        connection.commit()
        logger.info("Users table ensured.")
    except mysql.connector.Error as e:
        logger.error(f"Error creating users table: {e}")
    finally:
        connection.close()

def sanitize_table_name(email):
    """Sanitizes the email to create a valid table name."""
    sanitized_name = re.sub(r'\W+', '_', email)
    return sanitized_name

def create_table_userdata(email):
    """Creates a user-specific table for storing parts."""
    sanitized_email = sanitize_table_name(email)
    connection = db_connection()
    if not connection:
        logger.error(f"Failed to create user table for {email} due to database connection error.")
        return
    try:
        cursor = connection.cursor()
        cursor.execute(f'''
            CREATE TABLE IF NOT EXISTS {sanitized_email} (
                part_number INT AUTO_INCREMENT PRIMARY KEY,
                part_name VARCHAR(60) NOT NULL,
                description VARCHAR(255) NOT NULL,
                oem_number VARCHAR(255) NOT NULL UNIQUE,
                mmc_number VARCHAR(255) NOT NULL UNIQUE,
                price DECIMAL(10,2) NOT NULL,
                quantity INT NOT NULL,
                min_stock INT NOT NULL,
                location VARCHAR(255) NOT NULL,
                manufacturer VARCHAR(255) NOT NULL,
                notes TEXT
            )
        ''')
        connection.commit()
        logger.info(f"User table for {email} ensured.")
    except mysql.connector.Error as e:
        logger.error(f"Error creating user table for {email}: {e}")
    finally:
        connection.close()

# =======================
# Routes
# =======================

@app.route('/register1', methods=['POST'])
def add_user():
    """Registers a new user."""
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')

        logger.debug(f"Register attempt for email: {email}")

        if not email or not password:
            logger.warning("Registration failed: Missing email or password.")
            return jsonify({'error': 'Invalid email or password provided'}), 400

        if get_user(email):
            logger.warning(f"Registration failed: User {email} already exists.")
            return jsonify({'error': 'User already exists'}), 400

        is_valid, message = validate_password(password)
        if not is_valid:
            logger.warning(f"Registration failed for {email}: {message}")
            return jsonify({'error': message}), 400

        hashed_password = generate_password_hash(password)

        connection = db_connection()
        if not connection:
            logger.error("Registration failed: Database connection error.")
            return jsonify({'error': 'Database connection error'}), 500

        cursor = connection.cursor()
        cursor.execute('INSERT INTO users (email, password) VALUES (%s, %s)', (email, hashed_password))
        connection.commit()
        connection.close()

        create_table_userdata(email)
        access_token = create_access_token(identity=email)

        # Set JWT token in cookie
        resp = jsonify({'message': 'User registered successfully!'})
        set_access_cookies(resp, access_token)

        logger.info(f"User {email} registered successfully.")
        return resp, 201

    except mysql.connector.IntegrityError as ie:
        logger.error(f"IntegrityError during registration for {email}: {ie}")
        return jsonify({'error': 'Email already exists.'}), 400
    except Exception as e:
        logger.error(f"Unexpected error during registration for {email}: {e}")
        return jsonify({'error': 'Something went wrong', 'details': str(e)}), 500

@app.route('/login', methods=['POST'])
def login():
    """Logs in an existing user."""
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')

        logger.debug(f"Login attempt for email: {email}")

        user = get_user(email)
        if not user:
            logger.warning(f"Login failed: User {email} does not exist.")
            return jsonify({'error': 'Invalid credentials'}), 401

        if not check_password_hash(user['password'], password):
            logger.warning(f"Login failed: Incorrect password for {email}.")
            return jsonify({'error': 'Invalid credentials'}), 401

        access_token = create_access_token(identity=email)
        # Set JWT token in cookie
        resp = jsonify({'message': 'Login successful!'})
        set_access_cookies(resp, access_token)

        logger.info(f"User {email} logged in successfully.")
        return resp, 200

    except Exception as e:
        logger.error(f"Unexpected error during login for {email}: {e}")
        return jsonify({'error': 'Something went wrong', 'details': str(e)}), 500

@app.route('/logout', methods=['POST'])
def logout():
    """Logs out the current user by unsetting the JWT cookies."""
    try:
        resp = jsonify({'message': 'Logout successful!'})
        unset_jwt_cookies(resp)
        logger.info("User logged out successfully.")
        return resp, 200
    except Exception as e:
        logger.error(f"Unexpected error during logout: {e}")
        return jsonify({'error': 'Something went wrong', 'details': str(e)}), 500

@app.route('/get_current_user', methods=['GET'])
@jwt_required()
def get_current_user():
    """Returns the current logged-in user's email."""
    try:
        current_user = get_jwt_identity()  # Get the logged-in user's email from the token
        logger.debug(f"Current user fetched: {current_user}")
        return jsonify({'email': current_user}), 200
    except Exception as e:
        logger.error(f"Unexpected error fetching current user: {e}")
        return jsonify({'error': 'Something went wrong', 'details': str(e)}), 500

@app.route('/add_part', methods=['POST'])
@jwt_required()
def add_part():
    """Adds a new part to the user's inventory."""
    try:
        current_user = get_jwt_identity()  # Get the logged-in user's email from the token
        logger.debug(f"Add part attempt by user: {current_user}")

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
        notes = data.get('notes', '')  # Notes can be optional

        if not all([part_name, description, oem_number, mmc_number, price, quantity, min_stock, location, manufacturer]):
            logger.warning(f"Add part failed: Missing required fields by user {current_user}.")
            return jsonify({'error': 'Invalid part data provided'}), 400

        sanitized_email = sanitize_table_name(current_user)

        connection = db_connection()
        if not connection:
            logger.error("Add part failed: Database connection error.")
            return jsonify({'error': 'Database connection error'}), 500

        cursor = connection.cursor()
        cursor.execute(f'''
            INSERT INTO {sanitized_email} 
            (part_name, description, oem_number, mmc_number, price, quantity, min_stock, location, manufacturer, notes) 
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ''', (part_name, description, oem_number, mmc_number, price, quantity, min_stock, location, manufacturer, notes))
        connection.commit()
        part_number = cursor.lastrowid
        connection.close()

        logger.info(f"Part '{part_name}' added successfully by user {current_user} with part_number {part_number}.")
        return jsonify({'message': 'Part added successfully!', 'part_number': part_number}), 201

    except mysql.connector.IntegrityError as ie:
        logger.error(f"IntegrityError adding part by user {current_user}: {ie}")
        return jsonify({'error': 'OEM Number or MMC Number already exists.'}), 400
    except Exception as e:
        logger.error(f"Unexpected error adding part by user {current_user}: {e}")
        return jsonify({'error': 'Something went wrong', 'details': str(e)}), 500

@app.route('/delete_part', methods=['DELETE'])
@jwt_required()
def delete_part():
    """Deletes a part from the user's inventory."""
    try:
        current_user = get_jwt_identity()  # Get the logged-in user's email from the token
        logger.debug(f"Delete part attempt by user: {current_user}")

        data = request.get_json()
        part_number = data.get("part_number")

        if not part_number:
            logger.warning(f"Delete part failed: Missing part_number by user {current_user}.")
            return jsonify({'error': 'Invalid part number provided'}), 400

        sanitized_email = sanitize_table_name(current_user)

        connection = db_connection()
        if not connection:
            logger.error("Delete part failed: Database connection error.")
            return jsonify({'error': 'Database connection error'}), 500

        cursor = connection.cursor()

        cursor.execute(f'SELECT * FROM {sanitized_email} WHERE part_number = %s', (part_number,))
        part = cursor.fetchone()
        if not part:
            logger.warning(f"Delete part failed: Part number {part_number} not found for user {current_user}.")
            connection.close()
            return jsonify({'error': 'Part not found'}), 404

        cursor.execute(f'DELETE FROM {sanitized_email} WHERE part_number = %s', (part_number,))
        connection.commit()
        connection.close()

        logger.info(f"Part number {part_number} deleted successfully by user {current_user}.")
        return jsonify({'message': 'Part deleted successfully!'}), 200

    except Exception as e:
        logger.error(f"Unexpected error deleting part by user {current_user}: {e}")
        return jsonify({'error': 'Something went wrong', 'details': str(e)}), 500

@app.route('/edit_part', methods=['GET', 'PUT'])
@jwt_required()
def edit_part():
    """Handles both rendering the edit page and updating the part."""
    try:
        current_user = get_jwt_identity()
        logger.debug(f"Edit part request by user: {current_user}")

        sanitized_email = sanitize_table_name(current_user)
        connection = db_connection()
        if not connection:
            logger.error("Edit part failed: Database connection error.")
            return jsonify({'error': 'Database connection error'}), 500

        cursor = connection.cursor()

        if request.method == 'GET':
            part_number = request.args.get('part_number')
            if not part_number:
                logger.warning(f"Edit part failed: Missing part_number by user {current_user}.")
                connection.close()
                return jsonify({'error': 'Missing part number'}), 400

            try:
                cursor.execute(f'SELECT * FROM {sanitized_email} WHERE part_number = %s', (part_number,))
                part = cursor.fetchone()
                connection.close()

                if not part:
                    logger.warning(f"Edit part failed: Part number {part_number} not found for user {current_user}.")
                    return jsonify({'error': 'Part not found'}), 404

                logger.info(f"Rendering edit_part.html for part_number {part_number} by user {current_user}.")
                return render_template('edit_part.html', part=dict(part), current_user=current_user)

            except mysql.connector.Error as e:
                logger.error(f"Database error fetching part {part_number} for user {current_user}: {e}")
                connection.close()
                return jsonify({'error': 'Database query error'}), 500

        elif request.method == 'PUT':
            data = request.get_json()
            part_number = data.get("part_number")
            part_name = data.get('part_name')
            description = data.get('description')
            oem_number = data.get('oem_number')
            mmc_number = data.get('mmc_number')
            price = data.get('price')
            quantity = data.get('quantity')
            min_stock = data.get('min_stock')
            location = data.get('location')
            manufacturer = data.get('manufacturer')
            notes = data.get('notes', '')  # Notes are optional

            if not all([part_number, part_name, description, oem_number, mmc_number, price, quantity, min_stock, location, manufacturer]):
                logger.warning(f"Update part failed: Missing required fields by user {current_user}.")
                connection.close()
                return jsonify({'error': 'Missing required fields'}), 400

            try:
                cursor.execute(f'SELECT * FROM {sanitized_email} WHERE part_number = %s', (part_number,))
                part = cursor.fetchone()
                if not part:
                    logger.warning(f"Update part failed: Part number {part_number} not found for user {current_user}.")
                    connection.close()
                    return jsonify({'error': 'Part not found'}), 404

                cursor.execute(f'''
                    UPDATE {sanitized_email}
                    SET part_name = %s, description = %s, oem_number = %s, mmc_number = %s, price = %s, 
                        quantity = %s, min_stock = %s, location = %s, manufacturer = %s, notes = %s
                    WHERE part_number = %s
                ''', (part_name, description, oem_number, mmc_number, price, quantity, min_stock, location, manufacturer, notes, part_number))
                connection.commit()
                connection.close()

                logger.info(f"Part number {part_number} updated successfully by user {current_user}.")
                return jsonify({'message': 'Part updated successfully!'}), 200

            except mysql.connector.IntegrityError as ie:
                logger.error(f"IntegrityError updating part by user {current_user}: {ie}")
                connection.close()
                return jsonify({'error': 'OEM Number or MMC Number already exists.'}), 400
            except mysql.connector.Error as e:
                logger.error(f"Database error updating part {part_number} for user {current_user}: {e}")
                connection.close()
                return jsonify({'error': 'Database update error'}), 500

    except Exception as e:
        logger.error(f"Unexpected error in edit_part: {e}")
        return jsonify({'error': 'Something went wrong', 'details': str(e)}), 500

@app.route('/get_parts', methods=['GET'])
@jwt_required()
def get_parts():
    """Retrieves all parts for the logged-in user."""
    try:
        current_user = get_jwt_identity()  # Get the logged-in user's email from the token
        logger.debug(f"Get parts request by user: {current_user}")

        sanitized_email = sanitize_table_name(current_user)

        connection = db_connection()
        if not connection:
            logger.error("Get parts failed: Database connection error.")
            return jsonify({'error': 'Database connection error'}), 500

        cursor = connection.cursor()
        cursor.execute(f'SELECT * FROM {sanitized_email}')
        parts = cursor.fetchall()
        connection.close()

        logger.info(f"Retrieved {len(parts)} parts for user {current_user}.")
        return jsonify({'parts': [dict(part) for part in parts]})
    
    except Exception as e:
        logger.error(f"Unexpected error retrieving parts for user {current_user}: {e}")
        return jsonify({'error': 'Something went wrong', 'details': str(e)}), 500

@app.route('/')
def index():
    """Renders the login page."""
    return render_template('index.html')

@app.route('/register')
def register():
    """Renders the registration page."""
    return render_template('register.html')

@app.route('/dashboard')
@jwt_required()
def dashboard():
    """Renders the dashboard page."""
    current_user = get_jwt_identity()
    sanitized_email = sanitize_table_name(current_user)
    
    connection = db_connection()
    if not connection:
        logger.error("Dashboard access failed: Database connection error.")
        return jsonify({'error': 'Database connection error'}), 500

    cursor = connection.cursor()
    try:
        cursor.execute(f'SELECT * FROM {sanitized_email}')
        parts = cursor.fetchall()
        connection.close()
        return render_template('dashboard.html', parts=[dict(part) for part in parts], current_user=current_user)
    except mysql.connector.Error as e:
        logger.error(f"Database error fetching parts for dashboard: {e}")
        connection.close()
        return jsonify({'error': 'Database query error'}), 500

@app.route('/create_part')
@jwt_required()
def create_part():
    """Renders the create part page."""
    return render_template('create_part.html', current_user=get_jwt_identity())

if __name__ == '__main__':
    create_users_table()
    app.run(host="0.0.0.0", port=5000, debug=False)
