from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_mysqldb import MySQL
from werkzeug.security import generate_password_hash, check_password_hash
import re
import logging
import os
import json
import MySQLdb # For catching OperationalError

app = Flask(__name__)

logging.basicConfig(level=logging.DEBUG)

app.secret_key = 'your_secret_key_replace_with_a_strong_one' # Replace with a strong, unique key

# --- Database Configuration ---
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'home_tutoring'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

mysql = MySQL(app)

# --- Admin Credentials (Hardcoded) ---
ADMIN_USERNAME = 'admin'
ADMIN_PASSWORD = 'admin' # In a real app, hash this or use a better auth method

# --- Fallback File Configuration ---
FALLBACK_DATA_FILE = 'users_fallback.json'

# --- Helper Functions for File I/O ---
def read_users_from_file():
    if not os.path.exists(FALLBACK_DATA_FILE):
        return []
    try:
        with open(FALLBACK_DATA_FILE, 'r') as f:
            data = json.load(f)
            return data if isinstance(data, list) else [] # Ensure it's a list
    except (IOError, json.JSONDecodeError) as e:
        app.logger.error(f"Error reading fallback file {FALLBACK_DATA_FILE}: {e}")
        return []

def write_users_to_file(users):
    try:
        with open(FALLBACK_DATA_FILE, 'w') as f:
            json.dump(users, f, indent=4)
    except IOError as e:
        app.logger.error(f"Error writing to fallback file {FALLBACK_DATA_FILE}: {e}")

def get_next_file_user_id(users):
    if not users:
        return 1
    # Ensure IDs are integers before finding max
    max_id = 0
    for user in users:
        user_id = user.get('id', 0)
        if isinstance(user_id, int) and user_id > max_id:
            max_id = user_id
    return max_id + 1

# --- Error Handlers ---
@app.errorhandler(Exception)
def handle_unexpected_error(error):
    app.logger.error(f"An unexpected error occurred: {error}", exc_info=True) # Log traceback
    return render_template('error.html', error_message="An unexpected error occurred. Please try again later."), 500

@app.errorhandler(404)
def page_not_found(error):
    app.logger.error(f"Page not found: {request.url}")
    return render_template('404.html', loggedin='loggedin' in session, is_admin=session.get('is_admin', False)), 404

# --- Routes ---
@app.route('/')
def index():
    return render_template('index.html', loggedin='loggedin' in session, is_admin=session.get('is_admin', False))

@app.route('/login', methods=['GET', 'POST'])
def login():
    msg = {}
    if 'loggedin' in session:
        return redirect(url_for('admin_dashboard')) if session.get('is_admin') else redirect(url_for('index'))

    if request.method == 'POST':
        form_type = request.form.get('form_type')
        
        if form_type == 'user':
            username = request.form.get('user_username')
            password = request.form.get('user_password')
            if not username or not password:
                msg['user'] = 'Username and password are required!'
            else:
                try:
                    cursor = mysql.connection.cursor()
                    cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
                    account = cursor.fetchone()
                    cursor.close()
                    db_operational = True
                except MySQLdb.OperationalError as e:
                    app.logger.warning(f"Database error during user login: {e}. Attempting file fallback.")
                    db_operational = False
                    account = None
                    users_fallback = read_users_from_file()
                    for user_in_file in users_fallback:
                        if user_in_file.get('username') == username:
                            account = user_in_file # Mimic account structure
                            break
                except Exception as e:
                    app.logger.error(f"Unexpected error during user login: {e}")
                    msg['user'] = 'An error occurred during login. Please try again.'
                    account = None # Ensure account is None to prevent further processing

                if account and 'password' in account and check_password_hash(account['password'], password):
                    session['loggedin'] = True
                    session['id'] = account['id'] # This ID might be from file or DB
                    session['username'] = account['username']
                    session['is_admin'] = False
                    flash_msg = 'Logged in successfully!'
                    if not db_operational:
                        flash_msg += ' (using fallback data)'
                    flash(flash_msg, 'success')
                    return redirect(url_for('index'))
                else:
                    msg['user'] = 'Incorrect username or password!'
        
        elif form_type == 'admin':
            admin_username = request.form.get('admin_username')
            admin_password = request.form.get('admin_password')
            if not admin_username or not admin_password:
                msg['admin'] = 'Admin username and password are required!'
            elif admin_username == ADMIN_USERNAME and admin_password == ADMIN_PASSWORD: # Simple admin check
                session['loggedin'] = True
                session['username'] = admin_username
                session['is_admin'] = True
                flash('Admin login successful!', 'success')
                return redirect(url_for('admin_dashboard'))
            else:
                msg['admin'] = 'Incorrect admin username or password!'
        else:
            flash('Invalid login attempt.', 'danger')

    return render_template('login.html', msg=msg, loggedin='loggedin' in session, is_admin=session.get('is_admin', False))


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if 'loggedin' in session:
        return redirect(url_for('index'))

    if request.method == 'POST':
        full_name = request.form.get('full_name')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        contact = request.form.get('contact')

        if not all([full_name, email, password, confirm_password]):
            return jsonify({'status': 'error', 'message': 'Please fill out all required fields!'}), 400
        if password != confirm_password:
            return jsonify({'status': 'error', 'message': 'Passwords do not match!'}), 400
        if not re.match(r'[^@]+@[^@]+\.[^@]+', email): # Simple email regex
            return jsonify({'status': 'error', 'message': 'Invalid email address!'}), 400
        
        username = email # Using email as username
        
        try:
            cursor = mysql.connection.cursor()
            cursor.execute('SELECT * FROM users WHERE username = %s OR email = %s', (username, email,))
            account = cursor.fetchone()
            cursor.close()
            db_operational = True
        except MySQLdb.OperationalError as e:
            app.logger.warning(f"Database error during signup check: {e}. Using file fallback.")
            db_operational = False
            account = None
            users_fallback = read_users_from_file()
            for user_in_file in users_fallback:
                if user_in_file.get('username') == username or user_in_file.get('email') == email:
                    account = user_in_file
                    break
        except Exception as e:
            app.logger.error(f"Unexpected error during signup check: {e}")
            return jsonify({'status': 'error', 'message': 'An error occurred checking user existence.'}), 500


        if account:
            return jsonify({'status': 'error', 'message': 'Account already exists with that email or username!'}), 409
        else:
            hashed_password = generate_password_hash(password)
            if db_operational:
                try:
                    cursor = mysql.connection.cursor()
                    cursor.execute('INSERT INTO users (username, password, email, full_name, contact) VALUES (%s, %s, %s, %s, %s)',
                                   (username, hashed_password, email, full_name, contact))
                    mysql.connection.commit()
                    cursor.close()
                    return jsonify({'status': 'success', 'message': 'You have successfully registered! Redirecting to login...'}), 200
                except MySQLdb.OperationalError as e: # DB went down between check and insert
                    app.logger.error(f"Database error on signup insert after check: {e}. Attempting file write.")
                    db_operational = False # Explicitly set for the next block
                except Exception as e:
                    app.logger.error(f"Signup DB insert error: {e}")
                    mysql.connection.rollback()
                    if 'cursor' in locals() and cursor: cursor.close()
                    return jsonify({'status': 'error', 'message': 'An error occurred during registration in DB.'}), 500
            
            # Fallback to file if db_operational is False (either from initial check or failed insert)
            if not db_operational:
                users = read_users_from_file()
                new_user_id = get_next_file_user_id(users)
                new_user_data = {
                    'id': new_user_id, 
                    'username': username, 
                    'password': hashed_password, 
                    'email': email, 
                    'full_name': full_name, 
                    'contact': contact,
                    'is_offline_record': True # Mark as offline record
                }
                users.append(new_user_data)
                write_users_to_file(users)
                app.logger.info(f"User {username} registered to fallback file.")
                return jsonify({'status': 'success', 'message': 'Registered to fallback storage! Redirecting to login...'}), 200

    return render_template('signup.html', loggedin='loggedin' in session, is_admin=session.get('is_admin', False))


@app.route('/admin_dashboard')
def admin_dashboard():
    if not ('loggedin' in session and session.get('is_admin')):
        flash('Please log in as an admin to access this page.', 'warning')
        return redirect(url_for('login'))
    
    all_users = []
    db_error_message = None
    try:
        cursor = mysql.connection.cursor()
        cursor.execute('SELECT id, username, email, full_name, contact FROM users')
        all_users = cursor.fetchall()
        cursor.close()
    except MySQLdb.OperationalError as e:
        app.logger.warning(f"Admin dashboard DB error: {e}. Using file fallback.")
        all_users = read_users_from_file()
        # Optionally, filter out hashed passwords for display if they were stored
        for user in all_users:
            user.pop('password', None) 
        db_error_message = 'Database is currently unavailable. Showing data from local fallback. Some features might be limited.'
    except Exception as e:
        app.logger.error(f"Admin dashboard unexpected error: {e}")
        flash('Could not retrieve user data due to an unexpected error.', 'danger')
        # Render with empty users or handle differently
        return render_template('admin_dashboard.html', users=[], loggedin=True, is_admin=True, db_error_message="Error retrieving data.")

    if db_error_message:
        flash(db_error_message, 'warning')
    return render_template('admin_dashboard.html', users=all_users, loggedin=True, is_admin=True)


@app.route('/edit_user/<int:user_id>')
def edit_user(user_id):
    if not ('loggedin' in session and session.get('is_admin')):
        flash('Please log in as an admin to access this page.', 'warning')
        return redirect(url_for('login'))
    
    user_to_edit = None
    db_error_message = None
    try:
        cursor = mysql.connection.cursor()
        cursor.execute('SELECT id, username, email, full_name, contact FROM users WHERE id = %s', (user_id,))
        user_to_edit = cursor.fetchone()
        cursor.close()
    except MySQLdb.OperationalError as e:
        app.logger.warning(f"DB error fetching user for edit (ID: {user_id}): {e}. Using file fallback.")
        users_fallback = read_users_from_file()
        user_to_edit = next((u for u in users_fallback if u.get('id') == user_id), None)
        if user_to_edit:
            user_to_edit.pop('password', None) # Don't send password to template
            db_error_message = 'Database is unavailable. Editing data from local fallback.'
        else:
            flash('User not found in local fallback data.', 'danger')
            return redirect(url_for('admin_dashboard'))
    except Exception as e:
        app.logger.error(f"Error fetching user for edit (ID: {user_id}): {e}")
        flash('An error occurred while trying to fetch user data.', 'danger')
        return redirect(url_for('admin_dashboard'))

    if user_to_edit:
        if db_error_message: flash(db_error_message, 'warning')
        return render_template('edit_user.html', user=user_to_edit, loggedin=True, is_admin=True)
    else:
        flash('User not found.', 'danger')
        return redirect(url_for('admin_dashboard'))


@app.route('/update_user/<int:user_id>', methods=['POST'])
def update_user(user_id):
    if not ('loggedin' in session and session.get('is_admin')):
        flash('Please log in as an admin to perform this action.', 'warning')
        return redirect(url_for('login'))

    email = request.form.get('email')
    full_name = request.form.get('full_name')
    contact = request.form.get('contact')

    if not all([email, full_name]): # Contact can be optional
        flash('Email and Full Name are required.', 'danger')
        return redirect(url_for('edit_user', user_id=user_id))
    if not re.match(r'[^@]+@[^@]+\.[^@]+', email):
        flash('Invalid email address format.', 'danger')
        return redirect(url_for('edit_user', user_id=user_id))

    try:
        cursor = mysql.connection.cursor()
        # Check if email is being changed to one that already exists (excluding current user)
        cursor.execute("SELECT id FROM users WHERE email = %s AND id != %s", (email, user_id))
        existing_email_user = cursor.fetchone()
        if existing_email_user:
            flash('Email already registered to another user.', 'danger')
            cursor.close()
            return redirect(url_for('edit_user', user_id=user_id))

        cursor.execute('UPDATE users SET email = %s, full_name = %s, contact = %s, username = %s WHERE id = %s',
                       (email, full_name, contact, email, user_id)) # Assuming username is also email
        mysql.connection.commit()
        cursor.close()
        flash('User updated successfully in database!', 'success')
    except MySQLdb.OperationalError as e:
        app.logger.warning(f"DB error updating user (ID: {user_id}): {e}. Using file fallback.")
        users = read_users_from_file()
        user_found_in_file = False
        for i, user in enumerate(users):
            if user.get('id') == user_id:
                # Check for email conflict in file data (excluding current user)
                for other_user in users:
                    if other_user.get('email') == email and other_user.get('id') != user_id:
                        flash(f'Email "{email}" already exists in fallback data for another user.', 'danger')
                        return redirect(url_for('edit_user', user_id=user_id))
                
                users[i]['email'] = email
                users[i]['username'] = email # Keep username and email same
                users[i]['full_name'] = full_name
                users[i]['contact'] = contact
                users[i]['is_offline_record'] = True # Mark or re-mark as offline/modified offline
                user_found_in_file = True
                break
        if user_found_in_file:
            write_users_to_file(users)
            flash('User updated successfully in local fallback data!', 'success')
        else:
            flash('User not found in local fallback data for update.', 'danger')
            return redirect(url_for('admin_dashboard')) # Or back to edit page

    except Exception as e:
        app.logger.error(f"Error updating user (ID: {user_id}): {e}")
        if 'mysql' in locals() and mysql.connection: # Check if connection object exists
             try:
                mysql.connection.rollback()
             except Exception as rb_err:
                app.logger.error(f"Rollback failed: {rb_err}")

        flash('An error occurred while updating the user. Please try again.', 'danger')
    finally:
        if 'cursor' in locals() and cursor and not cursor.closed:
             try:
                cursor.close()
             except Exception as c_err:
                app.logger.error(f"Cursor close failed: {c_err}")
            
    return redirect(url_for('admin_dashboard'))


@app.route('/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if not ('loggedin' in session and session.get('is_admin')):
        return jsonify({'status': 'error', 'message': 'Unauthorized: Please log in as an admin.'}), 401
    
    try:
        cursor = mysql.connection.cursor()
        cursor.execute('DELETE FROM users WHERE id = %s', (user_id,))
        mysql.connection.commit()
        cursor.close()
        return jsonify({'status': 'success', 'message': f'User {user_id} deleted successfully from database!'}), 200
    except MySQLdb.OperationalError as e:
        app.logger.warning(f"DB error deleting user (ID: {user_id}): {e}. Operation unavailable offline.")
        return jsonify({'status': 'error', 'message': 'Database is offline. Delete operation is not available for fallback data.'}), 503 # Service Unavailable
    except Exception as e:
        app.logger.error(f"Error deleting user (ID: {user_id}): {e}")
        if 'mysql' in locals() and mysql.connection: mysql.connection.rollback()
        if 'cursor' in locals() and cursor and not cursor.closed: cursor.close()
        return jsonify({'status': 'error', 'message': 'An error occurred while deleting the user.'}), 500


# --- Static Page Routes ---
@app.route('/aboutus')
def aboutus():
    return render_template('aboutus.html', loggedin='loggedin' in session, is_admin=session.get('is_admin', False))

@app.route('/FAQs')
def FAQs():
    return render_template('FAQs.html', loggedin='loggedin' in session, is_admin=session.get('is_admin', False))

@app.route('/founder')
def founder():
    return render_template('founder.html', loggedin='loggedin' in session, is_admin=session.get('is_admin', False))

@app.route('/OurTutors')
def OurTutors():
    return render_template('OurTutors.html', loggedin='loggedin' in session, is_admin=session.get('is_admin', False))


# --- Logout ---
@app.route('/logout')
def logout():
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('username', None)
    session.pop('is_admin', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))


if __name__ == '__main__':
    # Ensure fallback file exists or create it as an empty list
    if not os.path.exists(FALLBACK_DATA_FILE):
        write_users_to_file([])
    app.run(debug=True, host='0.0.0.0')