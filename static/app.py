from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify # Added jsonify
from flask_mysqldb import MySQL
from werkzeug.security import generate_password_hash, check_password_hash
import re
import logging

app = Flask(__name__)

logging.basicConfig(level=logging.DEBUG)

app.secret_key = 'your_secret_key_replace_with_a_strong_one'

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'home_tutoring'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

mysql = MySQL(app)

ADMIN_USERNAME = 'admin'
ADMIN_PASSWORD = 'admin'

@app.errorhandler(Exception)
def handle_unexpected_error(error):
    app.logger.error(f"An unexpected error occurred: {error}")
    return render_template('error.html', error_message="An unexpected error occurred. Please try again later."), 500

@app.errorhandler(404)
def page_not_found(error):
    app.logger.error(f"Page not found: {request.url}")
    return render_template('404.html', loggedin='loggedin' in session, is_admin=session.get('is_admin', False)), 404

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
        try:
            if form_type == 'user':
                username = request.form.get('user_username')
                password = request.form.get('user_password')
                if not username or not password:
                    msg['user'] = 'Username and password are required!'
                else:
                    cursor = mysql.connection.cursor()
                    cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
                    account = cursor.fetchone()
                    cursor.close()

                    if account and check_password_hash(account['password'], password):
                        session['loggedin'] = True
                        session['id'] = account['id']
                        session['username'] = account['username']
                        session['is_admin'] = False
                        flash('Logged in successfully!', 'success')
                        return redirect(url_for('index'))
                    else:
                        msg['user'] = 'Incorrect username or password!'
            
            elif form_type == 'admin':
                admin_username = request.form.get('admin_username')
                admin_password = request.form.get('admin_password')
                if not admin_username or not admin_password:
                    msg['admin'] = 'Admin username and password are required!'
                elif admin_username == ADMIN_USERNAME and admin_password == ADMIN_PASSWORD:
                    session['loggedin'] = True
                    session['username'] = admin_username
                    session['is_admin'] = True
                    flash('Admin login successful!', 'success')
                    return redirect(url_for('admin_dashboard'))
                else:
                    msg['admin'] = 'Incorrect admin username or password!'
            else:
                flash('Invalid login attempt.', 'danger')

        except Exception as e:
            app.logger.error(f"Login error: {e}")
            if form_type == 'user':
                msg['user'] = 'An error occurred during login. Please try again.'
            elif form_type == 'admin':
                msg['admin'] = 'An error occurred during admin login. Please try again.'
            else:
                flash('An unexpected error occurred. Please try again.', 'danger')

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
        elif password != confirm_password:
            return jsonify({'status': 'error', 'message': 'Passwords do not match!'}), 400
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            return jsonify({'status': 'error', 'message': 'Invalid email address!'}), 400
        else:
            try:
                username = email
                cursor = mysql.connection.cursor()
                cursor.execute('SELECT * FROM users WHERE username = %s OR email = %s', (username, email,))
                account = cursor.fetchone()
                
                if account:
                    return jsonify({'status': 'error', 'message': 'Account already exists with that email or username!'}), 409
                else:
                    hashed_password = generate_password_hash(password)
                    cursor.execute('INSERT INTO users (username, password, email, full_name, contact) VALUES (%s, %s, %s, %s, %s)',
                                   (username, hashed_password, email, full_name, contact))
                    mysql.connection.commit()
                    return jsonify({'status': 'success', 'message': 'You have successfully registered! Redirecting to login...'}), 200
            
            except Exception as e:
                app.logger.error(f"Signup error: {e}")
                mysql.connection.rollback()
                return jsonify({'status': 'error', 'message': 'An error occurred during registration. Please try again.'}), 500
            finally:
                if 'cursor' in locals() and cursor:
                    cursor.close()

    return render_template('signup.html', loggedin='loggedin' in session, is_admin=session.get('is_admin', False))


@app.route('/admin_dashboard')
def admin_dashboard():
    if not ('loggedin' in session and session.get('is_admin')):
        flash('Please log in as an admin to access this page.', 'warning')
        return redirect(url_for('login'))
    
    try:
        cursor = mysql.connection.cursor()
        cursor.execute('SELECT id, username, email, full_name, contact FROM users')
        all_users = cursor.fetchall()
        cursor.close()
        return render_template('admin_dashboard.html', users=all_users, loggedin=True, is_admin=True)
    except Exception as e:
        app.logger.error(f"Admin dashboard error: {e}")
        flash('Could not retrieve user data. Please try again.', 'danger')
        return render_template('admin_dashboard.html', users=[], loggedin=True, is_admin=True)


@app.route('/edit_user/<int:user_id>')
def edit_user(user_id):
    if not ('loggedin' in session and session.get('is_admin')):
        flash('Please log in as an admin to access this page.', 'warning')
        return redirect(url_for('login'))
    
    try:
        cursor = mysql.connection.cursor()
        cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))
        user_to_edit = cursor.fetchone()
        cursor.close()
        
        if user_to_edit:
            return render_template('edit_user.html', user=user_to_edit, loggedin=True, is_admin=True)
        else:
            flash('User not found.', 'danger')
            return redirect(url_for('admin_dashboard'))
    except Exception as e:
        app.logger.error(f"Error fetching user for edit (ID: {user_id}): {e}")
        flash('An error occurred while trying to fetch user data.', 'danger')
        return redirect(url_for('admin_dashboard'))


@app.route('/update_user/<int:user_id>', methods=['POST'])
def update_user(user_id):
    if not ('loggedin' in session and session.get('is_admin')):
        flash('Please log in as an admin to perform this action.', 'warning')
        return redirect(url_for('login'))

    email = request.form.get('email')
    full_name = request.form.get('full_name')
    contact = request.form.get('contact')

    if not all([email, full_name]):
        flash('Email and Full Name are required.', 'danger')
        return redirect(url_for('edit_user', user_id=user_id))
    if not re.match(r'[^@]+@[^@]+\.[^@]+', email):
        flash('Invalid email address format.', 'danger')
        return redirect(url_for('edit_user', user_id=user_id))

    try:
        cursor = mysql.connection.cursor()
        cursor.execute('UPDATE users SET email = %s, full_name = %s, contact = %s WHERE id = %s',
                       (email, full_name, contact, user_id))
        mysql.connection.commit()
        flash('User updated successfully!', 'success')
    except Exception as e:
        app.logger.error(f"Error updating user (ID: {user_id}): {e}")
        mysql.connection.rollback()
        flash('An error occurred while updating the user. Please try again.', 'danger')
    finally:
        if 'cursor' in locals() and cursor:
            cursor.close()
            
    return redirect(url_for('admin_dashboard'))


@app.route('/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if not ('loggedin' in session and session.get('is_admin')):
        # For AJAX requests, return JSON error
        if request.is_xhr: # Check if it's an AJAX request
            return jsonify({'status': 'error', 'message': 'Unauthorized: Please log in as an admin.'}), 401
        flash('Please log in as an admin to perform this action.', 'warning')
        return redirect(url_for('login'))
    
    try:
        cursor = mysql.connection.cursor()
        cursor.execute('DELETE FROM users WHERE id = %s', (user_id,))
        mysql.connection.commit()
        # Return JSON success for AJAX
        return jsonify({'status': 'success', 'message': f'User {user_id} deleted successfully!'}), 200
    except Exception as e:
        app.logger.error(f"Error deleting user (ID: {user_id}): {e}")
        mysql.connection.rollback()
        # Return JSON error for AJAX
        return jsonify({'status': 'error', 'message': 'An error occurred while deleting the user.'}), 500
    finally:
        if 'cursor' in locals() and cursor:
            cursor.close()
            

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
    app.run(debug=True, host='0.0.0.0')
