from flask import Flask, render_template, request, redirect, url_for, session
from flask_mysqldb import MySQL
from werkzeug.security import generate_password_hash, check_password_hash
import re

app = Flask(__name__)

# Secret key for session management
app.secret_key = 'your_secret_key_replace_with_a_strong_one' # **CHANGE THIS**

# Database configuration (replace with your XAMPP or Clever Cloud MySQL details)
# Use your Clever Cloud details here if deploying there
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'     # Your MySQL username
app.config['MYSQL_PASSWORD'] = ''       # Your MySQL password (often empty for XAMPP root)
app.config['MYSQL_DB'] = 'home_tutoring' # The database you created
app.config['MYSQL_CURSORCLASS'] = 'DictCursor' # To get results as dictionaries

mysql = MySQL(app)

# Define hardcoded admin credentials (replace with a secure method in production)
ADMIN_USERNAME = 'admin'
ADMIN_PASSWORD = 'admin' # **CHANGE THIS IN PRODUCTION**

# Route for the index page (this will now be the default page at '/')
@app.route('/')
def index():
    # Pass login status and admin status to the template for conditional display
    return render_template('index.html', loggedin='loggedin' in session, is_admin=session.get('is_admin', False))


# Route for the login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    msg = {} # Initialize msg as a dictionary to hold messages for different forms

    # If user is already logged in, redirect them to the appropriate page
    if 'loggedin' in session:
        if session.get('is_admin'):
            return redirect(url_for('admin_dashboard')) # Redirect admin to admin dashboard
        else:
            return redirect(url_for('index')) # Redirect regular user to index

    if request.method == 'POST':
        form_type = request.form.get('form_type') # Get the form type from the hidden input

        if form_type == 'user':
            # Process User Login
            username = request.form.get('user_username')
            password = request.form.get('user_password')

            cursor = mysql.connection.cursor()
            # Retrieve the user from the database by username
            cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
            account = cursor.fetchone()

            # Check if account exists and password matches (after hashing check)
            if account and check_password_hash(account['password'], password):
                # If account exists and password matches
                session['loggedin'] = True
                session['id'] = account['id']
                session['username'] = account['username']
                session['is_admin'] = False # Mark as not admin
                # Redirect user to index page
                return redirect(url_for('index'))
            else:
                msg['user'] = 'Incorrect username/password!' # Add message to user key

        elif form_type == 'admin':
            # Process Admin Login
            admin_username = request.form.get('admin_username')
            admin_password = request.form.get('admin_password')

            # Authenticate against hardcoded admin credentials
            if admin_username == ADMIN_USERNAME and admin_password == ADMIN_PASSWORD:
                 session['loggedin'] = True
                 session['username'] = admin_username # Store admin username in session
                 session['is_admin'] = True # Mark as admin in session
                 # Redirect admin to admin dashboard
                 return redirect(url_for('admin_dashboard')) # Redirect to the new admin dashboard route

            else:
                msg['admin'] = 'Incorrect admin username/password!' # Add message to admin key

    # Render the login template, passing the message dictionary
    return render_template('login.html', msg=msg)


# Route for the signup page
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    msg = ''
     # If user is already logged in, redirect them to the index page
    if 'loggedin' in session:
        return redirect(url_for('index'))

    # Check if "username", "password", and "email" POST requests exist (user submitted form)
    if request.method == 'POST' and 'full_name' in request.form and 'email' in request.form and 'password' in request.form and 'confirm_password' in request.form:
        # Get form data
        full_name = request.form['full_name']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form.get('confirm_password') # Use .get for optional fields
        contact = request.form.get('contact')
        # Removed retrieval of academic_level and subjects_of_interest

        # Basic validation and checks
        if password != confirm_password:
            msg = 'Passwords do not match!'
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            msg = 'Invalid email address!'
        elif not full_name or not email or not password:
             msg = 'Please fill out required fields (Full Name, Email, Password)!'
        else:
            cursor = mysql.connection.cursor()

            # Using email as username as per your previous signup logic
            username = email

            # Check if account already exists using email (or username if you add it)
            cursor.execute('SELECT * FROM users WHERE username = %s OR email = %s', (username, email,))
            account = cursor.fetchone()

            if account:
                msg = 'Account already exists with that email or username!'
            else:
                # Hash the password
                hashed_password = generate_password_hash(password)

                # Insert the new user into the database
                # Modified INSERT statement to exclude academic_level and subjects_of_interest
                cursor.execute('INSERT INTO users (username, password, email, full_name, contact) VALUES (%s, %s, %s, %s, %s)',
                               (username, hashed_password, email, full_name, contact))

                mysql.connection.commit()
                msg = 'You have successfully registered! You can now login.'
                # Redirect to the login page after successful registration
                return redirect(url_for('login'))

    elif request.method == 'POST':
        msg = 'Please fill out all required fields!'

    # Render the signup template, passing the message
    return render_template('signup.html', msg=msg)


# Route for the Admin Dashboard (shows all user data)
@app.route('/admin_dashboard')
def admin_dashboard():
    # Check if the user is logged in AND is an admin
    if 'loggedin' in session and session.get('is_admin'):
        cursor = mysql.connection.cursor()
        # Fetch ALL user data from the database for the admin view
        # This query selects the columns you have in your table
        cursor.execute('SELECT id, username, email, full_name, contact FROM users')
        all_users = cursor.fetchall()

        # Render the admin_dashboard.html template, passing the list of all users
        return render_template('admin_dashboard.html', users=all_users, loggedin=True, is_admin=True)
    else:
        # User is not logged in or is not an admin, redirect to login
        return redirect(url_for('login'))


# Route to display the form to edit a user
@app.route('/edit_user/<int:user_id>')
def edit_user(user_id):
    # Check if logged in and is admin
    if 'loggedin' in session and session.get('is_admin'):
        cursor = mysql.connection.cursor()
        # Fetch user data by user_id
        cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))
        user_to_edit = cursor.fetchone()

        if user_to_edit:
            # Render an edit template (edit_user.html)
            return render_template('edit_user.html', user=user_to_edit, loggedin=True, is_admin=True)
        else:
            # User not found, redirect to admin dashboard with a message
            # You might want to add flash messages here
            return redirect(url_for('admin_dashboard'))
    else:
        # Not authorized, redirect to login
        return redirect(url_for('login'))

# Route to handle the update of user data
@app.route('/update_user/<int:user_id>', methods=['POST'])
def update_user(user_id):
    # Check if logged in and is admin
    if 'loggedin' in session and session.get('is_admin'):
        # Get data from the form
        email = request.form.get('email')
        full_name = request.form.get('full_name')
        contact = request.form.get('contact')
        # Get data from academic_level and subjects_of_interest if those fields are in your edit form
        # academic_level = request.form.get('academic_level') # Removed retrieval
        # subjects_of_interest = request.form.get('subjects_of_interest') # Removed retrieval

        cursor = mysql.connection.cursor()

        # Update the user in the database
        # Corrected UPDATE query to only include email, full_name, and contact
        try:
            cursor.execute('UPDATE users SET email = %s, full_name = %s, contact = %s WHERE id = %s',
                           (email, full_name, contact, user_id))
            mysql.connection.commit()
            # Redirect back to admin dashboard after successful update
            # You might want to add a flash message indicating success
            return redirect(url_for('admin_dashboard'))
        except Exception as e:
            # Handle potential errors during update
            print(f"Error updating user: {e}")
            # Redirect back to the edit page or admin dashboard with an error message
            # You might want to add flash messages here
            return redirect(url_for('edit_user', user_id=user_id)) # Redirect back to edit page on error

    else:
        # Not authorized, redirect to login
        return redirect(url_for('login'))


# Route to handle the deletion of a user
@app.route('/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    # Check if logged in and is admin
    if 'loggedin' in session and session.get('is_admin'):
        cursor = mysql.connection.cursor()
        try:
            cursor.execute('DELETE FROM users WHERE id = %s', (user_id,))
            mysql.connection.commit()
            # Redirect back to admin dashboard after deletion
            # You might want to add a flash message indicating success
            return redirect(url_for('admin_dashboard'))
        except Exception as e:
            # Handle potential errors (e.g., user not found)
            print(f"Error deleting user: {e}")
            # Redirect back with an error message if needed
            # You might want to add flash messages here
            return redirect(url_for('admin_dashboard'))
    else:
        # Not authorized, redirect to login
        return redirect(url_for('login'))


# Routes for other static pages (ensure these pass loggedin and is_admin status)
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


@app.route('/logout')
def logout():
    # Remove session data, effectively logging out the user
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('username', None)
    session.pop('is_admin', None) # Remove admin status from session
    # Redirect to the index page after logging out
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
