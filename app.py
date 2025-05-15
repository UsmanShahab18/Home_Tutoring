from flask import Flask, render_template, request, redirect, url_for, session
from flask_mysqldb import MySQL
from werkzeug.security import generate_password_hash, check_password_hash
import re

app = Flask(__name__)

# Secret key for session management
app.secret_key = 'your_secret_key_replace_with_a_strong_one' # **CHANGE THIS**

# Database configuration (replace with your XAMPP MySQL details)
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'     # Your MySQL username
app.config['MYSQL_PASSWORD'] = ''       # Your MySQL password (often empty for XAMPP root)
app.config['MYSQL_DB'] = 'home_tutoring'     # The database you created
app.config['MYSQL_CURSORCLASS'] = 'DictCursor' # To get results as dictionaries

mysql = MySQL(app)

# Route for the login page
@app.route('/', methods=['GET', 'POST']) # Make login the default page
@app.route('/login', methods=['GET', 'POST'])
def login():
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        # Get form data using the 'name' attributes from the HTML
        username = request.form['username']
        password = request.form['password']

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
            msg = 'Logged in successfully!'
            # Redirect to a dashboard or home page after successful login
            return render_template('index.html')

        else:
            # If account doesn't exist or password doesn't match
            msg = 'Incorrect username/password!'

    # Render the login template, passing the message
    return render_template('login.html', msg=msg)

# Route for the signup page
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    msg = ''
    # Check if "username", "password", and "email" POST requests exist (user submitted form)
    if request.method == 'POST' and 'full_name' in request.form and 'email' in request.form and 'password' in request.form and 'confirm_password' in request.form:
        # Get form data
        full_name = request.form['full_name']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        # Contact and Resume are also in the form, but handling them adds complexity
        contact = request.form.get('contact') # Use .get to avoid error if field is empty
        # For resume, request.files would be used, but handling file uploads is more involved

        # Basic validation and checks
        if password != confirm_password:
            msg = 'Passwords do not match!'
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            msg = 'Invalid email address!'
        elif not full_name or not email or not password:
            msg = 'Please fill out required fields (Full Name, Email, Password)!'
        else:
            cursor = mysql.connection.cursor()

            # For simplicity in this example, let's use the email as the username
            # If you want a separate username field, you'll need to add it to the HTML and table
            username = email # Using email as username for simplicity here

            # Check if account already exists using email (or username if you add it)
            cursor.execute('SELECT * FROM users WHERE username = %s OR email = %s', (username, email,))
            account = cursor.fetchone()

            if account:
                msg = 'Account already exists with that email or username!'
            else:
                # Hash the password
                hashed_password = generate_password_hash(password)

                # Insert the new user into the database
                # Modified INSERT statement to include full_name and email
                # Assuming 'username' column will store the email for simplicity
                cursor.execute('INSERT INTO users (username, password, email, full_name, contact) VALUES (%s, %s, %s, %s, %s)',
                            (username, hashed_password, email, full_name, contact))
                mysql.connection.commit()
                msg = 'You have successfully registered! You can now login.'
                # Redirect to the login page after successful registration
                return redirect(url_for('login'))

    elif request.method == 'POST':
        # If it's a POST request but required fields are missing
        msg = 'Please fill out all required fields!'

    # Render the signup template, passing the message
    return render_template('signup.html', msg=msg)

@app.route('/founder')
def founder():
    return render_template('founder.html')

@app.route('/index')
def index():
    return render_template('index.html')

@app.route('/aboutus')
def aboutus():
    return render_template('aboutus.html')

@app.route('/FAQs')
def FAQs():
    return render_template('FAQs.html')

@app.route('/OurTutors')
def OurTutors():
    return render_template('OurTutors.html')

# You'll also want a dashboard/home route for logged-in users
@app.route('/dashboard')
def dashboard():
    # Check if the user is logged in
    if 'loggedin' in session:
        # User is logged in, show the dashboard
        # Fetch user details from the database if needed for the dashboard
        cursor = mysql.connection.cursor()
        cursor.execute('SELECT full_name FROM users WHERE id = %s', (session['id'],))
        user_data = cursor.fetchone()
        full_name = user_data['full_name'] if user_data and 'full_name' in user_data else session['username'] # Display full name if available, otherwise username

        return render_template('dashboard.html', username=session['username'], full_name=full_name)
    else:
        # User is not logged in, redirect to login page
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    # Remove session data, effectively logging out the user
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('username', None)
    # Redirect to the login page
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)