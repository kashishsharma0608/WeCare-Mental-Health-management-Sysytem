from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import re
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Initialize database
def init_sqlite_db():
    try:
        conn = sqlite3.connect('users.db')
        print("Opened database successfully")
        conn.execute('PRAGMA foreign_keys = ON')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT, 
                username TEXT, 
                email TEXT, 
                password TEXT
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS moods (
                id INTEGER PRIMARY KEY AUTOINCREMENT,  
                user_id INTEGER,
                sleep_hours REAL,
                depressed_mood TEXT,
                elevated_mood TEXT,
                irritability TEXT,
                anxiety TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, 
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS journals (
                id INTEGER PRIMARY KEY AUTOINCREMENT, 
                user_id INTEGER, 
                entry TEXT, 
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, 
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        ''')
        print("Tables created successfully")
    except sqlite3.Error as e:
        print("Error initializing the database:", e)
    finally:
        conn.close()

init_sqlite_db()

# Validation functions

def validate_email(email):
    if not isinstance(email, str) or not email.strip():
        return False
    # Corrected re.match call with closing parenthesis
    return re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email) is not None
   

def validate_password(password):
    return len(password) >= 8 and re.search(r'\d', password) and re.search(r'[A-Z]', password)
# Meditation Audio Route
@app.route('/meditation')
def meditation():
    return render_template('meditation.html')

# Self-help Books Route
@app.route('/self_help_books')
def self_help_books():
    return render_template('self_help_books.html')



# Calming Audio Route
@app.route('/calming_audio')
def calming_audio():
    return render_template('calming_audio.html')

@app.route('/podcast')
def podcast():
    return render_template('podcast.html')  # Make sure you have this file created

@app.route('/music')
def music():
    return render_template('music.html')  # Make sure you have this file created


# Routes
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        # Validate inputs
        if not validate_email(email):
            flash("Invalid email format.", "danger")
            return redirect(url_for('signup'))
        if not validate_password(password):
            flash("Password must be at least 8 characters long, include a number, and an uppercase letter.", "danger")
            return redirect(url_for('signup'))

        hashed_password = generate_password_hash(password)

        try:
            with sqlite3.connect('users.db') as con:
                cur = con.cursor()
                cur.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                            (username, email, hashed_password))
                con.commit()
                flash("Signup successful! Please login.", "success")
                return redirect(url_for('login'))
        except sqlite3.Error as e:
            flash("Error occurred during signup. Please try again.", "danger")
            print("Error during signup:", e)

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        try:
            with sqlite3.connect('users.db') as con:
                cur = con.cursor()
                cur.execute("SELECT * FROM users WHERE email=?", (email,))
                user = cur.fetchone()

                if user and check_password_hash(user[3], password):
                    session['user'] = {'username': user[1], 'email': user[2], 'user_id': user[0]}
                    flash(f"Welcome, {user[1]}!", "success")
                    return redirect(url_for('index'))
                else:
                    flash("Invalid login credentials. Please try again.", "danger")
        except sqlite3.Error as e:
            flash("An error occurred. Please try again.", "danger")
            print("Error during login:", e)
    else:
            error_message = "Invalid email or password. Please try again."
            return render_template('login.html', error_message=error_message)
    return render_template('login.html')

@app.route('/')
def dashboard():
    if 'user' in session:
        return redirect(url_for('index'))
    return render_template('dashboard.html')

@app.route('/index')
def index():
    if 'user' in session:
        return render_template('index.html', username=session['user']['username'])
    else:
        flash("Please log in to access the dashboard.", "danger")
        return redirect(url_for('login'))

@app.route('/mood_tracker')
def mood_tracker():
    if 'user' not in session:
        flash("Please log in to track your mood.", "danger")
        return redirect(url_for('login'))

    return render_template('mood_tracker.html')

@app.route('/save_mood', methods=['POST'])
def save_mood():
    if 'user' not in session:
        return jsonify({"message": "User not logged in"}), 400

    mood_data = request.get_json()
    if mood_data:
        user_id = session['user']['user_id']
        try:
            conn = sqlite3.connect('users.db')
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO moods (user_id, sleep_hours, depressed_mood, elevated_mood, irritability, anxiety)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                user_id,
                mood_data.get('sleepHours'),
                mood_data.get('depressed'),
                mood_data.get('elevated'),
                mood_data.get('irritability'),
                mood_data.get('anxiety')
            ))
            conn.commit()
            return jsonify({"message": "Mood saved successfully"})
        except sqlite3.Error as e:
            return jsonify({"message": "Error saving mood: " + str(e)}), 500
        finally:
            conn.close()
    else:
        return jsonify({"message": "No data received"}), 400

@app.route('/journaling', methods=['GET', 'POST'])
def journaling():
    if 'user' not in session:
        flash("Please log in to access the journaling page.", "danger")
        return redirect(url_for('login'))

    user_id = session['user']['user_id']
    if request.method == 'POST':
        entry_text = request.form.get('entry')
        if entry_text:
            try:
                with sqlite3.connect('users.db') as con:
                    cur = con.cursor()
                    cur.execute("INSERT INTO journals (user_id, entry) VALUES (?, ?)", (user_id, entry_text))
                    con.commit()
                flash("Journal entry saved successfully!", "success")
            except sqlite3.Error as e:
                flash("Error saving journal entry. Please try again.", "danger")
                print("Error during journaling:", e)

    # Fetch journal entries
    try:
        with sqlite3.connect('users.db') as con:
            cur = con.cursor()
            cur.execute("SELECT entry, timestamp FROM journals WHERE user_id=? ORDER BY timestamp DESC", (user_id,))
            entries = cur.fetchall()
    except sqlite3.Error as e:
        flash("Error fetching journal entries.", "danger")
        entries = []

    return render_template('journaling.html', entries=entries)

@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))

# Other Routes
@app.route('/AboutUs')
def AboutUs():
    return render_template('AboutUs.html')

@app.route('/Profile', methods=['GET', 'POST'])
def Profile():
    if 'user' not in session:
        flash("Please log in to access your profile.", "danger")
        return redirect(url_for('login'))

    user = session['user']
    if request.method == 'POST':
        new_username = request.form.get('new_username')
        new_email = request.form.get('new_email')
        new_password = request.form.get('new_password')

       
        hashed_password = generate_password_hash(new_password) if new_password else user['password']

        try:
            with sqlite3.connect('users.db') as con:
                cur = con.cursor()
                cur.execute("UPDATE users SET username=?, email=?, password=? WHERE id=?",
                            (new_username, new_email, hashed_password, user['user_id']))
                con.commit()

            user['username'] = new_username
            user['email'] = new_email
            session['user'] = user
            flash("Profile updated successfully!", "success")
        except sqlite3.Error as e:
            flash("Error updating profile. Please try again.", "danger")
            print("Error during profile update:", e)

    return render_template('Profile.html', user=user)

if __name__ == '__main__':
    app.run(debug=True)
