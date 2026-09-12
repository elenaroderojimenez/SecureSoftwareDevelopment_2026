
import os
import sqlite3
import bcrypt
from functools import wraps
from flask import Flask, request, redirect, url_for, session, render_template_string, flash, send_from_directory
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = os.urandom(24) 

UPLOAD_FOLDER = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 8 * 1024 * 1024  
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
DB_NAME = "users_assig2.db"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash BLOB NOT NULL,
            salt BLOB NOT NULL,
            role TEXT NOT NULL DEFAULT 'user'
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            owner TEXT NOT NULL,
            uploaded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(owner) REFERENCES users(username)
        )
    ''')
    conn.commit()
    conn.close()

init_db()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            flash("Access denied. Please log in.")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


HTML_LOGIN = """
<!doctype html>
<title>Secure Login</title>
<h2>Login</h2>
{% for message in get_flashed_messages() %}
  <p style="color: red;">{{ message }}</p>
{% endfor %}
<form method="post">
  Username: <input type="text" name="username" required><br><br>
  Password: <input type="password" name="password" required><br><br>
  <input type="submit" value="Login">
</form>
<p>No account? <a href="/register">Register here</a></p>
"""

HTML_REGISTER = """
<!doctype html>
<title>Register</title>
<h2>Register New User</h2>
{% for message in get_flashed_messages() %}
  <p style="color: red;">{{ message }}</p>
{% endfor %}
<form method="post">
  Username: <input type="text" name="username" required><br><br>
  Password: <input type="password" name="password" required><br><br>
  <input type="submit" value="Register">
</form>
<p><a href="/login">Back to Login</a></p>
"""

HTML_UPLOAD = """
<!doctype html>
<title>Secure File Upload</title>
<style>
  /* Ocultamos el input original del navegador */
  input[type="file"] {
    display: none;
  }
  /* Damos estilo al label para que parezca un botón */
  .custom-file-upload {
    border: 1px solid #777;
    display: inline-block;
    padding: 6px 12px;
    cursor: pointer;
    background-color: #e0e0e0;
    font-family: Arial, sans-serif;
    font-size: 14px;
    border-radius: 4px;
  }
  .custom-file-upload:hover {
    background-color: #d0d0d0;
  }
</style>

<h2>File Dashboard</h2>
<p>User: <b>{{ session['username'] }}</b> | <a href="/logout">Logout</a></p>

{% for message in get_flashed_messages() %}
  <p style="color: blue;">{{ message }}</p>
{% endfor %}

<form method="post" enctype="multipart/form-data">
  <!-- Botón personalizado en inglés -->
  <label class="custom-file-upload">
    <input type="file" name="file" required onchange="document.getElementById('file-chosen').textContent = this.files[0].name">
    Browse File
  </label>
  <span id="file-chosen" style="margin-left: 10px;">No file chosen</span>
  <br><br>
  <input type="submit" value="Upload File">
</form>

<h3>Available Files:</h3>
<ul>
{% for file in files %}
  <li><a href="{{ url_for('download_file', filename=file) }}">{{ file }}</a></li>
{% else %}
  <li>No files uploaded.</li>
{% endfor %}
</ul>
"""


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        
        cursor.execute('SELECT username FROM users WHERE username = ?', (username,))
        if cursor.fetchone():
            flash("Error: Username already exists.")
            conn.close()
            return redirect(url_for('register'))

        salt = bcrypt.gensalt()
        password_hash = bcrypt.hashpw(password.encode('utf-8'), salt)

        cursor.execute('''
            INSERT INTO users (username, password_hash, salt)
            VALUES (?, ?, ?)
        ''', (username, password_hash, salt))
        conn.commit()
        conn.close()
        
        flash("Registration Successful! Please log in.")
        return redirect(url_for('login'))
        
    return render_template_string(HTML_REGISTER)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute('SELECT password_hash FROM users WHERE username = ?', (username,))
        record = cursor.fetchone()
        conn.close()

        if record:
            stored_hash = record[0] 
            if bcrypt.checkpw(password.encode('utf-8'), stored_hash):
                session['logged_in'] = True
                session['username'] = username
                return redirect(url_for('upload_file'))
        
        flash("Invalid credentials.")
            
    return render_template_string(HTML_LOGIN)

@app.route('/logout')
def logout():
    session.clear()
    flash("Successfully logged out.")
    return redirect(url_for('login'))

@app.route('/', methods=['GET', 'POST'])
@login_required
def upload_file():
    if request.method == 'POST':
        file = request.files.get('file')
        
        if not file or file.filename == '':
            flash('No file selected.')
            return redirect(request.url)
            
        if allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            
            conn = sqlite3.connect(DB_NAME)
            cursor = conn.cursor()
            cursor.execute('INSERT INTO files (filename, owner) VALUES (?, ?)', (filename, session['username']))
            conn.commit()
            conn.close()

            flash(f'File "{filename}" uploaded successfully.')
        else:
            flash('File type not allowed.')
            
        return redirect(request.url)

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT filename FROM files WHERE owner = ?', (session['username'],))
    user_files = [row[0] for row in cursor.fetchall()]
    conn.close()
    
    return render_template_string(HTML_UPLOAD, files=user_files)


@app.route('/download/<filename>')
@login_required
def download_file(filename):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM files WHERE filename = ? AND owner = ?', (filename, session['username']))
    record = cursor.fetchone()
    conn.close()
    
    if record:
        return send_from_directory(app.config['UPLOAD_FOLDER'], secure_filename(filename))
    else:
        flash("Unauthorized: You do not have permission to access this file.")
        return redirect(url_for('upload_file'))
    


if __name__ == '__main__':
    app.run(debug=True)