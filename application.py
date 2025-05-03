from datetime import timedelta
import os
import re
# import time
import logging
from tracemalloc import start
import mysql.connector
from mysql.connector import Error
from flask import Flask, request, redirect, url_for, render_template, send_from_directory, flash, session, send_file, abort
from werkzeug.utils import secure_filename
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
# from markupsafe import escape

# Import your modules
from Encrypt import HybridCryptKeys, Segment, encrypt_file
from Decrypt import HybridDeCryptKeys, DAES, DBlowFish, DTrippleDES, DIDEA, DFernet
import merge

# Configurations
UPLOAD_FOLDER = os.path.abspath('.')
SEGMENTS_FOLDER = 'Segments'
DOWNLOAD_FOLDER = 'downloads'
ACCESS_LIST = 'access_list.txt'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'} 

app = Flask(__name__, template_folder='template')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config["CACHE_TYPE"] = "null"
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'fallback-dev-key')
app.permanent_session_lifetime = timedelta(minutes=30)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Limit to 16 MB

app.logger.addHandler(logging.FileHandler('app.log'))

# Database connection
def get_db():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="root",
        database="tybca"
    )

# Login management
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, id, username, email):
        self.id = id
        self.username = username
        self.email = email

@login_manager.user_loader
def load_user(user_id):
    try:
        conn = get_db()
        cursor = conn.cursor(dictionary=True)
        cursor.execute('SELECT * FROM users WHERE id = %s', (int(user_id),))
        user = cursor.fetchone()
        if user:
            return User(id=user['id'], username=user['username'], email=user['email'])
        return None
    except Error as e:
        print(f"Error loading user: {e}")
        return None
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()

# Password validation
def validate_password(password):
    if len(password) < 8 or not re.search(r"[A-Z]", password) or not re.search(r"[0-9]", password):
        return False
    return True

# Routes
@app.route('/')
def index():
    if request.method == 'POST':
        uploaded_file = request.files['file']
        if uploaded_file.filename == '':
            flash('No file selected!', 'danger')
            return redirect(request.url)
        
        # Save to uploads folder (make sure this folder exists!)
        save_path = os.path.join('uploads', uploaded_file.filename)
        uploaded_file.save(save_path)

        # Save the path in the session
        session['uploaded_file'] = save_path

        flash('File uploaded successfully. Now choose Encrypt or Decrypt.', 'success')
        return redirect(url_for('Option'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['login-username']
        password = request.form['login-password']
        try:
            conn = get_db()
            cursor = conn.cursor(dictionary=True)
            cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
            user = cursor.fetchone()
            if user and check_password_hash(user['password'], password):
                login_user(User(id=user['id'], username=user['username'], email=user['email']))
                return redirect(url_for('index'))
            else:
                return render_template('login.html', error='Invalid credentials')
        except Error as e:
            return render_template('login.html', error=f'Database error {e}')
        finally:
            if conn.is_connected():
                cursor.close()
                conn.close()
    if request.method == 'GET':
        if session.get('_user_id'):
            return redirect(url_for('index')) 
        else:
            return redirect(url_for('login'))
        
    return render_template('login.html', show_form='login-form')

@app.route('/register', methods=['POST'])
def register():
    if request.method == 'POST':
        username = request.form['register-username']
        email = request.form['register-email']
        raw_password = request.form['register-password']
        if not validate_password(raw_password):
            return render_template('login.html', error='Password must be at least 8 characters, include a number and a capital letter.')

        password = generate_password_hash(raw_password)
        try:
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute('INSERT INTO users (username, email, password) VALUES (%s, %s, %s)', (username, email, password))
            conn.commit()
            return redirect(url_for('login'))
        except Error as e:
            return render_template('login.html', error='Username/Email already exists')
        finally:
            if conn.is_connected():
                cursor.close()
                conn.close()
    return render_template('login.html', show_form='register-form')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.', 'info')
    return redirect(url_for('login'))

@app.route('/health')
def health_check():
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT 1")
        return "Database connection successful", 200
    except Error as e:
        return f"Database connection failed: {str(e)}", 500

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# @app.route('/encrypt/', methods=['GET', 'POST'])
# @login_required
# def encrypt_input():
#     # Perform segmentation and encryption
#     Segment()
#     HybridCryptKeys()

#     # Define filenames for the key and encrypted data
#     key_filename = 'generated_key.key'
#     data_filename = 'encrypted_file.enc'

#     # Construct full paths
#     key_path = os.path.join(app.config['UPLOAD_FOLDER'], key_filename)
#     data_path = os.path.join(app.config['UPLOAD_FOLDER'], data_filename)

#     # Check if the files exist and set session variables
#     if os.path.exists(key_path):
#         session['key_path'] = key_path
#     else:
#         flash('Key file not found.', 'danger')

#     if os.path.exists(data_path):
#         session['data_path'] = data_path
#     else:
#         flash('Encrypted file not found.', 'danger')

#     # List files in the segments folder to display
#     files = os.listdir(SEGMENTS_FOLDER)
#     return render_template('Result.html', dir_list=files)

@app.route('/encrypt/', methods=['POST'])
@login_required
def encrypt_input():
    # if request.method == 'GET':
    #     # Render a page to initiate encryption or show available options
    #     return render_template('encrypt.html')  # Replace with your actual template if needed

    # file_path = session.get('uploaded_file')
    # if not file_path or not os.path.exists(file_path):
    #     flash('No file uploaded yet!', 'danger')
    #     return redirect(url_for('index'))
    # encrypted_path = encrypt_file(file_path)

    # flash('File encrypted successfully.', 'success')
    # return send_file(encrypted_path, as_attachment=True)                    

    if request.method == 'POST':
        uploaded_file = request.files.get('uploaded_file')
        # Perform segmentation and encryption
        Segment()
        HybridCryptKeys()

        # Define filenames for the key and encrypted data
        key_filename = 'generated_key.key'
        data_filename = 'encrypted_file.enc'

        # Construct full paths
        key_path = os.path.join(app.config['UPLOAD_FOLDER'], key_filename)
        data_path = os.path.join(app.config['UPLOAD_FOLDER'], data_filename)

        # Check if the files exist and set session variables
        if os.path.exists(key_path):
            session['key_path'] = key_path
        else:
            flash('Key file not found.', 'danger')

        if os.path.exists(data_path):
            session['data_path'] = data_path
        else:
            flash('Encrypted file not found.', 'danger')

        # List files in the segments folder to display
    files = os.listdir(SEGMENTS_FOLDER)
    flash('Encryption completed successfully!', 'success')
    return render_template('Result.html', dir_list=files)


@app.route('/upload_key', methods=['GET', 'POST'])
@login_required
def upload_key():
    print(f"HTTP Method used: {request.method}")

    if request.method == 'GET':
        # Handle GET: simply render the form
        return render_template('resultD.html', show_form='key_file')

    if request.method == 'POST':
        # Handle POST: process the uploaded file
        if 'key_file' not in request.files:
            flash('No file part')
            return redirect(request.url)

        key_file = request.files['key_file']
        if key_file.filename == '':
            flash('No selected file')
            return redirect(request.url)

        if key_file and allowed_file(key_file.filename):
            filename = secure_filename('uploaded_key.key')  # Safe fixed name
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            key_file.save(filepath)
            session['key_path'] = filepath
            return redirect(url_for('validate_access'))

        # If file is not valid
        flash('Invalid file type')
        return redirect(request.url)

# @app.route('/upload_key', methods=['GET', 'POST'])
# @login_required
# def upload_key():
#     print(f"HTTP Method used: {request.method}")
#     if request.method == 'POST':
#         if 'key_file' not in request.files:
#             flash('No file part')
#             return redirect(request.url)
        
#         key_file = request.files['key_file']
#         if key_file.filename == '':
#             flash('No selected file')
#             return redirect(request.url)
        
#         if key_file and allowed_file(key_file.filename):
#             filename = secure_filename('uploaded_key.key')  # Safe fixed name
#             filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
#             key_file.save(filepath)
#             session['key_path'] = filepath
#             return redirect(url_for('validate_access'))
#     return render_template('resultD.html', show_form='key_file')

# @app.route('/validate_access', methods=['GET', 'POST'])
# @login_required
# def validate_access():
#     print(f"HTTP Method used: {request.method}")
#     if request.method == 'POST':
#         email = request.form['email']
#         if not os.path.exists(ACCESS_LIST):
#             return "Access list missing!", 404
        
#         with open(ACCESS_LIST, 'r') as f:
#             allowed_emails = f.read().splitlines()
        
#         if email.strip() in allowed_emails:
#             session['email_verified'] = True
#             flash('Email verified! Ready to decrypt.', 'success')
#             return redirect(url_for('decrypt_and_merge'))
#         else:
#             flash('Email not authorized.', 'danger')
#             return redirect(request.url)
#     return render_template('Result.html')

@app.route('/validate_access', methods=['GET', 'POST'])
@login_required
def validate_access():

    if request.method == 'GET':
        # Handle GET: render the email validation form
        return render_template('Option.html')

    if request.method == 'POST':
        # Handle POST: process the email input
        email = request.form['email_v']
        uploaded_file = request.files.get('uploaded_file')

        if uploaded_file:
            uploaded_file.save(os.path.join(r'C:\Users\DELL\OneDrive\Desktop\bca project\downloadsq', uploaded_file.filename))

        if not os.path.exists(ACCESS_LIST):
            return "Access list missing!", 404

        with open(ACCESS_LIST, 'r') as f:
            allowed_emails = f.read().splitlines()

        if email.strip() in allowed_emails:
            session['email_verified'] = True
            flash('Email verified! Ready to decrypt.', 'success')
            return redirect(url_for('decrypt_and_merge'))
        else:
            flash('Email not authorized.', 'danger')
            return redirect(request.url)

# @app.route('/decrypt_and_merge', methods=['GET', 'POST'])
# @login_required
# def decrypt_and_merge():
#     if not session.get('email_verified') or 'key_path' not in session:
#         flash('You must verify email and upload key first.', 'warning')
#         return redirect(url_for('upload_key'))

#     try:
#         key_path = session['key_path']
#         with open(key_path, 'rb') as f:
#             key = f.read()

#         iv_hex = request.args.get('iv')  # IV input from URL query
#         if not iv_hex:
#             return "Missing IV in request.", 400
#         iv = bytes.fromhex(iv_hex)

#         # Decrypt process
#         HybridDeCryptKeys(key)
#         DAES(key, iv)
#         DBlowFish(key, iv)
#         DTrippleDES(key, iv)
#         DIDEA(key, iv)
#         DFernet(key)
#         merge.merge_segments()

#         flash('Files decrypted and merged successfully!', 'success')
#         return redirect(url_for('download_merged'))
#     except Exception as e:
#         flash(f'Error during decryption: {e}', 'danger')
#         return redirect(url_for('upload_key'))

@app.route('/decrypt_and_merge', methods=['GET', 'POST'])
@login_required
def decrypt_and_merge():
    if request.method == 'GET':
        # Only allow access to decryption form/page after validation
        if not session.get('email_verified') or 'key_path' not in session:
            flash('You must verify email and upload key first.', 'warning')
            return redirect(url_for('upload_key'))
        
        return render_template('decrypt.html') 

    if request.method == 'POST':
        if not session.get('email_verified') or 'key_path' not in session:
            flash('You must verify email and upload key first.', 'warning')
            return redirect(url_for('upload_key'))

        try:
            key_path = session['key_path']
            with open(key_path, 'rb') as f:
                key = f.read()

            iv_hex = request.form.get('iv')  # Assuming IV comes from form POST
            if not iv_hex:
                flash("Missing IV in form data.", "danger")
                return redirect(request.url)

            iv = bytes.fromhex(iv_hex)

            # Decryption steps
            HybridDeCryptKeys(key)
            DAES(key, iv)
            DBlowFish(key, iv)
            DTrippleDES(key, iv)
            DIDEA(key, iv)
            DFernet(key)
            merge.merge_segments()

            flash('Files decrypted and merged successfully!', 'success')
            return redirect(url_for('download_merged'))
        except Exception as e:
            flash(f'Error during decryption: {e}', 'danger')
    return redirect(url_for('upload_key'))


@app.route('/download')
@login_required
def download_merged():
    files = os.listdir(DOWNLOAD_FOLDER)
    if not files:
        return "No merged file found!", 404

    final_file = files[0]
    return send_from_directory(DOWNLOAD_FOLDER, final_file, as_attachment=True)

@app.route('/return-files-key/')
@login_required
def return_files_key():
    if not session.get('email_verified'):
        flash('Email not verified. Cannot download key.', 'danger')
        return redirect(url_for('validate_access'))

    key_path = session.get('key_path')
    if key_path and os.path.exists(key_path):
        return send_file(key_path, as_attachment=True)
    else:
        flash('Key file not found.', 'danger')
        return abort(404)

@app.route('/return-files-data/')
@login_required
def return_files_data():
    if not session.get('email_verified'):
        flash('Email not verified. Cannot download data.', 'danger')
        return redirect(url_for('validate_access'))

    # Assuming encrypted file is stored in session or at a known location
    encrypted_file = os.path.join(app.config['UPLOAD_FOLDER'], 'encrypted_file.enc')
    session['data_path'] = encrypted_file  # Optionally store in session

    if os.path.exists(encrypted_file):
        return send_file(encrypted_file, as_attachment=True)
    else:
        flash('Encrypted file not found.', 'danger')
        return abort(404)
    
@app.route('/data/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'GET':
        # Show the upload form or page
        return render_template('Option.html')  # or another page for the upload form

    if request.method == 'POST':
        if 'file' not in request.files:
            return render_template('Nofile.html')

        file = request.files['file']
        if file.filename == '':
            return render_template('Nofile.html')

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], 'Original.txt'))
            return start()  # Assuming start() processes the uploaded file

        # If the file type is invalid
        return render_template('Invalid.html')
    
# @app.route('/data/', methods=['GET', 'POST'])
# def upload_file():
#   if request.method == 'POST':
#     if 'file' not in request.files:
#       return render_template('Nofile.html')
#     file = request.files['file']
#     if file.filename == '':
#       return render_template('Nofile.html')
#     if file and allowed_file(file.filename):
#       filename = secure_filename(file.filename)
#       file.save(os.path.join(app.config['UPLOAD_FOLDER'], 'Original.txt'))
#       return start()
#   return render_template('Invalid.html')

# @app.route('/data/', methods=['POST'])
# @login_required
# def upload_file():
#     # print(f"HTTP Method used: {request.method}")
#     # print(f"File used: {file}")
#     if request.method == 'POST':
#         if 'file' not in request.files:
#             flash('No file part found in the request.', 'danger')
#             return render_template('Nofile.html')

#         file = request.files['file']
#         if file.filename == '':
#             flash('No file was selected.', 'danger')
#             return render_template('Nofile.html')
        
#         if file and allowed_file(file.filename):
#             filename = secure_filename('Original.txt')  # You can also use file.filename if dynamic
#             file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
#             flash('File uploaded successfully!', 'success')
#             return redirect(url_for('Option'))
#         else:
#             flash('Invalid file type.', 'danger')
#             return render_template('Invalid.html')

#     # For GET requests, show the upload form
#     return render_template('Option.html')

if __name__ == '__main__':
    app.run(debug=True)
