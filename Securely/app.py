from flask import Flask, render_template, request, redirect, session, send_file, jsonify
from flask_mysqldb import MySQL
import MySQLdb.cursors
from flask_mail import Mail, Message
import random
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
import hashlib
from virus_total_apis import PublicApi as vtPubAPI
import os
import io
import string
from PyPDF2 import PdfReader, PdfWriter
import speedtest
from werkzeug.utils import secure_filename
import requests
import ssl
import socket
from bs4 import BeautifulSoup
from pathlib import Path
from PIL import Image
from PIL.ExifTags import TAGS
import time
import pikepdf
from tqdm import tqdm
import re

app = Flask(__name__)
app.secret_key = 'your_secret_key'

UPLOAD_FOLDER = 'uploads'  # Specify the directory to store uploaded files
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Virus Totla Cofig
vt = vtPubAPI(
    "31154865e8ef395133e015fc5c1da932aa7e4bcb83a43db3821a1e44a8ff0925")

# MySQL Configuration
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'securely_web'

# Flask-Mail Configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'sonabai2009@gmail.com'
app.config['MAIL_PASSWORD'] = 'pmtpzjnmszyuboxy'

mysql = MySQL(app)
mail = Mail(app)


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    msg = ''
    if request.method == 'POST' and 'email' in request.form and 'password' in request.form:
        email = request.form['email']
        password = request.form['password']
        enc_pass = encrypt(password)
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute(
            'SELECT * FROM accounts WHERE email = %s AND password = %s', (email, enc_pass))
        account = cursor.fetchone()
        if account:
            session['loggedin'] = True
            session['id'] = account['id']
            session['email'] = account['email']
            session['name'] = account['username']
            # Password verification successful, generate OTP
            otp = str(random.randint(1000, 9999))
            session['otp'] = otp

            with open("templates/otp-template.html", "r") as f_in:
                data = f_in.read()
            verified = data.replace('CHANGEOTP', str(otp))
            print(verified)
            msg = Message('OTP Verification', html=verified,
                          sender='your_email', recipients=[email])
            msg.body = data.replace('CHANGEOTP', str(otp))
            mail.send(msg)

            return redirect('/otp-login')
        else:
            msg = 'Incorrect Email / password!'
    return render_template('login.html', msg=msg)


@app.route('/otp-login', methods=['GET', 'POST'])
def otp_login1():
    if 'email' in session:
        email = session['email']
        if request.method == 'POST' or 'otp' in request.form:
            input1 = request.form['text1']
            input2 = request.form['text2']
            input3 = request.form['text3']
            input4 = request.form['text4']
            otp = f"{input1}{input2}{input3}{input4}"
            if session['otp'] == otp:
                session['otp_verified'] = True
                return redirect('/dashboard')
            else:
                return render_template('otp-login.html', email=email, msg='Invalid OTP')
        else:
            return render_template('otp-login.html', email=email)
    else:
        return redirect('/login')


@app.route('/dashboard')
def dashboard6():
    if 'email' in session:
        return render_template('dashboard.html')
    else:
        return redirect('/login')


@app.route('/logout')
def logout():
    if 'email' in session:
        session.pop('loggedin', None)
        session.pop('id', None)
        session.pop('email', None)
        session.pop('otp_verified', None)
        return redirect('/login')
    else:
        return redirect('/login')


@app.route('/register', methods=['GET', 'POST'])
def register():
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form:
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute(
            'SELECT * FROM accounts WHERE username = %s', (username,))
        account = cursor.fetchone()
        if account:
            msg = 'Account already exists!'
        elif not username or not password or not email:
            msg = 'Please fill out the form!'
        else:
            # Generate and send OTP
            otp = str(random.randint(1000, 9999))
            session['otp'] = otp

            with open("otp-template.html", "r") as f_in:
                data = f_in.read()
            print(data)
            verified = data.replace('CHANGEOTP', str(otp))
            print(verified)
            msg = Message('OTP Verification', html=verified,
                          sender='your_email', recipients=[email])
            print(msg)
            mail.send(msg)

            session['register_data'] = {
                'username': username,
                'password': password,
                'email': email
            }
            return redirect('/otp-register')
    elif request.method == 'POST':
        msg = 'Please fill out the form!'
    return render_template('register.html', msg=msg)


@app.route('/otp-register', methods=['GET', 'POST'])
def otp_register():
    if 'register_data' in session:
        register_data = session['register_data']
        if request.method == 'POST' or 'otp' in request.form:
            input1 = request.form['text1']
            input2 = request.form['text2']
            input3 = request.form['text3']
            input4 = request.form['text4']
            otp = f"{input1}{input2}{input3}{input4}"
            if session['otp'] == otp:
                newp = register_data['password']
                enc_pass = encrypt(newp)
                cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                cursor.execute(
                    'INSERT INTO accounts (username, password, email) VALUES (%s, %s, %s)',
                    (register_data['username'],
                     enc_pass, register_data['email'])
                )
                mysql.connection.commit()
                session.pop('register_data', None)
                return redirect('/login')
            else:
                return render_template('otp-registration.html', error='Invalid OTP')
        else:
            return render_template('otp-registration.html')
    else:
        return redirect('/login')


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    msg = ''
    if request.method == 'POST' and 'email' in request.form:
        email = request.form['email']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE email = %s', (email,))
        account = cursor.fetchone()
        if account:
            # Generate and send OTP
            otp = str(random.randint(1000, 9999))
            session['otp'] = otp
            with open("otp-template.html", "r") as f_in:
                data = f_in.read()
            msg = Message('OTP Verification', html=True,
                          sender='your_email', recipients=[email])
            msg.body = data.replace('CHANGEOTP', str(otp))
            mail.send(msg)

            return redirect('/reset-password')
        else:
            msg = 'Invalid Email Address'
    return render_template('forgot-password.html', msg=msg)


@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if 'reset_email' in session:
        email = session['reset_email']
        if request.method == 'POST' or 'otp' in request.form and 'password' in request.form:
            input1 = request.form['text1']
            input2 = request.form['text2']
            input3 = request.form['text3']
            input4 = request.form['text4']
            otp = f"{input1}{input2}{input3}{input4}"
            if session['otp'] == otp:
                return redirect('/reset')
            else:
                return render_template('otp-reset.html', email=email, msg='Invalid OTP')

        return render_template('otp-reset.html', email=email)
    else:
        return redirect('/')


@app.route('/reset', methods=['GET', 'POST'])
def change_password():
    msg = ''
    if 'email' in session:
        email = session['email']
        if request.method == 'POST' and 'new_password' in request.form and 'confirm_password' in request.form:
            new_password = request.form['new_password']
            confirm_password = request.form['confirm_password']
            if new_password == confirm_password:
                enc_pass = encrypt(new_password)
                cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                cursor.execute(
                    'UPDATE accounts SET password = %s WHERE email = %s', (enc_pass, email))
                mysql.connection.commit()
                msg = 'Password changed successfully!'
                return redirect('/dashboard')

            else:
                msg = 'Passwords do not match!'
        return render_template('reset.html', email=email, msg=msg)
    else:
        return redirect('/forgot-password-17')


# Frontend

# Text Encode and Decode

@app.route('/text_encoder', methods=['POST', 'GET'])
def text_encode():
    if 'email' in session:
        if request.method == 'POST':
            input_text = request.form.get('string_text')
            key = request.form.get('enc_key')

            cipher = AES.new(key.encode(), AES.MODE_ECB)
            encrypted_text = b64encode(cipher.encrypt(
                pad(input_text.encode(), AES.block_size))).decode()

            return render_template('text_encoder.html', enc_text=encrypted_text)

        email = session['email']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute(
            'INSERT INTO user_log (route, email) VALUES ("/text_encoder", %s)', (email,)
        )
        mysql.connection.commit()

        return render_template('text_encoder.html')
    else:
        return redirect('/login')


@app.route('/text_decoder', methods=['POST', 'GET'])
def text_decode():
    if 'email' in session:
        if request.method == 'POST':
            input_text = request.form.get('chiper_text')
            key = request.form.get('dec_key')

            cipher = AES.new(key.encode(), AES.MODE_ECB)
            decrypted_text = unpad(cipher.decrypt(
                b64decode(input_text)), AES.block_size).decode()

            email = session['email']
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute(
                'INSERT INTO user_log (route, email) VALUES ("/text_decoder", %s)', (email,)
            )
            mysql.connection.commit()

            return render_template('text_encoder.html', dec_text=decrypted_text)

        return render_template('text_encoder.html')
    else:
        return redirect('/login')


# Website Scan

def scan_url(url):
    response = vt.scan_url([url])
    if response["response_code"] == 200:
        resource = response["results"]["url"]
        url_report = vt.get_url_report(resource)
        print(url_report)
        if url_report["response_code"] == 200:
            total = url_report["results"]["total"] / 2
            if url_report["results"]["positives"] > int(total):
                return "Virus detected!"
            else:
                return "No virus found, Site is Secure"
        else:
            return "Error occurred during URL scanning."
    else:
        return "Error occurred during scanning."


@app.route('/website_scan', methods=['POST', 'GET'])
def website_scanner():
    if 'email' in session:
        if request.method == 'POST':
            msg = ""

            link = request.form.get('link')

            msg = scan_url(link)

            return render_template('website_scanner.html', result=msg)

        email = session['email']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute(
            'INSERT INTO user_log (route, email) VALUES ("/website_scan", %s)', (email,)
        )
        mysql.connection.commit()

        return render_template('website_scanner.html')
    else:
        return redirect('/login')


# Image Encode and Decode

encryption_key = None
encrypted_image = None
decrypted_image = None


def generate_key():
    """Generate a new encryption key"""
    return os.urandom(16)


def encrypt_image(image_path, key):
    """Encrypt an image file using the provided key"""
    with open(image_path, 'rb') as file:
        image_data = file.read()

    cipher = AES.new(key, AES.MODE_ECB)
    encrypted_data = cipher.encrypt(pad(image_data, AES.block_size))

    encrypted_image = io.BytesIO(encrypted_data)

    return encrypted_image


def decrypt_image(encrypted_image_path, key):
    """Decrypt an encrypted image file using the provided key"""
    with open(encrypted_image_path, 'rb') as file:
        encrypted_data = file.read()

    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)

    decrypted_image = io.BytesIO(decrypted_data)

    return decrypted_image


@app.route('/download_encrypted')
def download_encrypted():
    if 'email' in session:
        global encrypted_image
        if encrypted_image:
            encrypted_image.seek(0)
            return send_file(encrypted_image, mimetype='image/png', as_attachment=True,
                             download_name='encrypted_image.png')
        return 'No encrypted image available.'
    else:
        return redirect('/login')


@app.route('/download_decrypted')
def download_decrypted():
    if 'email' in session:
        global decrypted_image
        if decrypted_image:
            decrypted_image.seek(0)
            return send_file(decrypted_image, mimetype='image/png', as_attachment=True,
                             download_name='decrypted_image.png')

        return 'No decrypted image available.'
    else:
        return redirect('/login')


@app.route('/image_encoder', methods=['POST', 'GET'])
def image_encode():
    if 'email' in session:
        global encrypted_image
        if request.method == 'POST':
            if 'image' in request.files:
                image_file = request.files['image']
                if image_file.filename != '':
                    image_path = 'uploads/images_encode/' + image_file.filename
                    image_file.save(image_path)
                    key = generate_key()
                    encrypted_image = encrypt_image(image_path, key)
                    return render_template('image_encoder.html', dec_key=key.hex(),
                                           encrypted_image_available=True)

        # Storing in the Log

        email = session['email']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute(
            'INSERT INTO user_log (route, email) VALUES ("/image_encoder", %s)', (email,)
        )
        mysql.connection.commit()

        return render_template('image_encoder.html')
    else:
        return redirect('/login')


@app.route('/image_decoder', methods=['POST', 'GET'])
def image_decode():
    if 'email' in session:
        global decrypted_image
        if request.method == 'POST':
            if 'image' in request.files:
                image_file = request.files['image']
                if image_file.filename != '':
                    image_path = 'uploads/images_decode/' + image_file.filename
                    image_file.save(image_path)

                    key = bytes.fromhex(request.form['key'])
                    decrypted_image = decrypt_image(image_path, key)

                    # Storing in the Log

                    email = session['email']
                    cursor = mysql.connection.cursor(
                        MySQLdb.cursors.DictCursor)
                    cursor.execute(
                        'INSERT INTO user_log (route, email) VALUES ("/image_decoder", %s)', (email,)
                    )
                    mysql.connection.commit()

                    return render_template('image_encoder.html', decryption_key=request.form['key'],
                                           decrypted_image_available=True)

        return render_template('image_encoder.html')
    else:
        return redirect('/login')


# Password Security

def check_password_strength(password):
    # Minimum requirements
    min_length = 8
    min_uppercase = 1
    min_lowercase = 1
    min_digits = 1
    min_special_chars = 1

    # Check length
    if len(password) < min_length:
        return "Password should be at least {} characters long.".format(min_length)

    # Check uppercase letters
    if sum(1 for c in password if c.isupper()) < min_uppercase:
        return "Password should contain at least {} uppercase letter(s).".format(min_uppercase)

    # Check lowercase letters
    if sum(1 for c in password if c.islower()) < min_lowercase:
        return "Password should contain at least {} lowercase letter(s).".format(min_lowercase)

    # Check digits
    if sum(1 for c in password if c.isdigit()) < min_digits:
        return "Password should contain at least {} digit(s).".format(min_digits)

    # Check special characters
    special_chars = string.punctuation
    if sum(1 for c in password if c in special_chars) < min_special_chars:
        return "Password should contain at least {} special character(s).".format(min_special_chars)

    return "Password is strong."


@app.route('/password_security', methods=['POST', 'GET'])
def password_strength():
    if 'email' in session:

        if request.method == 'POST':
            password = request.form.get('password')
            result = check_password_strength(password)
            return render_template('password-security.html', result=result, checked=True)

        # Storing in the Log

        email = session['email']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute(
            'INSERT INTO user_log (route, email) VALUES ("/image_encoder", %s)', (email,)
        )
        mysql.connection.commit()

        return render_template('password-security.html')

    else:
        return redirect('/login')


# PDF Locker

@app.route("/download_locked_pdf", methods=["GET"])
def downloadlockpdf():
    if 'email' in session:
        output_file = request.args.get("output_file")

        # Validate the output file path
        output_path = os.path.join("uploads/pdf_locker", output_file)
        if not os.path.isfile(output_path):
            return "File not found."

        # Return the output file for download
        return send_file(output_path, as_attachment=True)
    else:
        return redirect('/login')

@app.route('/pdf_locker', methods=['POST', 'GET'])
def pdf_locker():
    if 'email' in session:
        if request.method == 'POST':
            if 'pdf' in request.files:
                pdf_file = request.files['pdf']
                password = request.form["password"]

                # Ensure the "uploads/pdf_locker" directory exists
                os.makedirs("uploads/pdf_locker", exist_ok=True)

                # Save the uploaded PDF file to the directory
                pdf_path = os.path.join(
                    "uploads/pdf_locker", secure_filename(pdf_file.filename))
                pdf_file.save(pdf_path)

                reader = PdfReader(pdf_path)

                # Create a new PDF writer
                writer = PdfWriter()

                # Copy each page from the input file to the writer
                for page in reader.pages:
                    writer.add_page(page)

                # Encrypt the PDF with the provided password
                writer.encrypt(password)

                output_filename = os.path.splitext(secure_filename(pdf_file.filename))[
                    0] + "_locked.pdf"
                output_path = os.path.join(
                    "uploads/pdf_locker", output_filename)

                # Write the encrypted PDF to the output file
                with open(output_path, "wb") as out_file:
                    writer.write(out_file)

                # Render the result template with the output file name
                return render_template("pdf_locker.html", locked=True, output_file=output_filename)

        # Storing in the Log
        email = session['email']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute(
            'INSERT INTO user_log (route, email) VALUES ("/pdf_locker", %s)', (email,))
        mysql.connection.commit()

        return render_template("pdf_locker.html")
    else:
        return redirect('/login')


@app.route("/download_unlocked_pdf", methods=["GET"])
def downloadunlockpdf():
    if 'email' in session:

        output_file = request.args.get("output_file")

        output_path = os.path.join("uploads/pdf_unlocker", output_file)
        if not os.path.isfile(output_path):
            return "File not found."

        # Return the output file for download
        return send_file(output_path, as_attachment=True)
    else:
        return redirect('/login')


@app.route("/pdf_unlocker", methods=['POST', 'GET'])
def pdf_unlocker():
    if 'email' in session:
        if request.method == 'POST':
            if 'pdf' in request.files:
                pdf_file = request.files['pdf']
                password = request.form["password"]

                # Ensure the "uploads/pdf_unlocker" directory exists
                os.makedirs("uploads/pdf_unlocker", exist_ok=True)

                # Save the uploaded PDF file to the directory
                pdf_path = os.path.join(
                    "uploads/pdf_unlocker", secure_filename(pdf_file.filename))
                pdf_file.save(pdf_path)

                # Read the encrypted PDF file
                reader = PdfReader(pdf_path)
                if reader.is_encrypted:
                    reader.decrypt(password)

                # Create a new PDF writer
                writer = PdfWriter()

                # Copy each page from the input file to the writer
                for page in reader.pages:
                    writer.add_page(page)

                # Generate the output file path
                original_filename = secure_filename(pdf_file.filename)
                output_filename = os.path.splitext(original_filename)[
                    0] + "_unlocked.pdf"
                output_path = os.path.join(
                    "uploads/pdf_unlocker", output_filename)

                # Write the decrypted PDF to the output file
                with open(output_path, "wb") as out_file:
                    writer.write(out_file)

                # Storing in the Log
                email = session['email']
                cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                cursor.execute(
                    'INSERT INTO user_log (route, email) VALUES ("/pdf_unlocker", %s)', (email,))
                mysql.connection.commit()

                # Render the result template with the output file name
                return render_template("pdf_locker.html", unlocked=True, output_file=output_filename)

        return render_template("pdf_locker.html")
    else:
        return redirect('/login')


# Internet Speed Tester

@app.route('/speed_test')
def get_speed():
    speedtester = speedtest.Speedtest()
    download_speed = speedtester.download() / 10**6  # Convert to Mbps
    upload_speed = speedtester.upload() / 10**6  # Convert to Mbps
    return jsonify({
        'download': download_speed,
        'upload': upload_speed
    })


@app.route('/internet_speed_test', methods=['POST', 'GET'])
def internet_speed_test():
    if 'email' in session:
        # Storing in the Log

        email = session['email']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute(
            'INSERT INTO user_log (route, email) VALUES ("/internet_speed_test", %s)', (email,)
        )
        mysql.connection.commit()

        return render_template('internet-speed.html')
    else:
        return redirect('/login')


# IP Address Tracker

@app.route('/ip_address_tracker', methods=['GET', 'POST'])
def ip_address_tracker():
    if 'email' in session:
        if request.method == 'POST':
            ip_address = request.form.get('ip_address')
            url = f"http://ip-api.com/json/{ip_address}"
            response = requests.get(url)
            data = response.json()
            if data["status"] == "success":
                country = data["country"]
                city = data["city"]
                isp = data["isp"]
                longitude = data["lon"]
                latitude = data["lat"]
                zip = data["zip"]
                region = data["regionName"]
                return render_template('ip_address_tracker.html', is_fetched=True, ip_add=ip_address, country=country, city=city, isp=isp, longitude=longitude, latitude=latitude, zip=zip, region=region)

        # Storing in the Log

        email = session['email']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute(
            'INSERT INTO user_log (route, email) VALUES ("/ip_address_tracker", %s)', (email,)
        )
        mysql.connection.commit()

        return render_template("ip_address_tracker.html")
    else:
        return redirect('/login')


# SSL/TSL Validator


def ssl_tls_checker(hostname, port=443):
    context = ssl.create_default_context()

    with socket.create_connection((hostname, port)) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as secure_sock:
            certificate = secure_sock.getpeercert()

    return certificate


def get_ssl_info(certificate):
    subject = dict(item[0] for item in certificate["subject"])
    issuer = dict(item[0] for item in certificate["issuer"])
    common_name = subject.get("commonName")
    organization = subject.get("organizationName")
    issuer_common_name = issuer.get("commonName")
    issuer_organization = issuer.get("organizationName")
    expiration_date = certificate["notAfter"]

    return {
        "Common Name (CN)": common_name,
        "Organization": organization,
        "Issuer Common Name (CN)": issuer_common_name,
        "Issuer Organization": issuer_organization,
        "Expiration Date": expiration_date
    }


@app.route('/ssl_validator', methods=['GET', 'POST'])
def ssl_validator():
    if 'email' in session:
        if request.method == 'POST':
            hostname = request.form['hostname']

            certificate = ssl_tls_checker(hostname)
            ssl_info = get_ssl_info(certificate)

            return render_template('ssl_validator.html', is_fetched=True, ssl_info=ssl_info)

        # Storing in the Log

        email = session['email']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute(
            'INSERT INTO user_log (route, email) VALUES ("/ssl_validator", %s)', (email,)
        )
        mysql.connection.commit()

        return render_template('ssl_validator.html')
    else:
        return redirect('/login')


# Password Manager

def encrypt(text):
    input_text = text
    key = "mordenizemordnei"
    cipher = AES.new(key.encode(), AES.MODE_ECB)
    encrypted_text = b64encode(cipher.encrypt(
        pad(input_text.encode(), AES.block_size))).decode()

    return encrypted_text


def decrypt(text):
    encrypted_text = text
    key = "mordenizemordnei"
    cipher = AES.new(key.encode(), AES.MODE_ECB)
    decrypted_text = unpad(cipher.decrypt(
        b64decode(encrypted_text)), AES.block_size).decode()

    return decrypted_text


@app.route('/password_manager', methods=['GET', 'POST'])
def password_manager():
    if 'email' in session:
        if request.method == 'POST':
            platform = request.form['platform']
            password = request.form['password']
            encrypted_password = encrypt(password)
            email = session['email']

            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute(
                'INSERT INTO password_manager (email, platform, password) VALUES (%s, %s, %s)',
                (email, platform, encrypted_password)
            )
            mysql.connection.commit()

            return redirect('/password_manager')

        email = session['email']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute(
            "SELECT * FROM password_manager WHERE email = %s", (email,))
        accounts = cursor.fetchall()

        # Storing in the Log

        email = session['email']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute(
            'INSERT INTO user_log (route, email) VALUES ("/password_manager", %s)', (email,)
        )
        mysql.connection.commit()

        for row in accounts:
            encrypted_password2 = row['password']
            decrypted_password = decrypt(encrypted_password2)
            row['password'] = decrypted_password

        return render_template('password-manager.html', accounts=accounts)
    else:
        return redirect('/login')


@app.route('/delete_password', methods=['POST'])
def delete_password():
    if 'email' in session:
        entry_id = request.form['entry_id']

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute(
            "DELETE FROM password_manager WHERE id = %s", (entry_id,))
        mysql.connection.commit()

        # Storing in the Log

        email = session['email']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute(
            'INSERT INTO user_log (route, email) VALUES ("/delete_password", %s)', (email,)
        )
        mysql.connection.commit()

        return redirect("/password_manager")
    else:
        return redirect('/login')


# File Integrity Tester

@app.route('/file_integrity_verify', methods=['GET', 'POST'])
def file_integrity_verify():
    if 'email' in session:
        if request.method == 'POST':
            file = request.files['file']
            file_data = file.read()

            # Calculate the MD5 hash of the file
            file_hash = hashlib.md5(file_data).hexdigest()

            return render_template('file_integrity.html', is_fetched=True, file_hash=file_hash)

        # Storing in the Log

        email = session['email']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute(
            'INSERT INTO user_log (route, email) VALUES ("/file_integrity_verify", %s)', (email,)
        )
        mysql.connection.commit()

        return render_template('file_integrity.html')
    else:
        return redirect('/login')


@app.route('/file_integrity_check', methods=['GET', 'POST'])
def file_integrity_check():
    if 'email' in session:
        if request.method == 'POST':
            file = request.files['file']
            file_data = file.read()
            entered_hash = request.form['hash']

            # Calculate the MD5 hash of the file
            file_hash = hashlib.md5(file_data).hexdigest()

            if file_hash == entered_hash:
                integrity_result = 'File integrity verified. The hash matches!'
            else:
                integrity_result = 'File integrity compromised. The hash does not match!'

            # Storing in the Log

            email = session['email']
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute(
                'INSERT INTO user_log (route, email) VALUES ("/file_integrity_check", %s)', (email,)
            )
            mysql.connection.commit()

            return render_template("file_integrity.html", is_fetched=True, result=integrity_result)

        return render_template("file_integrity.html")
    else:
        return redirect('/login')

# Redirect URL Scanner


@app.route('/redirect_url_scanner', methods=['GET', 'POST'])
def redirect_url_scanner():
    if 'email' in session:
        if request.method == 'POST':
            url = request.form['hostname']
            redirect_links = []
            try:
                response = requests.get(url)
                soup = BeautifulSoup(response.content, 'html.parser')

                for link in soup.find_all('a'):
                    href = link.get('href')
                    if href and 'http' in href:
                        redirect_links.append(href)

                # Remove duplicate links
                redirect_links = list(set(redirect_links))

                return render_template('redirect_url_scanner.html', is_fetched=True, redirect_links=redirect_links)

            except requests.exceptions.RequestException:
                return 'Error occurred while scanning the URL.'

        # Storing in the Log

        email = session['email']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute(
            'INSERT INTO user_log (route, email) VALUES ("/redirect_url_scanner", %s)', (email,)
        )
        mysql.connection.commit()

        return render_template('redirect_url_scanner.html')
    else:
        return redirect('/login')


# Metadata Viewer and Eraser

fields = {
    "File name": "File name",
    "File size": "File size",
    "Model": "Camera Model",
    "ExifImageWidth": "Width",
    "ExifImageHeight": "Height",
    "DateTimeOriginal": "Creation Date",
    "Software": "Software",
    "Artist": "Artist",
    "Make": "Make",
    "ExposureTime": "Exposure Time",
    "FNumber": "F-Stop",
    "ISO": "ISO",
    "FocalLength": "Focal Length",
    "Flash": "Flash",
    "MeteringMode": "Metering Mode",
    "ExposureProgram": "Exposure Program",
    "WhiteBalance": "White Balance",
    "ExposureBiasValue": "Exposure Bias",
    "SceneCaptureType": "Scene Capture Type",
    "LensModel": "Lens Model",
    "GPSInfo": "GPS Info",
    "ImageDescription": "Description",
    "Orientation": "Orientation",
    "XResolution": "X Resolution",
    "YResolution": "Y Resolution",
    "ResolutionUnit": "Resolution Unit",
    "AccessTime": "Access Date",
    "static_line": "*"
}


def get_exif_data(path):
    """
    Extracts the Exif information from the provided photo
    """
    exif_data = {}
    try:
        image = Image.open(path)
        info = image._getexif()
    except (OSError, AttributeError):
        info = {}

    if info is None:
        info = {}

    for tag, value in info.items():
        decoded = TAGS.get(tag, tag)
        exif_data[decoded] = value

    return exif_data


@app.route("/image_metadata", methods=["POST", "GET"])
def image_metadata():
    if 'email' in session:
        if request.method == "POST":
            image_file = request.files["file"]
            image_path = Path('uploads/images_metadata/'+image_file.filename)
            image_file.save(image_path)

            exif_data = get_exif_data(image_path.absolute())
            image_info = {}

            for field in fields:
                if field == "File name":
                    image_info[field] = image_path.name
                elif field == "File size":
                    image_info[field] = image_path.stat().st_size
                elif field == "AccessTime":
                    image_info[field] = time.ctime(image_path.stat().st_atime)
                else:
                    image_info[field] = str(exif_data.get(field, "No data"))

            return render_template("metadata_viewer.html", is_fetched=True, image_info=image_info)

        # Storing in the Log

        email = session['email']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute(
            'INSERT INTO user_log (route, email) VALUES ("/image_metadata", %s)', (email,)
        )
        mysql.connection.commit()

        return render_template("metadata_viewer.html")
    else:
        return redirect('/login')


@app.route('/download_nometadata', methods=['GET'])
def download_nometadata():
    if 'email' in session:
        modified_img_data = request.args.get('modified_img_data')
        return send_file(modified_img_data, as_attachment=True, download_name='modified_image.png')
    else:
        return redirect('/login')


# PDF Cracker

@app.route('/pdf_cracker', methods=['GET', 'POST'])
def pdf_cracker():
    if 'email' in session:
        if request.method == 'POST':
            pdf_file = request.files['pdf_file']
            wordlist_file = request.files['wordlist_file']

            # Save the uploaded files to the server
            pdf_filename = secure_filename(pdf_file.filename)
            wordlist_filename = secure_filename(wordlist_file.filename)
            pdf_file.save(os.path.join(
                app.config['UPLOAD_FOLDER'], pdf_filename))
            wordlist_file.save(os.path.join(
                app.config['UPLOAD_FOLDER'], wordlist_filename))

            # Load password list
            passwords = [line.strip() for line in open(
                os.path.join(app.config['UPLOAD_FOLDER'], wordlist_filename))]

            # Iterate over passwords
            for password in tqdm(passwords, "Decrypting PDF"):
                try:
                    # Open PDF file
                    with pikepdf.open(os.path.join(app.config['UPLOAD_FOLDER'], pdf_filename), password=password) as pdf:
                        # Password decrypted successfully, break out of the loop
                        result = "Congrats, Password found: " + password
                        break
                except pikepdf._core.PasswordError as e:
                    # Wrong password, just continue in the loop
                    result = "Password not found."

            # Remove the uploaded files
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], pdf_filename))
            os.remove(os.path.join(
                app.config['UPLOAD_FOLDER'], wordlist_filename))

            return render_template('pdf_cracker.html', is_fetched=True, result=result)

        # Storing in the Log

        email = session['email']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute(
            'INSERT INTO user_log (route, email) VALUES ("/pdf_cracker", %s)', (email,)
        )
        mysql.connection.commit()

        return render_template('pdf_cracker.html')
    else:
        return redirect('/login')


# Wordlist Generator

def generate_word_list(length, num_words, characters):
    word_list = []
    characters_list = list(characters)

    while len(word_list) < num_words:
        word = generate_word(length, characters_list)
        word_list.append(word)

    return word_list


def generate_word(length, characters_list):
    word = ''.join(random.choice(characters_list) for _ in range(length))
    return word


@app.route('/wordlist_generate', methods=['POST', 'GET'])
def wordlist_generate():
    if 'email' in session:
        if request.method == 'POST':
            length = int(request.form['length'])
            num_words = int(request.form['num_words'])
            characters = request.form['characters']
            global word_list
            word_list = generate_word_list(length, num_words, characters)

            return render_template('wordlist_generate.html', is_fetched=True)

        # Storing in the Log

        email = session['email']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute(
            'INSERT INTO user_log (route, email) VALUES ("/wordlist_generate", %s)', (email,)
        )
        mysql.connection.commit()

        return render_template('wordlist_generate.html')
    else:
        return redirect('/login')


@app.route('/download_wordlist')
def download_wordlist():
    if 'email' in session:
        filename = 'uploads/wordlist/word_list.txt'
        with open(filename, 'w') as file:
            file.write('\n'.join(word_list))

        # Storing in the Log

        email = session['email']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute(
            'INSERT INTO user_log (route, email) VALUES ("/download_wordlist", %s)', (email,)
        )
        mysql.connection.commit()

        return send_file(filename, as_attachment=True)
    else:
        return redirect('/login')


# Sub-Domain Scanner

def get_subdomains(url):
    # Send a GET request to the URL
    response = requests.get(url)

    # Extract the subdomains using a regular expression
    pattern = r'([a-zA-Z0-9]+\.)*[a-zA-Z0-9]+\.[a-zA-Z]+'
    subdomains = re.findall(pattern, response.text)

    # Remove duplicates and return the subdomains
    return list(set(subdomains))


@app.route('/sub_domain_scanner', methods=['GET', 'POST'])
def scan_sub_domain():
    if 'email' in session:
        if request.method == 'POST':
            # Get the URL from the request data
            target_domain = request.form['target_domain']
            check = target_domain.startswith('http://')
            check2 = target_domain.startswith('https://')
            if check or check2:
                # Call the function to get the subdomains
                msg = "Successfully scanned the Sub Domain`s"
                subdomains = get_subdomains(target_domain)
                err = False
            else:
                msg = "Invaild URL, URL must start with http://"
                subdomains = ""
                err = True
            # Render the result.html template with the subdomains
            return render_template('sub_domain_scanner.html', is_fetched=True, err=err, msg=msg, subdomains=subdomains)

        # Storing in the Log

        email = session['email']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute(
            'INSERT INTO user_log (route, email) VALUES ("/sub_domain_scanner", %s)', (email,)
        )
        mysql.connection.commit()

        return render_template('sub_domain_scanner.html')
    else:
        return redirect('/login')


# User Logs

@app.route('/user_logs', methods=['GET'])
def user_logs():
    if 'email' in session:
        email = session['email']
        print(email)
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute(
            'SELECT * FROM user_log WHERE email = %s', (email,))
        account = cursor.fetchall()
        cursor.close()
        print(account)
        return render_template('user_logs.html', account=account)
    else:
        return redirect('/login')


# Change Password in Settings

@app.route('/change_password_login', methods=['GET', 'POST'])
def change_password_login():
    if 'email' in session:
        if request.method == 'POST':
            oldpass = request.form['oldpass']
            newpass = request.form['newpass']
            confirm = request.form['conpass']
            email = session['email']
            encpass = encrypt(newpass)
            if newpass == confirm:
                cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                cursor.execute(
                    'SELECT * FROM accounts WHERE email = %s', (email,))
                curpass = cursor.fetchone()
                perpass = curpass['password']
                dec_pass = decrypt(perpass)
                print(perpass)
                if dec_pass == oldpass:
                    print("verified")
                    cursor = mysql.connection.cursor(
                        MySQLdb.cursors.DictCursor)
                    cursor.execute(
                        'UPDATE accounts SET password = %s WHERE email = %s', (encpass, email))
                    mysql.connection.commit()
                    msg = "Password Changed Successfully!"
                    return render_template('settings.html', is_fetched=True, msg=msg)
                else:
                    msg = "Current Password is incorrect"
                    return render_template('settings.html', is_fetched=True, msg=msg)
            else:
                msg = "Password not Matched"
                return render_template('settings.html', is_fetched=True, msg=msg)

        return render_template('settings.html', email=session['email'])
    else:
        return redirect('/login')


@app.route('/settings', methods=['GET', 'POST'])
def settings():
    if 'email' in session:
        if request.method == 'POST':

            name = request.form['user_name']
            email = session['email']

            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute(
                'UPDATE accounts SET username = %s WHERE email = %s', (name, email))
            mysql.connection.commit()

            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute(
                'SELECT * FROM accounts WHERE email = %s', (email,))
            account = cursor.fetchone()
            user_name = account['username']

            msg = "Username Updated Successfully!"

            return render_template('settings.html', is_fetched=True, username=user_name, msg=msg)

        email = session['email']

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute(
            'SELECT * FROM accounts WHERE email = %s', (email,))
        account = cursor.fetchone()
        user_name = account['username']
        return render_template('settings.html', username=user_name, email=email)
    else:
        return redirect('/login')


if __name__ == '__main__':
    app.run(debug=True)
