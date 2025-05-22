from flask import Flask, render_template, url_for, request, redirect, flash, make_response, session
from flask_login import login_required, LoginManager, UserMixin, login_user, logout_user, current_user
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from dotenv import load_dotenv
from flask_sqlalchemy import SQLAlchemy
from passlib.hash import bcrypt
from random import randint
import os

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')

# Mail Configuration
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = os.getenv('MAIL_PORT')
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True

mail = Mail(app)

# for time sensitive otp
serializer = URLSafeTimedSerializer(app.secret_key)

# Database setup
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Init
login_manager = LoginManager()
login_manager.init_app(app)

# Where to redirect if not logged in
login_manager.login_view = 'login'


# User-Model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(100), nullable=False)

    def __repr__(self):
        return f"<User {self.username}>"


# create Database
with app.app_context():
    db.create_all()


# load user
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# home-route
@app.route('/')
@app.route('/home')
def home():
    return render_template('home.html')


# login-route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        try:
            username = request.form['username']
            password = request.form['password']

            user = User.query.filter_by(username=username).first()

            if user and bcrypt.verify(password, user.password):
                login_user(user)
                return redirect(url_for('dashboard'))
            else:
                flash("Invalid Credentials!!")
        except Exception as e:
            flash(f"Error: {str(e)}")
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            username = request.form['username']
            password = request.form['password']
            user_email = request.form.get('email')

            hashed_password = bcrypt.hash(password)

            session['user'] = username
            session['password'] = hashed_password

            existing_email = User.query.filter_by(email=user_email).first()
            existing_user = User.query.filter_by(username=username).first()

            if existing_user or existing_email:
                flash('Account already exists!')
            else:
                otp = str(randint(100000, 999999))
                token = serializer.dumps(otp)

                session['otp_token'] = token
                session['email'] = user_email  # Save email for reference

                subject = 'OTP Validation - NetMon'
                sender = 'ramavraja@gmail.com'
                body = f"The OTP for NetMon is {otp}"
                msg = Message(subject=subject,
                              sender=sender,
                              recipients=[user_email],
                              body=body)

                try:
                    mail.send(msg)
                except Exception as e:
                    flash(f"Error : {str(e)}")
                    return redirect(url_for('register'))

                flash("OTP sent to your email.")
                return redirect(url_for('validation'))
        except Exception as e:
            flash(f"Error: {str(e)}")
    return render_template('register.html')


@app.route('/validation', methods=['GET', 'POST'])
def validation():
    if request.method == 'POST':
        user_otp = request.form.get('otp')
        token = session.get('otp_token')
        email = session.get('email')
        user = session.get('user')
        password = session.get('password')

        session.pop('otp_token', None)
        session.pop('email', None)
        session.pop('user', None)
        session.pop('password', None)

        try:
            original_otp = serializer.loads(token, max_age=120)

            if original_otp == user_otp:
                new_user = User(username=user, password=password, email=email)
                db.session.add(new_user)
                db.session.commit()
                flash("OTP Verified. Registration Complete!")
                return redirect(url_for('login'))
            else:
                flash("Invalid OTP. Please try again.")
        except SignatureExpired:
            flash("OTP has expired, please register again!")
        except BadSignature:
            flash("Invalid or tampered OTP!")

    return render_template('verification.html')


# dashboard-route
@app.route('/dashboard')
@login_required
def dashboard():
    response = make_response(render_template('dashboard.html'))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    return response


# logs-route
@app.route('/logs')
@login_required
def logs():
    dummy_logs = [
        {
            'timestamp': '2025-04-16 09:15:22',
            'src_ip': '192.168.1.10',
            'dst_ip': '8.8.8.8',
            'protocol': 'ICMP',
            'port': 'N/A',
            'event': 'Ping Request',
            'status': 'Success'
        },
        {
            'timestamp': '2025-04-16 09:20:44',
            'src_ip': '192.168.1.12',
            'dst_ip': '172.217.194.101',
            'protocol': 'TCP',
            'port': '443',
            'event': 'HTTPS Access',
            'status': 'Success'
        },
        {
            'timestamp': '2025-04-16 09:23:10',
            'src_ip': '192.168.1.5',
            'dst_ip': '10.0.0.254',
            'protocol': 'UDP',
            'port': '53',
            'event': 'DNS Query',
            'status': 'Success'
        },
        {
            'timestamp': '2025-04-16 09:30:51',
            'src_ip': '192.168.1.7',
            'dst_ip': '192.168.1.1',
            'protocol': 'TCP',
            'port': '22',
            'event': 'SSH Login Attempt',
            'status': 'Failed'
        },
        {
            'timestamp': '2025-04-16 09:33:12',
            'src_ip': '192.168.1.20',
            'dst_ip': '104.21.54.15',
            'protocol': 'TCP',
            'port': '80',
            'event': 'HTTP Request',
            'status': 'Success'
        },
        {
            'timestamp': '2025-04-16 09:38:40',
            'src_ip': '192.168.1.8',
            'dst_ip': '192.168.1.1',
            'protocol': 'TCP',
            'port': '3389',
            'event': 'RDP Login Attempt',
            'status': 'Blocked'
        },
    ]
    return render_template('logs.html', logs=dummy_logs)


# settings-route
@app.route('/settings')
@login_required
def settings():
    return render_template('settings.html')


# change_password-route
@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')

    user = User.query.get(current_user.id)

    if not bcrypt.verify(current_password, user.password):
        flash("Current password is incorrect.")
        return redirect(url_for('settings'))

    if new_password != confirm_password:
        flash("New passwords do not match.")
        return redirect(url_for('settings'))

    user.password = bcrypt.hash(new_password)
    db.session.commit()
    flash("Password successfully updated.")
    return redirect(url_for('settings'))


# delete_account-route
@app.route('/delete_account', methods=['POST'])
@login_required
def delete_account():
    delete_password = request.form.get('delete_password')
    user = User.query.get(current_user.id)

    if not bcrypt.verify(delete_password, user.password):
        flash("Incorrect password.")
        return redirect(url_for('settings'))

    logout_user()
    db.session.delete(user)
    db.session.commit()
    flash("Account deleted successfully.")
    return redirect(url_for('home'))


# dashout-route
@app.route('/dashout')
def dashout():
    return render_template('dashout.html')


# logout-route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    flash(" ")
    return redirect(url_for('dashout'))


if __name__ == '__main__':
    app.run(debug=True)