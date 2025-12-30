# app.py
import os
from functools import wraps
from flask import (
    Flask, render_template, request, redirect, url_for, flash, session, abort
)
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import (
    StringField, SubmitField, PasswordField, TextAreaField
)
from wtforms.validators import (
    DataRequired, Length, Regexp, Email, EqualTo
)
from flask_bcrypt import Bcrypt
import bleach

# -----------------------
# App config & security
# -----------------------
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-me')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Session cookie hardening (set SESSION_COOKIE_SECURE=True in production with HTTPS)
app.config['SESSION_COOKIE_SECURE'] = False  # set to True on production (HTTPS)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
csrf = CSRFProtect(app)  # enable CSRF globally

# -----------------------
# Models
# -----------------------
class FirstApp(db.Model):
    sno = db.Column(db.Integer, primary_key=True)
    fname = db.Column(db.String(100), nullable=False)
    lname = db.Column(db.String(100), nullable=False)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)

    def verify_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

class Contact(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    phone = db.Column(db.String(30), nullable=True)
    message = db.Column(db.Text, nullable=True)

with app.app_context():
    db.create_all()

# -----------------------
# Sanitizers & constants
# -----------------------
NAME_RE = r'^[A-Za-z\s\-]+$'         # letters, spaces, hyphens allowed
USERNAME_RE = r'^[A-Za-z0-9_.-]+$'   # allowed username chars
PHONE_RE = r'^[0-9+\-\s()]{7,30}$'   # basic phone validation

def sanitize_input(value: str) -> str:
    if value is None:
        return ''
    cleaned = bleach.clean(value, tags=[], attributes={}, strip=True)
    return cleaned.strip()

# -----------------------
# Forms
# -----------------------
class PersonForm(FlaskForm):
    fname = StringField('First Name', validators=[
        DataRequired(), Length(min=1, max=100),
        Regexp(NAME_RE, message="Only letters, spaces and hyphens allowed.")
    ])
    lname = StringField('Last Name', validators=[
        DataRequired(), Length(min=1, max=100),
        Regexp(NAME_RE, message="Only letters, spaces and hyphens allowed.")
    ])
    submit = SubmitField('Submit')

class UpdatePersonForm(PersonForm):
    submit = SubmitField('Update Record')

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(), Length(min=3, max=80),
        Regexp(USERNAME_RE, message="Invalid username characters.")
    ])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    password2 = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=80)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class ContactForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Length(min=1, max=120), Regexp(NAME_RE)])
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=120)])
    phone = StringField('Phone', validators=[Length(max=30), Regexp(PHONE_RE, message="Invalid phone format.")])
    message = TextAreaField('Message', validators=[Length(max=2000)])
    submit = SubmitField('Send')

# -----------------------
# Auth helpers
# -----------------------
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please login to access that page.", "warning")
            return redirect(url_for('login', next=request.path))
        return f(*args, **kwargs)
    return decorated

# -----------------------
# Routes
# -----------------------
@app.route('/', methods=['GET', 'POST'])
def index():
    form = PersonForm()
    if form.validate_on_submit():
        fname = sanitize_input(form.fname.data)
        lname = sanitize_input(form.lname.data)
        if not fname or not lname:
            flash("Invalid input provided.", "danger")
            return redirect(url_for('index'))
        person = FirstApp(fname=fname, lname=lname)  # SQLAlchemy ORM -> parameterized
        db.session.add(person)
        db.session.commit()
        flash("Record added.", "success")
        return redirect(url_for('index'))

    allpeople = FirstApp.query.all()
    return render_template('index.html', form=form, allpeople=allpeople)

@app.route('/update/<int:sno>', methods=['GET', 'POST'])
@login_required
def update_entry(sno):
    person = FirstApp.query.filter_by(sno=sno).first_or_404()
    form = UpdatePersonForm(obj=person)
    if form.validate_on_submit():
        fname = sanitize_input(form.fname.data)
        lname = sanitize_input(form.lname.data)
        if not fname or not lname:
            flash("Invalid input after sanitization.", "danger")
            return redirect(url_for('update_entry', sno=sno))
        person.fname = fname
        person.lname = lname
        db.session.commit()
        flash("Record updated.", "success")
        return redirect(url_for('index'))
    return render_template('update.html', form=form, person=person)

# Use POST for delete and protect with CSRF
@app.route('/delete/<int:sno>', methods=['POST'])
@login_required
def delete_entry(sno):
    person = FirstApp.query.filter_by(sno=sno).first_or_404()
    db.session.delete(person)
    db.session.commit()
    flash("Record deleted.", "info")
    return redirect(url_for('index'))

# Contact page (collects contact details and stores sanitized)
@app.route('/contact', methods=['GET', 'POST'])
def contact():
    form = ContactForm()
    if form.validate_on_submit():
        name = sanitize_input(form.name.data)
        email = sanitize_input(form.email.data)
        phone = sanitize_input(form.phone.data)
        message = sanitize_input(form.message.data)
        # Basic post-sanitization check to ensure not empty
        if not name or not email:
            flash("Name and email are required.", "danger")
            return redirect(url_for('contact'))
        c = Contact(name=name, email=email, phone=phone, message=message)
        db.session.add(c)
        db.session.commit()
        flash("Contact saved. Thank you.", "success")
        return redirect(url_for('contact'))
    return render_template('contact.html', form=form)

# -----------------------
# Auth routes
# -----------------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        username = sanitize_input(form.username.data)
        if User.query.filter_by(username=username).first():
            flash("Username already exists (generic message).", "danger")
            return redirect(url_for('register'))
        pw_hash = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=username, password_hash=pw_hash)
        db.session.add(user)
        db.session.commit()
        flash("Registration successful. Please login.", "success")
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = sanitize_input(form.username.data)
        user = User.query.filter_by(username=username).first()
        if user and user.verify_password(form.password.data):
            session.clear()
            session['user_id'] = user.id
            flash("Login successful.", "success")
            next_page = request.args.get('next') or url_for('index')
            return redirect(next_page)
        # Generic error message (don't reveal whether username exists)
        flash("Invalid username or password.", "danger")
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for('index'))

# -----------------------
# Error handlers
# -----------------------
@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(e):
    # do not expose e or stacktrace to end user
    return render_template('500.html'), 500

# -----------------------
# Health route
# -----------------------
@app.route('/health')
def health():
    return {"status": "ok"}, 200

# -----------------------
# Run
# -----------------------
if __name__ == "__main__":
    # For local development without HTTPS, SESSION_COOKIE_SECURE may be False.
    app.run(host="127.0.0.1", port=5000, debug=False)
