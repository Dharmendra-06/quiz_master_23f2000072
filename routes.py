from flask import render_template, request, redirect, url_for, flash, session
from app import app
from models import db, User
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

# Authentication Required Decorator
def auth_required(func):
    @wraps(func)
    def inner(*args, **kwargs):
        if 'user_id' not in session:
            if request.endpoint in ['login', 'register', 'login_post', 'register_post']:
                return func(*args, **kwargs)
            flash('Please login to continue', 'danger')
            return redirect(url_for("login"))
        return func(*args, **kwargs)
    return inner

# Admin Required Decorator
def admin_required(func):
    @wraps(func)
    def inner(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to continue', 'danger')
            return redirect(url_for('login'))
        user = User.query.get(session['user_id'])
        if not user.is_admin:
            flash('You are not authorized to access this page', 'danger')
            return redirect(url_for('home'))
        return func(*args, **kwargs)
    return inner

# Home Route - Redirects Based on Role
@app.route("/")
def home():
    user_id = session.get('user_id')
    if not user_id:
        flash("Registered successfully, now login", "success")
        return redirect(url_for("login"))

    user = User.query.get(user_id)
    if user.is_admin:
        return redirect(url_for("admin"))
    return redirect(url_for('user'))

# Register Route
@app.route("/register")
def register():
    return redirect(url_for("home"))

# Login Page Route
@app.route("/login")
def login():
    return render_template("index.html")

# Login Logic
@app.route("/login_post", methods=["POST"])
def login_post():
    email = request.form.get("email")
    password = request.form.get("pswd")

    if not email or not password:
        flash("Please fill out all fields", "danger")
        return redirect(url_for('login'))

    user = User.query.filter_by(email=email).first()

    if not user:
        flash("Username does not exist", "danger")
        return redirect(url_for('login'))

    if user.status == "blocked":
        flash("Your account has been blocked. Please contact the administrator.", "danger")
        return redirect(url_for('login'))

    if not check_password_hash(user.password, password):
        flash("Incorrect password", "danger")
        return redirect(url_for('login'))

    session['user_id'] = user.id
    flash("Login successful", "success")
    return redirect(url_for("home"))

# User Registration Route
@app.route("/register", methods=["POST"])
@auth_required
def register_post():
    username = request.form.get("txt")
    email = request.form.get("email")
    password = request.form.get("pwd")
    confirm_password = request.form.get("c_pwd")
    name = request.form.get("name")

    if not username or not password or not confirm_password:
        flash('Please fill out all fields', "danger")
        return redirect(url_for('register'))
    
    if password != confirm_password:
        flash('Passwords do not match', "danger")
        return redirect(url_for('register'))
    
    if User.query.filter_by(username=username).first():
        flash('Username already exists', "danger")
        return redirect(url_for('register'))
    
    if User.query.filter_by(email=email).first():
        flash('Email already exists', "danger")
        return redirect(url_for('register'))

    password_hash = generate_password_hash(password)

    new_user = User(username=username, email=email, password=password_hash, name=name)
    db.session.add(new_user)
    db.session.commit()
    
    flash("Registration successful! Please log in.", "success")
    return redirect(url_for('login'))
