from flask import render_template,request,redirect,url_for, flash,session, send_file,Response
from app import app
from models import db, User, Subject ,Chapter, Quiz, Question, Score
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import sqlite3
import csv
import os
# import matplotlib
# matplotlib.use('Agg')  # Add this line before importing pyplot
# import matplotlib.pyplot as plt
import io
import base64
from sqlalchemy.orm import aliased
from sqlalchemy.sql import func

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


# Admin Dashboard Route

@app.route('/admin')
@admin_required
def admin():
    total_users = User.query.count()
    total_subjects = Subject.query.count()
    total_chapters = Chapter.query.count()
    total_quizzes = Quiz.query.count()
    total_questions = Question.query.count()
    users = User.query.all()  # Fetch all users
    
    return render_template(
        'admin.html',
        total_users=total_users,
        total_subjects=total_subjects,
        total_chapters=total_chapters,
        total_quizzes=total_quizzes,
        total_questions=total_questions,
        users=users
    )


#CRUD Operations for Subjects

@app.route('/admin_subject')
@admin_required
def admin_subject():
    subjects = Subject.query.all()  # Fetch all subjects
    return render_template('admin_subject.html', subjects=subjects)

@app.route("/add_subject", methods=["POST"])
@admin_required
def add_subject():
    name = request.form.get("name")
    description = request.form.get("description")

    if not name or not description:
        flash("All fields are required!", "danger")
        return redirect(url_for("admin_subject"))

    new_subject = Subject(name=name, description=description)
    db.session.add(new_subject)
    db.session.commit()

    flash("Subject added successfully!", "success")
    return redirect(url_for("admin_subject"))

@app.route("/edit_subject/<int:subject_id>", methods=["GET", "POST"])
@admin_required
def edit_subject(subject_id):
    subject = Subject.query.get_or_404(subject_id)

    if request.method == "POST":
        subject.name = request.form.get("name")
        subject.description = request.form.get("description")
        db.session.commit()
        flash("Subject updated successfully!", "success")
        return redirect(url_for("admin_subject"))

    return render_template("edit_subject.html", subject=subject)

@app.route("/delete_subject/<int:subject_id>", methods=["POST"])
@admin_required
def delete_subject(subject_id):
    subject = Subject.query.get_or_404(subject_id)
    db.session.delete(subject)
    db.session.commit()
    flash("Subject deleted successfully!", "success")
    return redirect(url_for("admin_subject"))


# CRUD Operations for Chapters

@app.route("/subject/<int:subject_id>/chapters")
@admin_required
def show_chapters(subject_id):
    subject = Subject.query.get_or_404(subject_id)
    chapters = Chapter.query.filter_by(subject_id=subject_id).all()
    return render_template("manage_chapters.html", subject=subject, chapters=chapters)

@app.route("/subject/<int:subject_id>/add_chapter", methods=["POST"])
@admin_required
def add_chapter(subject_id):
    name = request.form.get("name")
    description = request.form.get("description")

    if name:
        new_chapter = Chapter(name=name, description=description, subject_id=subject_id)
        db.session.add(new_chapter)
        db.session.commit()
        flash("Chapter added successfully!", "success")

    return redirect(url_for("show_chapters", subject_id=subject_id))

@app.route("/edit_chapter/<int:chapter_id>", methods=["POST"])
@admin_required
def edit_chapter(chapter_id):
    chapter = Chapter.query.get_or_404(chapter_id)
    chapter.name = request.form.get("name")
    chapter.description = request.form.get("description") 
    db.session.commit()
    flash("Chapter updated successfully!", "success")
    return redirect(url_for("show_chapters", subject_id=chapter.subject_id))

@app.route("/delete_chapter/<int:chapter_id>", methods=["POST"])
@admin_required
def delete_chapter(chapter_id):
    chapter = Chapter.query.get_or_404(chapter_id)
    subject_id = chapter.subject_id
    db.session.delete(chapter)
    db.session.commit()
    flash("Chapter deleted successfully!", "success")
    return redirect(url_for("show_chapters", subject_id=subject_id))

#CRUD Operations for Quizzes

@app.route("/chapter/<int:chapter_id>/quizzes")
@admin_required
def show_quizzes(chapter_id):
    chapter = Chapter.query.get_or_404(chapter_id)
    quizzes = Quiz.query.filter_by(chapter_id=chapter_id).all()
    return render_template("show_quizzes.html", chapter=chapter, quizzes=quizzes)

@app.route("/chapter/<int:chapter_id>/add_quiz", methods=["POST"])
@admin_required
def add_quiz(chapter_id):
    title = request.form.get("title")
    duration = request.form.get("duration")

    if not title or not duration:
        flash("Please fill in all fields", "danger")
        return redirect(url_for("show_quizzes", chapter_id=chapter_id))

    new_quiz = Quiz(title=title, duration=int(duration), chapter_id=chapter_id)
    db.session.add(new_quiz)
    db.session.commit()
    flash("Quiz added successfully!", "success")
    
    return redirect(url_for("show_quizzes", chapter_id=chapter_id))

@app.route("/edit_quiz/<int:quiz_id>", methods=["POST"])
@admin_required
def edit_quiz(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    quiz.title = request.form.get("title")
    quiz.duration = int(request.form.get("duration"))

    db.session.commit()
    flash("Quiz updated successfully!", "success")

    return redirect(url_for("show_quizzes", chapter_id=quiz.chapter_id))

@app.route("/delete_quiz/<int:quiz_id>", methods=["POST"])
@admin_required
def delete_quiz(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    chapter_id = quiz.chapter_id  # Save chapter ID before deleting
    db.session.delete(quiz)
    db.session.commit()
    flash("Quiz deleted successfully!", "success")

    return redirect(url_for("show_quizzes", chapter_id=chapter_id))

# CRUD Operations for Questions

@app.route('/admin/quiz/<int:quiz_id>/questions')
@admin_required
def show_questions(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    questions = Question.query.filter_by(quiz_id=quiz_id).all()
    return render_template('show_question.html', quiz=quiz, questions=questions)

@app.route('/admin/quiz/<int:quiz_id>/add_question', methods=['GET', 'POST'])
@admin_required
def add_question(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)

    if request.method == 'POST':
        text = request.form['text']
        option_a = request.form['option_a']
        option_b = request.form['option_b']
        option_c = request.form['option_c']
        option_d = request.form['option_d']
        correct_option = request.form['correct_option']
        marks = request.form['marks']

        new_question = Question(
            quiz_id=quiz_id,
            text=text,
            option_a=option_a,
            option_b=option_b,
            option_c=option_c,
            option_d=option_d,
            correct_option=correct_option,
            marks=int(marks)
        )

        db.session.add(new_question)
        db.session.commit()
        flash('Question added successfully!', 'success')
        return redirect(url_for('show_questions', quiz_id=quiz_id))

    return render_template('add_question.html', quiz=quiz)

@app.route('/admin/question/<int:question_id>/delete', methods=['POST'])
@admin_required
def delete_question(question_id):
    question = Question.query.get_or_404(question_id)
    quiz_id = question.quiz_id
    db.session.delete(question)
    db.session.commit()
    flash("Question deleted successfully!", 'success')
    return redirect(url_for('show_questions', quiz_id=quiz_id))

