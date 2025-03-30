from flask import render_template,request,redirect,url_for, flash,session, send_file,Response
from app import app
from models import db, User, Subject ,Chapter, Quiz, Question, Score
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import sqlite3
import csv
import os
import matplotlib
matplotlib.use('Agg')  # Add this line before importing pyplot
import matplotlib.pyplot as plt
import io
import base64
from sqlalchemy.orm import aliased
from sqlalchemy.sql import func
 
 
def auth_required(func):
    @wraps(func)
    def inner(*args, **kwargs):
        if 'user_id' not in session:
            # Agar user already login page pe hai to wapas login pe na bheje
            if request.endpoint in ['login', 'register', 'login_post', 'register_post']:
                return func(*args, **kwargs)
            flash('Please login to continue')
            return redirect(url_for("login"))
        return func(*args, **kwargs)
    return inner

def admin_required(func):
    @wraps(func)
    def inner(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to continue')
            return redirect(url_for('login'))
        user = User.query.get(session['user_id'])
        if  not user.is_admin:
            flash('You are not authorized to access this page')
            return redirect(url_for('home'))
        return func(*args, **kwargs)
    return inner


@app.route("/")
def home():
    user_id = session.get('user_id')  # Fix
    if not user_id:
        flash("Registered successfully ,now login", "success")
        return redirect(url_for("login"))

    user = User.query.get(user_id)
    if user.is_admin:
        return redirect(url_for("admin"))
    else:
        
        return redirect(url_for('user'))
    
    return render_template("index.html")





@app.route("/register")
def register():
    return redirect(url_for("home"))

@app.route("/login")
def login():
    return render_template("index.html")

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
    flash("Login successfully", "success")
    return redirect(url_for("home"))


@app.route("/register", methods=["POST"])
@auth_required
def register_post():
    username = request.form.get("txt")
    email = request.form.get("email")
    password = request.form.get("pwd")
    confirm_password = request.form.get("c_pwd")
    name = request.form.get("name")
     
    if not username or not password or not confirm_password:
        flash('Please fill out all fields')
        return redirect(url_for('register'))
    
    if password != confirm_password:   
        flash('Passwords do not match')
        return redirect(url_for('register'))
    
    user = User.query.filter_by(username=username).first()
    user1 = User.query.filter_by(email=email).first()
    if user:
        flash('Username already exists')
        return redirect(url_for('register'))
    if user1:
        flash('email already exists')
        return redirect(url_for('register'))
    password_hash = generate_password_hash(password)

    new_user = User(username=username,email=email,password=password_hash,name=name)
    db.session.add(new_user)
    db.session.commit()
    return redirect(url_for('home'))



@app.route('/homepage')
@auth_required
def homepage():
    return render_template("homepage.html")
 

@app.route('/profile')
@auth_required
def profile():
    user=User.query.get(session['user_id'])
    return render_template("profile.html",user=user)

@app.route('/user_profile')
@auth_required
def user_profile():
    user=User.query.get(session['user_id'])
    return render_template("user_profile.html",user=user)

@app.route('/profile', methods=['POST'])
@auth_required
def profile_post():
    username = request.form.get('username')
    cpassword = request.form.get('current_password')
    password = request.form.get('new_password')
    name = request.form.get('name')
    email = request.form.get('email')
    
    if not username or not cpassword or not password or not email:
        flash('Please fill out all the required fields')
        return redirect(url_for('profile'))
    
    user = User.query.get(session['user_id'])
    if not check_password_hash(user.password, cpassword):
        flash('Incorrect password')
        return redirect(url_for('profile'))
    
    if username != user.username:
        new_username = User.query.filter_by(username=username).first()
        if new_username:
            flash('Username already exits')
            return redirect(url_for('profile'))
    if email != user.email:
        new_email = User.query.filter_by(email=email).first()
        if new_email:
            flash('email already exits')
            return redirect(url_for('profile'))
    
    new_password_hash = generate_password_hash(password)
    user.username = username
    user.password = new_password_hash
    user.name = name
    user.email=email
    db.session.commit()
    flash('Profile updated successfully')
    return redirect(url_for('profile'))

@app.route('/logout')
@auth_required
def logout():
    session.pop('user_id')
    return redirect(url_for('home'))

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

    # Create a new Subject object
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

@app.route("/delete_subject/<int:subject_id>", methods=["GET", "POST"])
@admin_required
def delete_subject(subject_id):
    subject = Subject.query.get_or_404(subject_id)
    db.session.delete(subject)
    db.session.commit()
    flash("Subject deleted successfully!", "success")
    return redirect(url_for("admin_subject"))

 
@app.route("/subject/<int:subject_id>/chapters")
@admin_required
def show_chapters(subject_id):
    subject = Subject.query.get_or_404(subject_id)
    chapters = Chapter.query.filter_by(subject_id=subject_id).all()
    return render_template("manage_chapters.html", subject=subject, chapters=chapters)

@app.route("/manage_chapters/<int:subject_id>")
@admin_required
def manage_chapters(subject_id):
    subject = Subject.query.get_or_404(subject_id)
    chapters = subject.chapters  # Get all chapters linked to this subject
    return render_template("manage_chapters.html", subject=subject, chapters=chapters)

@app.route("/subject/<int:subject_id>/add_chapter", methods=["POST"])
@admin_required
def add_chapter(subject_id):
    name = request.form.get("name")
    description = request.form.get("description")
    if name:
        new_chapter = Chapter(name=name, description=description ,subject_id=subject_id)
        db.session.add(new_chapter)
        db.session.commit()
        flash("Chapter added successfully!", "success")
    return redirect(url_for("show_chapters", subject_id=subject_id))
 


@app.route('/add_chapter', methods=['GET', 'POST'])
@admin_required
def add_chapters():
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        subject_id = request.form['subject_id']

        if not name or not subject_id:
            flash("Chapter Name and Subject are required!", "danger")
        else:
            new_chapter = Chapter(name=name, description=description, subject_id=subject_id)
            db.session.add(new_chapter)
            db.session.commit()
            flash("Chapter added successfully!", "success")
            return redirect(url_for('add_chapters'))  # Redirect to prevent form resubmission

    subjects = Subject.query.all()  # Fetch all subjects to show in dropdown
    chapters = Chapter.query.all()
    return render_template('add_chapter.html', subjects=subjects,chapters=chapters)


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

@app.route('/add_quizs', methods=['GET', 'POST'])
@admin_required
def add_quizs():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        duration = request.form['duration']
        chapter_id = request.form['chapter_id']

        if not title or not chapter_id or not duration:
            flash("Quiz Title, Chapter, and Duration are required!", "danger")
        else:
            new_quiz = Quiz(
                title=title,
                description=description,
                duration=int(duration),
                chapter_id=int(chapter_id)
            )
            db.session.add(new_quiz)
            db.session.commit()
            flash("Quiz added successfully!", "success")
            return redirect(url_for('add_quizs'))  # Prevent form resubmission

    chapters = Chapter.query.all()  # Fetch all chapters for selection
    quizzes = Quiz.query.all()
    return render_template('add_quizs.html', chapters=chapters, quizzes=quizzes)


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

@app.route('/admin/quiz/<int:quiz_id>/questions')
@admin_required
def show_questions(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    questions = Question.query.filter_by(quiz_id=quiz_id).all()
    return render_template('show_question.html', quiz=quiz, questions=questions)

# Add a new question
@app.route('/admin/quiz/<int:quiz_id>/add_question', methods=['GET', 'POST'])
@admin_required
def add_question(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)

    if request.method == 'POST':
        try:
            text = request.form['text']
            option_a = request.form['option_a']
            option_b = request.form['option_b']
            option_c = request.form['option_c']
            option_d = request.form['option_d']
            correct_option = request.form['correct_option']  # FIXED
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
        
        except KeyError as e:
            flash(f"Missing form field: {str(e)}", "danger")
            return redirect(url_for('add_question', quiz_id=quiz_id))

    return render_template('add_question.html', quiz=quiz)

# Edit a question
@app.route('/admin/question/<int:question_id>/edit', methods=['GET', 'POST'])
@admin_required
def edit_question(question_id):
    question = Question.query.get_or_404(question_id)
    
    if request.method == 'POST':
        question.text = request.form['text']
        question.option_a = request.form['option_a']
        question.option_b = request.form['option_b']
        question.option_c = request.form['option_c']
        question.option_d = request.form['option_d']
        question.correct_answer = request.form['correct_answer']
        
        db.session.commit()
        flash("Question updated successfully!", 'success')
        return redirect(url_for('show_questions', quiz_id=question.quiz_id))
    
    return render_template('admin/edit_question.html', question=question)

# Delete a question
@app.route('/admin/question/<int:question_id>/delete', methods=['POST'])
@admin_required
def delete_question(question_id):
    question = Question.query.get_or_404(question_id)
    quiz_id = question.quiz_id
    db.session.delete(question)
    db.session.commit()
    flash("Question deleted successfully!", 'success')
    return redirect(url_for('show_questions', quiz_id=quiz_id))


 

@app.route('/block_user/<int:user_id>')
@admin_required
def block_user(user_id):
    user = User.query.get(user_id)
    if user:
        user.status = "blocked"
        db.session.commit()
        flash(f"User {user.username} has been blocked.", "danger")
    return redirect(url_for('admin'))

@app.route('/unblock_user/int:user_id')
@admin_required
def unblock_user(user_id):
    user = User.query.get(user_id)
    if user:
        user.status = "active"
        db.session.commit()
        flash(f"User {user.username} has been unblocked.", "success")
    return redirect(url_for('admin'))
 
 
@app.route('/search', methods=['GET'])
@admin_required
def search():
    query = request.args.get('query', '').strip()  # Get search query from URL

    if query:
        # Perform case-insensitive search on quizzes, subjects, and chapters
        quizzes = Quiz.query.filter(Quiz.title.ilike(f"%{query}%")).all()
        subjects = Subject.query.filter(Subject.name.ilike(f"%{query}%")).all()
        chapters = Chapter.query.filter(Chapter.name.ilike(f"%{query}%")).all()
    else:
        quizzes, subjects, chapters = [], [], []

    return render_template('search_results.html', query=query, quizzes=quizzes, subjects=subjects, chapters=chapters)

 

@app.route('/admin/report')
@admin_required
def admin_report():
    # Check if the user is logged in and is an admin
    user_id = session.get('user_id')
    if not user_id:
        flash("You must be logged in as an admin to access this page.", "danger")
        return redirect(url_for('login'))
    
    user = User.query.get(user_id)
    if not user or not user.is_admin:
        flash("Access Denied! Only admins can view reports.", "danger")
        return redirect(url_for('dashboard'))

    # 📌 1. Number of Chapters per Subject
    subjects = Subject.query.all()
    subject_data = {sub.name: len(sub.chapters) for sub in subjects}

    plt.figure(figsize=(8, 5))
    plt.bar(subject_data.keys(), subject_data.values(), color='blue')
    plt.xlabel("Subjects")
    plt.ylabel("Number of Chapters")
    plt.title("Chapters per Subject")
    plt.xticks(rotation=45)

    img1 = io.BytesIO()
    plt.savefig(img1, format='png')
    img1.seek(0)
    chart1_url = base64.b64encode(img1.getvalue()).decode()

    # 📌 2. Number of Quizzes per Chapter
    chapters = Chapter.query.all()
    chapter_data = {ch.name: len(ch.quizzes) for ch in chapters}

    plt.figure(figsize=(8, 5))
    plt.bar(chapter_data.keys(), chapter_data.values(), color='green')
    plt.xlabel("Chapters")
    plt.ylabel("Number of Quizzes")
    plt.title("Quizzes per Chapter")
    plt.xticks(rotation=45)

    img2 = io.BytesIO()
    plt.savefig(img2, format='png')
    img2.seek(0)
    chart2_url = base64.b64encode(img2.getvalue()).decode()

    # 📌 3. Number of Questions per Quiz
    quizzes = Quiz.query.all()
    quiz_data = {q.title: len(q.questions) for q in quizzes}

    plt.figure(figsize=(8, 5))
    plt.bar(quiz_data.keys(), quiz_data.values(), color='red')
    plt.xlabel("Quizzes")
    plt.ylabel("Number of Questions")
    plt.title("Questions per Quiz")
    plt.xticks(rotation=45)

    img3 = io.BytesIO()
    plt.savefig(img3, format='png')
    img3.seek(0)
    chart3_url = base64.b64encode(img3.getvalue()).decode()

    return render_template('admin_report.html', chart1_url=chart1_url, chart2_url=chart2_url, chart3_url=chart3_url)

@app.route("/chapter/<int:chapter_id>/quizzes")
def chapter_quizzes(chapter_id):
    chapter = Chapter.query.get_or_404(chapter_id)
    quizzes = Quiz.query.filter_by(chapter_id=chapter_id).all()
    return render_template("chapter_quizzes.html", chapter=chapter, quizzes=quizzes)

@app.route('/user')
@auth_required
def user():
    return render_template('user.html')

@app.route('/user_dashboard')
def user_dashboard():
    user_id = session.get('user_id')  # Get user_id from session
    
    if not user_id:  # If no user is logged in, redirect to login
        flash("You must be logged in to access the dashboard.", "danger")
        return redirect(url_for('login'))

    user = User.query.get(user_id)  # Fetch user object from database

    if not user:  # If user is not found in DB, redirect to login
        flash("User not found!", "danger")
        return redirect(url_for('login'))
    quizzes = Quiz.query.all()
    return render_template("user.html", user=user,quizzes=quizzes)

@app.route("/start_quiz/<int:quiz_id>")
def start_quiz(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    return render_template("quiz.html", quiz=quiz)

@app.route('/user/subjects')
def user_subjects():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    subjects = Subject.query.all()  # Modify if subjects are linked to users

    return render_template('user_subjects.html', subjects=subjects)

@app.route('/user/chapter/<int:chapter_id>')
def user_chapter_detail(chapter_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    chapter = Chapter.query.get_or_404(chapter_id)
    
    return render_template('user_chapter.html', chapter=chapter)

@app.route('/user/chapters')
def user_chapters():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    chapters = Chapter.query.all()  # Modify if chapters are linked to subjects or users

    return render_template('user_chapters.html', chapters=chapters)

@app.route('/user/quiz/<int:quiz_id>')
def user_quiz_detail(quiz_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    quiz = Quiz.query.get_or_404(quiz_id)
    
    return render_template('user_quiz.html', quiz=quiz)


@app.route('/user/quiz/<int:quiz_id>/questions')
def user_quiz_questions(quiz_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    quiz = Quiz.query.get_or_404(quiz_id)
    questions = quiz.questions  # Assuming a relationship between Quiz and Questions

    return render_template('user_questions.html', quiz=quiz, questions=questions)

@app.route('/user/quizzes')
def user_quizzes():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']

    # Fetch quizzes taken by the user
    user = User.query.get(user_id)
    quizzes = user.quizzes  # Accessing the quizzes via the many-to-many relationship

    return render_template('user_quizzes.html', quizzes=quizzes)

@app.route('/my_quiz')
def my_quiz():
    quizzes = Quiz.query.all()  # Fetch all quizzes
    return render_template('my_quiz.html', quizzes=quizzes)

@app.route('/quiz_questions/<int:quiz_id>')
def quiz_questions(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)  # Fetch quiz by ID
    questions = Question.query.filter_by(quiz_id=quiz.id).all()  # Fetch questions for the quiz
    return render_template('quiz_questions.html', quiz=quiz, questions=questions)

@app.route('/my_quizzes')
def my_quizzes():
    user_id = session.get('user_id')
    attempted_quizzes = (
        db.session.query(Quiz, Score)
        .join(Score, Quiz.id == Score.quiz_id)
        .filter(Score.user_id == user_id)
        .all()
    )

    return render_template('my_quizzes.html', attempted_quizzes=attempted_quizzes)

# def attempt_quiz(user_id, quiz_id):
    # from models import UserQuiz

    # user_quiz = UserQuiz(user_id=user_id, quiz_id=quiz_id)
    # db.session.add(user_quiz)
    # db.session.commit()
@app.route('/quiz/<int:quiz_id>', methods=['GET', 'POST'])
def attempt_quiz(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    questions = quiz.questions

    if request.method == 'POST':
        correct_count = 0
        total_questions = len(questions)

        for question in questions:
            selected_option = request.form.get(f'question_{question.id}')
            if selected_option and selected_option == question.correct_option:
                correct_count += 1

        # Save the attempt
        score = Score(user_id=session['user_id'], quiz_id=quiz_id, total_scored=correct_count)
        db.session.add(score)
        db.session.commit()

        return redirect(url_for('quiz_result', quiz_id=quiz_id, correct=correct_count, total=total_questions))

    return render_template('attempt_quiz.html', quiz=quiz, questions=questions)

@app.route('/quiz_result/<int:quiz_id>/<int:correct>/<int:total>')
def quiz_result(quiz_id, correct, total):
    quiz = Quiz.query.get_or_404(quiz_id)
    return render_template('quiz_result.html', quiz=quiz, correct=correct, total=total)

@app.route('/my_scores')
def my_scores():
    if 'user_id' not in session:
        return redirect(url_for('login'))  # Redirect if not logged in

    user_id = session['user_id']
    user = User.query.get(user_id)

    if not user:
        return "User not found", 404

    scores = Score.query.filter_by(user_id=user_id).all()  # Fetch user's scores

    return render_template('my_scores.html', scores=scores)

def record_score(user_id, quiz_id, total_scored):
    score = Score(user_id=user_id, quiz_id=quiz_id, total_scored=total_scored)
    db.session.add(score)
    db.session.commit()

@app.route('/settings', methods=['GET', 'POST'])
def settings():
    if 'user_id' not in session:
        return redirect(url_for('login'))  # Redirect if not logged in

    user_id = session['user_id']
    user = User.query.get(user_id)

    if request.method == 'POST':
        # Update user details
        user.name = request.form.get('name')
        user.email = request.form.get('email')
        user.username = request.form.get('username')

        # If password is provided, update it
        new_password = request.form.get('password')
        if new_password:
            user.password = generate_password_hash(new_password)

        db.session.commit()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('settings'))

    return render_template('settings.html', user=user)


@app.route('/subjects')
def subjects():
    subjects = Subject.query.all()
    return render_template('subjects.html', subjects=subjects)

@app.route('/chapters/<int:subject_id>')
def chapters(subject_id):
    subject = Subject.query.get_or_404(subject_id)
    return render_template('chapters.html', subject=subject, chapters=subject.chapters)

@app.route('/quizzes/<int:chapter_id>')
def quizzes(chapter_id):
    chapter = Chapter.query.get_or_404(chapter_id)
    return render_template('quizzes.html', chapter=chapter, quizzes=chapter.quizzes)

@app.route('/questions/<int:quiz_id>')
def questions(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    return render_template('questions.html', quiz=quiz, questions=quiz.questions)