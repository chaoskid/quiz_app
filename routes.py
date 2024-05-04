from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from db import db, User, Quiz, Option, UserQuizScore

import bcrypt

def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def verify_password(hashed_password,password):
    return bcrypt.checkpw(password.encode('utf-8'),hashed_password)

routes = Blueprint('routes', __name__)

@routes.route('/')
def index():
    return redirect(url_for('routes.login'))

@routes.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = hash_password(password)
        new_user = User(username=username, pswrd=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash("Registration Successful. Please log in.")
        return redirect(url_for('routes.login'))
    return render_template('register.html', current_user=current_user)


@routes.route('/login', methods = ['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and verify_password(user.pswrd, password):
            login_user(user)
            print("User Logged In")
            return redirect(url_for('routes.dashboard'))
        else:
            print("Not logged in")
            flash('Invalid username or password. Please try again.')
    return render_template('login.html', current_user=current_user)

@routes.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('routes.login'))

@routes.route('/dashboard')
@login_required
def dashboard():
    quizes = Quiz.query.all()

    return render_template('dashboard.html', quizes=quizes,current_user=current_user)


@routes.route('/quiz/<int:quiz_id>', methods=['GET','POST'])
@login_required
def take_quiz(quiz_id):
    quiz=Quiz.query.get(quiz_id)
    user_score = UserQuizScore.query.filter_by(user_id=current_user.id, quiz_id=quiz_id).first()
    if user_score:
        #flash("You have already attempted this quiz")
        return redirect(url_for('routes.quiz_result',  quiz_id=quiz_id))
    
    if request.method == 'POST':
        score = 0
        for question in quiz.questions:
            selected_option_id = int(request.form.get(f'question{question.id}'))
            correct_option_id = Option.query.filter_by(question_id = question.id, is_correct=True).first().id
            if selected_option_id == correct_option_id:
                score = score+1
        #flash(f'Yout score: {score}/{len(quiz.questions)}')
        new_score = UserQuizScore(user_id=current_user.id, quiz_id=quiz_id, score=score)
        db.session.add(new_score)
        db.session.commit()
        return redirect(url_for('routes.quiz_result', quiz_id=quiz_id))
    return render_template('quiz.html', quiz=quiz, current_user=current_user)

@routes.route('/quiz/<int:quiz_id>/result')
@login_required
def quiz_result(quiz_id):
    quiz = Quiz.query.get(quiz_id)
    user_score = current_user.get_score(quiz_id)
    return render_template('quiz_result.html', current_user=current_user,quiz=quiz, user_score=user_score)
        