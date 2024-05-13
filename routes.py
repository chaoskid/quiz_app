from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from flask_login import login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from authenticator import *
from db import db, User, Quiz, Option, UserQuizScore, Question
from question_form import QuizForm

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
        firstname = request.form['firstname']
        lastname = request.form['lastname']
        role = request.form['role']
        username = request.form['username']
        password = request.form['password']
        hashed_password = hash_password(password)
        new_user = User(firstname=firstname, lastname=lastname, role=role, username=username, pswrd=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash("Registration Successful. Please log in.")
        return redirect(url_for('routes.login'))
    return render_template('register.html', current_user=current_user)

@routes.route('/admin_register', methods=['GET', 'POST'])
def admin_register():
    if request.method == 'POST':
        firstname = request.form['firstname']
        lastname = request.form['lastname']
        role = request.form['role']
        username = request.form['username']
        password = request.form['password']
        hashed_password = hash_password(password)
        new_user = User(firstname=firstname, lastname=lastname, role=role, username=username, pswrd=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash("Registration Successful. Please log in.")
        return redirect(url_for('routes.login'))
    return render_template('admin_signup.html', current_user=current_user)


@routes.route('/login', methods = ['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and verify_password(user.pswrd, password):
            role = user.role
            login_user(user)
            if role == 'Admin':
                session['admin_logged_in'] = True
                print("Admin Logged In")
            session['user_logged_in'] = True
            print("User Logged In")
            print(session)
            return redirect(url_for('routes.dashboard'))
        else:
            print("Not logged in")
            flash('Invalid username or password. Please try again.')
    return render_template('login.html', current_user=current_user)

@routes.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('admin_logged_in', None)
    return redirect(url_for('routes.login'))

@routes.route('/dashboard')
@login_required
def dashboard():
    quizes = Quiz.query.all()
    users = User.query.all()

    user_scores = []
    for user in users:
        total_score = sum(score.score for score in user.quiz_scores)
        user_scores.append((user, total_score))
    
    sorted_users = sorted(user_scores, key=lambda x: x[1], reverse=True)
    print(sorted_users)
    print(current_user.id)
    for index, (user,score) in enumerate(sorted_users,1):
        if user.role=="Admin":
            sorted_users.pop(index-1)
            pass
        if current_user.id == user.id:
            current_user_rank = index
            current_user_score = score
    print(current_user_rank)
    top_performers = sorted_users[:5]


    return render_template('dashboard.html', quizes=quizes,current_user=current_user, user_score=current_user_score, current_user_rank=current_user_rank, top_performers=top_performers)

@routes.route('/create_quiz', methods=['GET','POST'])
@admin_required
def create_quiz():
    form = QuizForm()
    if request.method == 'POST':
    #if form.validate_on_submit():
        print("*****************")
        quiz = Quiz()
        quiz.title=form.title.data
        quiz.description = form.description.data
        quiz.level = form.level.data
        print(quiz.title)
        for question_data in form.questions.data:
            print("------------------")
            print(question_data['text'])
            if question_data['text'] != None:    
                question = Question(text=question_data['text'], quiz=quiz)
                print(question.text)
                print("*****************")
                for option_data in question_data['options']:
                    option = Option(text=option_data['text'], is_correct=option_data['is_correct'], question=question)
                    question.options.append(option)
                quiz.questions.append(question)
        db.session.add(quiz)
        db.session.commit()
        print('Quiz created successfully!')
        return redirect(url_for('routes.dashboard'))
    return render_template('create_quiz.html',form=form,current_user=current_user)


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
        if current_user.role != "Admin":
            db.session.add(new_score)
            db.session.commit()
        return redirect(url_for('routes.quiz_result', quiz_id=quiz_id))
    return render_template('quiz.html', quiz=quiz, current_user=current_user)

@routes.route('/quiz/<int:quiz_id>/result')
@login_required
def quiz_result(quiz_id):
    current_user_rank = None
    quiz = Quiz.query.get(quiz_id)
    user_score = current_user.get_score(quiz_id)
    quiz_scores = UserQuizScore.query.filter_by(quiz_id=quiz_id).all()
    sorted_scores = sorted(quiz_scores, key=lambda x: x.score, reverse=True)
    if user_score:
        for index, score in enumerate(sorted_scores,1):
            print(index,score.score)
            if score.score == user_score:
                current_user_rank = index
                break
    if current_user_rank !=None:
        if current_user_rank <= 5:
            current_user_rank=None
    top_performers = sorted_scores[:5]
    top_performers_details = [(User.query.get(score.user_id), score) for score in top_performers]

    current_user_details = (current_user, user_score) if user_score else None

    return render_template('quiz_result.html', top_performers=top_performers_details, current_user=current_user,quiz=quiz, user_score=user_score, current_user_rank=current_user_rank)
        