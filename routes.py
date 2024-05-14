from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from flask_login import login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from authenticator import *
from db import db, User, Quiz, Option, UserQuizScore, Question
from question_form import QuizForm

import bcrypt

#bcrypt method to hash password and check hashed password while log in
def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def verify_password(hashed_password,password):
    return bcrypt.checkpw(password.encode('utf-8'),hashed_password)

#initializing routes blueprint
routes = Blueprint('routes', __name__)

#Setting the homepage route to log in.
#Homepage will be set up later
@routes.route('/')
def index():
    return redirect(url_for('routes.login'))

#Register route
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

#Route for admin registration -- Will be updated to a dynamic url log in.
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

#log in route
@routes.route('/login', methods = ['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and verify_password(user.pswrd, password):
            role = user.role
            login_user(user)

            #Updating session for admin log in.
            if role == 'Admin':
                session['admin_logged_in'] = True
            
            # If not admin, setting the session for user logged in
            session['user_logged_in'] = True

            #return to dashboard if log in is successsfull
            return redirect(url_for('routes.dashboard'))
        
        else:
            #Flash message if log in is not successful.
            flash('Invalid username or password. Please try again.')
    
    #Render log in page for get requests
    return render_template('login.html', current_user=current_user)

#Route for log out and admin log out
@routes.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('admin_logged_in', None)
    return redirect(url_for('routes.login'))

#Dashboard route to display available quiz and leaderboard
@routes.route('/dashboard')
@login_required
def dashboard():

    #Querying available quizzes from db
    quizes = Quiz.query.all()

    #Querying users from db for leaderboard.
    users = User.query.all()

    #Calculating the top 5 people in the platform based on scores for all quizzes.
    user_scores = []
    for user in users:
        total_score = sum(score.score for score in user.quiz_scores)
        user_scores.append((user, total_score))
    
    sorted_users = sorted(user_scores, key=lambda x: x[1], reverse=True)
    
    current_user_rank = None
    current_user_score = None

    for index, (user,score) in enumerate(sorted_users,1):

        #Removing admin user from the top performers
        if user.role=="Admin":
            sorted_users.pop(index-1)
            pass
        
        #Setting current user details to highlight in the page
        if current_user.id == user.id:
            current_user_rank = index
            current_user_score = score
        
    #Limiting the dashboard to just 5 records
    top_performers = sorted_users[:5]


    return render_template('dashboard.html', quizes=quizes,current_user=current_user, user_score=current_user_score, current_user_rank=current_user_rank, top_performers=top_performers)

#Route for create quiz
@routes.route('/create_quiz', methods=['GET','POST'])
#Admin required for creating quiz
@admin_required
def create_quiz():

    #Initialize wtf form for quiz
    form = QuizForm()

    #Getting the quiz details on submit
    if request.method == 'POST':
        quiz = Quiz()
        quiz.title=form.title.data
        quiz.description = form.description.data
        quiz.level = form.level.data

        for question_data in form.questions.data:
            if question_data['text'] != None:    
                question = Question(text=question_data['text'], quiz=quiz)

                for option_data in question_data['options']:
                    option = Option(text=option_data['text'], is_correct=option_data['is_correct'], question=question)
                    question.options.append(option)
                
                quiz.questions.append(question)
        
        db.session.add(quiz)
        db.session.commit()

        return redirect(url_for('routes.dashboard'))
    return render_template('create_quiz.html',form=form,current_user=current_user)


#Route for delete quiz
@routes.route('/delete_quiz_by_id/<int:quiz_id>', methods=['GET','POST'])
@admin_required
def delete_quiz_by_id(quiz_id):

    # Find the quiz by ID
    quiz = Quiz.query.get_or_404(quiz_id)
    
    # Delete the quiz
    db.session.delete(quiz)
    
    # Commit the changes
    db.session.commit()
    
    return redirect(url_for('routes.dashboard'))

#Route for quiz attempt page
@routes.route('/quiz/<int:quiz_id>', methods=['GET','POST'])
@login_required
def take_quiz(quiz_id):

    #Querying quiz and user details
    quiz=Quiz.query.get(quiz_id)
    user_score = UserQuizScore.query.filter_by(user_id=current_user.id, quiz_id=quiz_id).first()

    #Redirect to result page if score is already there.
    if user_score:
        return redirect(url_for('routes.quiz_result',  quiz_id=quiz_id))
    
    #Calculating score on quiz submit
    if request.method == 'POST':
        score = 0
        for question in quiz.questions:
            selected_option_id = int(request.form.get(f'question{question.id}'))
            correct_option_id = Option.query.filter_by(question_id = question.id, is_correct=True).first().id
            if selected_option_id == correct_option_id:
                score = score+1
        
        #Boost the score based on the quiz level
        if quiz.level == 'Intermediate':
            score = score + (score * 0.25)
        elif quiz.level == 'Advanced' :
            score = score + (score * 0.5)
        
        #Updating new score to the db
        new_score = UserQuizScore(user_id=current_user.id, quiz_id=quiz_id, score=score)
        
        #Only submit score to db if the user is not an admin.
        if current_user.role != "Admin":
            db.session.add(new_score)
            db.session.commit()
        return redirect(url_for('routes.quiz_result', quiz_id=quiz_id))
    return render_template('quiz.html', quiz=quiz, current_user=current_user)

#Route for rendering the quiz results
@routes.route('/quiz/<int:quiz_id>/result')
@login_required
def quiz_result(quiz_id):

    #Calculating rank for leaderboard.
    current_user_rank = None
    quiz = Quiz.query.get(quiz_id)
    user_score = current_user.get_score(quiz_id)
    quiz_scores = UserQuizScore.query.filter_by(quiz_id=quiz_id).all()
    sorted_scores = sorted(quiz_scores, key=lambda x: x.score, reverse=True)
    if user_score:
        for index, score in enumerate(sorted_scores,1):
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
        