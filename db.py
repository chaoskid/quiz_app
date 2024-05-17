from flask_sqlalchemy import SQLAlchemy

from flask_login import UserMixin

#Initializing db object
db = SQLAlchemy()

#User table
class User(UserMixin, db.Model):
    firstname = db.Column(db.String(100), nullable=False)
    lastname = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(20),nullable=False)
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    pswrd = db.Column(db.String(100), nullable=False)
    total_score = db.Column(db.Integer, default=0)
    quiz_scores = db.relationship('UserQuizScore', backref = 'user', lazy=True)

    def get_score(self, quiz_id):
        score = UserQuizScore.query.filter_by(user_id=self.id, quiz_id=quiz_id, ).first()
        return score.score if score else 0

#Quiz table
class Quiz(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(150), nullable=False)
    level = db.Column(db.String(10), nullable=False)
    questions = db.relationship('Question', backref='quiz', cascade='all, delete-orphan', lazy=True)

#Question table
class Question(db.Model):
    id= db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(100), nullable=False)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id'), nullable=False)
    options = db.relationship('Option', backref='question', cascade='all, delete-orphan', lazy=True)

#Option table
class Option(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(100), nullable=False)
    is_correct = db.Column(db.Boolean, default=False)
    question_id = db.Column(db.Integer, db.ForeignKey('question.id'),nullable=False)

#User quiz score table
class UserQuizScore(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id'), nullable=False)
    score = db.Column(db.Float, nullable=False)


