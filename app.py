from flask import Flask
from flask_login import LoginManager
from routes import routes
from db import db, User

app = Flask(__name__)

#Flask app config
app.config['SECRET_KEY'] = 'TEAM5QUIZAPP'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///quiz.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

#Intitialize flask db
db.init_app(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    if user_id is not None:
        return User.query.get(int(user_id))
    else:
        return None

#Registering blueprints
app.register_blueprint(routes)

if __name__ == '__main__':
    with app.app_context():
        #Create sqlite db - will update to postgreSQL
        db.create_all()
    app.run(debug=True,port=5008)