from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from db import Quiz, Question, Option

#Modified on 25th April

# Database configuration
DB_URI = 'sqlite:///instance/quiz.db'

# Create the database engine
engine = create_engine(DB_URI)

# Create a session maker
Session = sessionmaker(bind=engine)
session = Session()

# Define models
class QuizData:
    def __init__(self, title, questions_data):
        self.title = title
        self.questions_data = questions_data

class QuestionData:
    def __init__(self, text, options_data):
        self.text = text
        self.options_data = options_data

class OptionData:
    def __init__(self, text, is_correct):
        self.text = text
        self.is_correct = is_correct

# Function to add a quiz to the database
def add_quiz(quiz_data):
    quiz = Quiz(title=quiz_data.title)
    session.add(quiz)
    session.commit()
    
    for q_data in quiz_data.questions_data:
        question = Question(text=q_data.text, quiz_id=quiz.id)
        session.add(question)
        session.commit()
        
        for option_data in q_data.options_data:
            option = Option(text=option_data.text, is_correct=option_data.is_correct, question_id=question.id)
            session.add(option)
            session.commit()

# Example quizzes data
quiz1_data = QuizData(
    title='Math Quiz 5',
    questions_data=[
        QuestionData(
            text='What is 2 * 2?',
            options_data=[
                OptionData(text='4', is_correct=True),
                OptionData(text='5', is_correct=False),
                OptionData(text='3', is_correct=False),
                OptionData(text='6', is_correct=False)
            ]
        ),
        QuestionData(
            text='What is 5 + 6?',
            options_data=[
                OptionData(text='11', is_correct=True),
                OptionData(text='22', is_correct=False),
                OptionData(text='10', is_correct=False),
                OptionData(text='5', is_correct=False)
            ]
        ),
        QuestionData(
            text='What is 11 - 6?',
            options_data=[
                OptionData(text='5', is_correct=True),
                OptionData(text='6', is_correct=False),
                OptionData(text='10', is_correct=False),
                OptionData(text='9', is_correct=False)
            ]
        ),
        QuestionData(
            text='What is 11 + 6?',
            options_data=[
                OptionData(text='17', is_correct=True),
                OptionData(text='16', is_correct=False),
                OptionData(text='18', is_correct=False),
                OptionData(text='19', is_correct=False)
            ]
        )
        # Add more questions here...
    ]
)


add_quiz(quiz1_data)

print("Quizzes and questions added successfully!")