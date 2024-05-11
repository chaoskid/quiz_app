from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, FieldList, FormField, SubmitField, BooleanField
from wtforms.validators import DataRequired
from wtforms.widgets import RadioInput

class OptionForm(FlaskForm):
    text = StringField('Option', validators=[DataRequired()])
    is_correct = BooleanField('Is Correct')

class QuestionForm(FlaskForm):
    text = StringField('Question', validators=[DataRequired()])
    options = FieldList(FormField(OptionForm), min_entries=4, max_entries=4)

class QuizForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    questions = FieldList(FormField(QuestionForm), min_entries=1, max_entries=5)
    submit = SubmitField('Create Quiz')