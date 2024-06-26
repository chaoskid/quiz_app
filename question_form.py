from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, FieldList, FormField, SubmitField, BooleanField, SelectField, TextAreaField
from wtforms.validators import DataRequired
from wtforms.widgets import RadioInput

#Defining Option form
class OptionForm(FlaskForm):
    text = StringField('Option:', validators=[DataRequired()])
    is_correct = BooleanField('Is Correct:')

#Defining Question form
class QuestionForm(FlaskForm):
    text = StringField('Question:', validators=[DataRequired()])
    options = FieldList(FormField(OptionForm), min_entries=4, max_entries=4)

#Quiz form
class QuizForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    description = TextAreaField('Description',validators=[DataRequired()])
    choices = [("Basic","Basic"),("Intermediate","Intermediate"),("Advanced","Advanced")]
    level= SelectField("Quiz Level", choices=choices)
    questions = FieldList(FormField(QuestionForm), min_entries=1, max_entries=5)
    submit = SubmitField('Create Quiz')