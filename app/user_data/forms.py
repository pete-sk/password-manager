from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SubmitField
from flask_wtf.file import FileField, FileAllowed
from wtforms.widgets import PasswordInput
from wtforms.validators import Length, DataRequired


class ImportDataForm(FlaskForm):
    master_key = StringField('Master Key', validators=[DataRequired()])
    file = FileField('File', validators=[DataRequired(), FileAllowed(['json'], 'Must be .json file')])
    submit = SubmitField('')


class NewPasswordForm(FlaskForm):
    name = StringField('Name', validators=[Length(min=0, max=128)])
    site = StringField('Site', validators=[Length(min=0, max=128)])
    username = StringField('Username', validators=[Length(min=0, max=128)])
    password = StringField('Password', widget=PasswordInput(hide_value=False), validators=[Length(min=0, max=128)])
    submit = SubmitField('Save')


class NewSecureNoteForm(FlaskForm):
    name = StringField('Title', validators=[Length(min=0, max=128)])
    content = TextAreaField('Content')
    submit = SubmitField('Save')


class NewCreditCardForm(FlaskForm):
    name = StringField('Name', validators=[Length(min=0, max=128)])
    number = StringField('Card Number', validators=[Length(min=0, max=19)])
    expiration_date = StringField('Expiration Date (MM/YY)', validators=[Length(min=0, max=5)])
    cvv = StringField('Security Code (CVV)', validators=[Length(min=0, max=3)])
    cardholder_name = StringField('Cardholder Name', validators=[Length(min=0, max=128)])
    submit = SubmitField('Save')


class SearchForm(FlaskForm):
    query = StringField('Search', validators=[DataRequired()])
    submit = SubmitField('')
