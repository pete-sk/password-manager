from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SubmitField
from wtforms.validators import Length,  DataRequired


class PostForm(FlaskForm):
    title = StringField('Title', validators=[Length(0, 128), DataRequired()])
    author = StringField('Author', validators=[Length(0, 32), DataRequired()])
    content = TextAreaField('Content', validators=[DataRequired()])
    submit = SubmitField('Submit')
