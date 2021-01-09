from flask import flash
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from flask_login import current_user

from app import bcrypt
from app.models import User


class RegistrationForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Length(min=0, max=128), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=0, max=128)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Email already in use!')


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')


class TFAForm(FlaskForm):
    security_code = StringField('Security Code', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Submit')


class RequestResetForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Submit')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if not user:
            raise ValidationError('There is no account with this email.')


class ResetPasswordForm(FlaskForm):
    password = PasswordField('New Password', validators=[DataRequired(), Length(min=0, max=128)])
    confirm_password = PasswordField('Confirm New Password', validators=[DataRequired(), EqualTo('password')])
    master_key = StringField('Master Key', validators=[Length(min=0, max=32)])
    master_key_file = FileField('', validators=[FileAllowed(['txt'], 'Must be .txt file')])
    lost_master_key = BooleanField('I have lost my master key and agree to permanently erase all my saved passwords')
    submit = SubmitField('Reset Password')


class UpdateAccountForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Length(min=0, max=128), Email()])
    current_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[Length(min=0, max=128)])
    confirm_password = PasswordField('Confirm New Password', validators=[EqualTo('new_password')])
    submit = SubmitField('Update')

    def validate_email(self, email):
        if email.data != current_user.email:
            user = User.query.filter_by(email=email.data).first()
            if user:
                raise ValidationError('Email already in use!')

    def validate_current_password(self, current_password):
        if not bcrypt.check_password_hash(current_user.password.encode(), current_password.data):
            flash('The entered current password is incorrect!', 'danger')
            raise ValidationError()


class ChangeMasterKeyForm(FlaskForm):
    master_key = StringField('Master Key', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Save')


class Enable2FAForm(FlaskForm):
    secret = StringField('Secret', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Enable')


class PasswordPrompt(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('')
