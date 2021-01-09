import onetimepass
from datetime import datetime
from flask import current_app
from flask_login import UserMixin
from itsdangerous import (JSONWebSignatureSerializer as Serializer, TimedJSONWebSignatureSerializer as TimedSerializer,
                          SignatureExpired)

from app import db, login_manager


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(9999), unique=True, nullable=False)
    password = db.Column(db.String(9999), nullable=False)
    otp_secret = db.Column(db.String(9999), nullable=True)
    activated = db.Column(db.Boolean(), nullable=False, default=False)
    master_key = db.Column(db.String(9999), nullable=False)
    managed_passwords = db.relationship('Password', backref='user', lazy='dynamic')
    managed_secure_notes = db.relationship('SecureNote', backref='user', lazy='dynamic')
    managed_credit_cards = db.relationship('CreditCard', backref='user', lazy='dynamic')

    def get_activation_token(self):
        s = Serializer(current_app.config['SECRET_KEY'])
        return s.dumps({'user_id': self.id, 'email': self.email}).decode('utf-8')

    @staticmethod
    def verify_activation_token(token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token)['user_id']
        except:
            return None
        email = s.loads(token)['email']
        return User.query.get(user_id), email

    def get_reset_token(self, expires_seconds=1800):
        s = TimedSerializer(current_app.config['SECRET_KEY'], expires_seconds)
        return s.dumps({'user_id': self.id}).decode('utf-8')

    @staticmethod
    def verify_reset_token(token):
        s = TimedSerializer(current_app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token)['user_id']
        except:
            return None
        return User.query.get(user_id)

    def get_api_token(self, expires_seconds=20):
        s = TimedSerializer(current_app.config['SECRET_KEY'], expires_seconds)
        return s.dumps({'user_id': self.id}).decode('utf-8')

    @staticmethod
    def verify_api_token(token):
        s = TimedSerializer(current_app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token)['user_id']
        except SignatureExpired:
            return 'expired'
        except:
            return None
        return User.query.get(user_id)

    def verify_totp(self, token):
        return onetimepass.valid_totp(token, self.otp_secret)

    def __repr__(self):
        return f"User('{self.id}', '{self.email}')"


class Password(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(9999), nullable=False)
    site = db.Column(db.String(9999), nullable=False)
    username = db.Column(db.String(9999), nullable=False)
    password = db.Column(db.String(9999), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f"Password('{self.name}', '{self.site}', '{self.username}', '{self.password}', '{self.user_id}')"


class SecureNote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(9999), nullable=False)
    content = db.Column(db.String(9999), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f"SecureNote('{self.name}', '{self.content}', '{self.user_id}')"


class CreditCard(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(9999), nullable=False)
    number = db.Column(db.String(9999), nullable=False)
    expiration_date = db.Column(db.String(9999), nullable=False)
    cvv = db.Column(db.String(9999), nullable=False)
    cardholder_name = db.Column(db.String(9999), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f"CreditCard('{self.name}', '{self.number}', '{self.expiration_date}', '{self.cvv}'," \
               f" '{self.cardholder_name}', '{self.user_id}')"


class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(9999), unique=True, nullable=False)

    def __repr__(self):
        return f"Admin('{self.id}', '{self.email}')"


class BlogPost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    author = db.Column(db.String(9999), nullable=False)
    title = db.Column(db.String(9999), nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    content = db.Column(db.Text, nullable=False)

    def __repr__(self):
        return f"Post('{self.author}', '{self.title}', '{self.date_posted}', '{self.content}')"
