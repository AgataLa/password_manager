from passkeeper import db, login_manager
from datetime import datetime
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask_login import UserMixin
from flask import current_app


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


shared_passwords = db.Table('shared_passwords',
    db.Column('user_id', db.ForeignKey('user.id'), primary_key=True),
    db.Column('password_id', db.ForeignKey('password.id'), primary_key=True)
)


class User(db.Model, UserMixin):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    salt = db.Column(db.String(20), nullable=False)
    owned_passwords = db.relationship('Password', backref='owner', lazy=True)
    received_passwords = db.relationship(
        "Password",
        secondary=shared_passwords,
        back_populates="users_shared")

    def get_reset_token(self, expires_sec=1800):
        s = Serializer(current_app.config['SECRET_KEY'], expires_sec)
        return s.dumps({'user_id': self.id}).decode('utf-8')

    @staticmethod
    def verify_reset_token(token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token)['user_id']
        except:
            return None
        return User.query.get(user_id)

    def __repr__(self):
        return f"User('{self.username}', '{self.email}')"


class Password(db.Model):
    __tablename__ = 'password'
    id = db.Column(db.Integer, primary_key=True)
    service_name = db.Column(db.String(100), nullable=False)
    service_password = db.Column(db.String(60))
    date_modified = db.Column(db.DateTime, nullable=False, default=datetime.now)
    iv = db.Column(db.String(20), nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    users_shared = db.relationship(
        "User",
        secondary=shared_passwords,
        back_populates="received_passwords")

    def __repr__(self):
        return f"Password('{self.service_name}', '{self.date_modified}')"


class Attempt(db.Model):
    __tablename__ = 'attempt'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    attempts_left = db.Column(db.Integer, nullable=False, default=3)
    to_date = db.Column(db.DateTime, nullable=False, default=datetime.now)
