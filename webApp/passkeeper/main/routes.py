from flask import render_template, Blueprint
from flask_wtf.csrf import CSRFError
from passkeeper import db

main = Blueprint('main', __name__)


@main.errorhandler(CSRFError)
def csrf_error(reason):
    return render_template('csrf_error.html', reason=reason)


@main.route('/')
@main.route('/home')
def home():
    # db.create_all()
    return render_template('home.html')
