from flask import render_template, url_for, flash, redirect, request, Blueprint
from flask_login import login_user, current_user, logout_user, login_required
from flask_wtf.csrf import CSRFError
from passkeeper import db
from datetime import datetime, timedelta
import bcrypt
from passkeeper.models import User, Password, Attempt
from passkeeper.users.forms import (RegistrationForm, LoginForm, UpdateAccountForm,
                                    RequestResetForm, ResetPasswordForm, ChangePasswordForm)
from passkeeper.users.utils import send_reset_email, entropy, send_new_ip_email
import os
import time
import random

users = Blueprint('users', __name__)


@users.errorhandler(CSRFError)
def csrf_error(reason):
    return render_template('csrf_error.html', reason=reason)


@users.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('users.my_passwords'))
    form = RegistrationForm()
    if form.validate_on_submit():
        salt = bcrypt.gensalt(15)
        pepper = os.environ.get('PEPPER').encode()
        hashed_password = bcrypt.hashpw(form.password.data.encode() + pepper, salt)
        wait_time = random.uniform(0, 1)
        time.sleep(wait_time)
        user = User(username=form.username.data, email=form.email.data, password=hashed_password, salt=salt)
        db.session.add(user)
        db.session.commit()
        flash('Twoje konto zostało utworzone! Możesz się teraz zalogować', 'success')
        return redirect(url_for('users.login'))
    else:
        if 'csrf_token' in form.errors:
            flash('Zablokowano próbę wykonania żądania.', 'danger')
    return render_template('register.html', title='Zarejestruj', form=form)


@users.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('users.my_passwords'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            attempt = Attempt.query.filter_by(user_id=user.id).first()
            if not attempt:
                att = Attempt(user_id=user.id, attempts_left=3)
                db.session.add(att)
                db.session.commit()
                attempt = att
            else:
                if attempt.attempts_left == 0 and attempt.to_date < datetime.now():
                    attempt.attempts_left = 3
                    db.session.commit()
            if attempt.attempts_left > 0:
                pepper = os.environ.get('PEPPER').encode()
                if bcrypt.checkpw(form.password.data.encode() + pepper, user.password):
                    wait_time = random.uniform(0, 1)
                    time.sleep(wait_time)
                    login_user(user)
                    next_page = request.args.get('next')
                    attempt.attempts_left = 3
                    db.session.commit()
                    # send_new_ip_email(user, str(request.environ['REMOTE_ADDR']))
                    # ip = request.remote_addr
                    # flash("Logowanie z adresu " + ip, 'info')
                    return redirect(next_page) if next_page else redirect(url_for('users.my_passwords'))
                else:
                    attempt.attempts_left -= 1
                    db.session.commit()
                    if attempt.attempts_left == 2:
                        flash('Nie udało się zalogować. Sprawdź poprawność emaila i hasła. Pozostały 2 próby.', 'danger')
                    elif attempt.attempts_left == 1:
                        flash('Nie udało się zalogować. Sprawdź poprawność emaila i hasła. Pozostała 1 próba.', 'danger')
                    else:
                        attempt.to_date = datetime.now() + timedelta(hours=24)
                        db.session.commit()
                        flash('Nie udało się zalogować. Twoje konto zostało zablokowane na 24 godziny.', 'danger')
            else:
                flash('Twoje konto jest zablokowane do ' + attempt.to_date.strftime('%d.%m %H:%M') + '.', 'danger')
        else:
            flash('Nie istnieje konto powiązane z podanym emailem.', 'danger')
    else:
        if 'csrf_token' in form.errors:
            flash('Zablokowano próbę wykonania żądania.', 'danger')
    return render_template('login.html', title='Zaloguj', form=form)


@users.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('users.my_passwords'))


@users.route('/account', methods=['GET', 'POST'])
@login_required
def account():
    form = UpdateAccountForm()
    if form.validate_on_submit():
        current_user.username = form.username.data
        current_user.email = form.email.data
        db.session.commit()
        flash('Twoje konto zostało zaktualizowane!', 'success')
        return redirect(url_for('users.account'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
    else:
        if 'csrf_token' in form.errors:
            flash('Zablokowano próbę wykonania żądania.', 'danger')
    return render_template('account.html', title='Moje konto', form=form)


@users.route('/account/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=current_user.username).first()
        pepper = os.environ.get('PEPPER').encode()
        if user and bcrypt.checkpw(form.old_password.data.encode() + pepper, user.password):
            wait_time = random.uniform(0, 1)
            time.sleep(wait_time)
            entr, extent = entropy(form.confirm_new_password.data)
            hashed_new_password = bcrypt.hashpw(form.confirm_new_password.data.encode() + pepper, user.salt)
            user.password = hashed_new_password
            db.session.commit()
            flash('Twoje hasło zostało zmienione! Entropia hasła: ' + str(round(entr, 2)) + ', stopień: ' + str(round(extent*100, 2)) + '%.', 'success')
            return redirect(url_for('users.account'))
        else:
            flash('Nie udało się zmienić hasła. Niepoprawne stare hasło', 'danger')
    else:
        if 'csrf_token' in form.errors:
            flash('Zablokowano próbę wykonania żądania.', 'danger')
    return render_template('change_password.html', title='Zmień hasło', form=form)


@users.route('/my_passwords')
@login_required
def my_passwords():
    page = request.args.get('page', default=1, type=int)
    passwords = Password.query.filter_by(owner_id=current_user.id)
    received = [p.id for p in current_user.received_passwords]
    re = Password.query.filter(Password.id.in_(received))
    passwords = passwords.union(re).order_by(Password.date_modified.desc()).paginate(page=page, per_page=5)
    return render_template('my_passwords.html', title='Moje hasła', passwords=passwords)


@users.route('/user/<string:username>')
def user_account(username):
    user = User.query.filter_by(username=username).first_or_404()
    return render_template('user_account.html', user=user)


@users.route('/reset_password', methods=['GET', 'POST'])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for('users.my_passwords'))
    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        send_reset_email(user)
        flash('Na podanego emaila została wysłana wiadomość z dalszymi instrukcjami resetowania hasłą', 'info')
        return redirect(url_for('users.login'))
    else:
        if 'csrf_token' in form.errors:
            flash('Zablokowano próbę wykonania żądania.', 'danger')
    return render_template('reset_request.html', title='Zresetuj hasło', form=form)


@users.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('users.my_passwords'))
    user = User.verify_reset_token(token)
    if user is None:
        flash('Niepoprawny lub wygasły token', 'warning')
        return redirect(url_for('users.reset_request'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        pepper = os.environ.get('PEPPER').encode()
        hashed_new_password = bcrypt.hashpw(form.password.data.encode() + pepper, user.salt)
        wait_time = random.uniform(0, 1)
        time.sleep(wait_time)
        user.password = hashed_new_password
        db.session.commit()
        flash('Twoje hasło zostało zmienione! Możesz się teraz zalogować', 'success')
        return redirect(url_for('users.login'))
    else:
        if 'csrf_token' in form.errors:
            flash('Zablokowano próbę wykonania żądania.', 'danger')
    return render_template('reset_token.html', title='Zresetuj hasło', form=form)
