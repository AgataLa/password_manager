from Crypto.Random import get_random_bytes
from flask import (render_template, url_for, flash,
                   redirect, request, abort, Blueprint)
from flask_login import current_user, login_required
from datetime import datetime
from flask_wtf.csrf import CSRFError
from passkeeper import db
import bcrypt
from passkeeper.models import Password, User
from passkeeper.service_passwords.forms import PasswordForm, SharePasswordForm
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad, pad
import argon2
import os


service_passwords = Blueprint('service_passwords', __name__)


@service_passwords.errorhandler(CSRFError)
def csrf_error(reason):
    return render_template('csrf_error.html', reason=reason)


@service_passwords.route('/password/new', methods=['GET', 'POST'])
@login_required
def new_password():
    form = PasswordForm()
    if form.validate_on_submit():
        main_key = os.environ.get('PASSWORDS_KEY').encode()
        key = argon2.hash_password_raw(main_key, current_user.salt, hash_len=32, type=argon2.Type.ID)
        iv = get_random_bytes(16)
        aes = AES.new(key, AES.MODE_CBC, iv)
        enc_password = aes.encrypt(pad(str.encode(form.service_password.data), AES.block_size))
        service_pass = Password(service_name=form.service_name.data, service_password=enc_password, iv=iv,
                                owner=current_user)
        db.session.add(service_pass)
        db.session.commit()
        flash('Twoje nowe hasło do serwisu ' + form.service_name.data + ' zostało dodane!', 'success')
        return redirect(url_for('users.my_passwords'))
    else:
        if 'csrf_token' in form.errors:
            flash('Zablokowano próbę wykonania żądania.', 'danger')
    return render_template('create_password.html', title='Nowe hasło', form=form, legend='Nowe hasło')


@service_passwords.route('/password/<int:password_id>', methods=['GET', 'POST'])
@login_required
def password(password_id):
    pswd = Password.query.get_or_404(password_id)
    if current_user == pswd.owner or current_user in pswd.users_shared:
        main_key = os.environ.get('PASSWORDS_KEY').encode()
        key = argon2.hash_password_raw(main_key, pswd.owner.salt, hash_len=32, type=argon2.Type.ID)
        iv = pswd.iv
        aes = AES.new(key, AES.MODE_CBC, iv)
        decrypted = unpad(aes.decrypt(pswd.service_password), AES.block_size).decode('utf-8')
    else:
        abort(403)
    return render_template('password.html', title=pswd.service_name, password=pswd, decrypted=decrypted)


@service_passwords.route('/password/<int:password_id>/update', methods=['GET', 'POST'])
@login_required
def update_password(password_id):
    pswd = Password.query.get_or_404(password_id)
    if pswd.owner != current_user:
        abort(403)
    form = PasswordForm()
    if form.validate_on_submit():
        pswd.service_name = form.service_name.data
        main_key = os.environ.get('PASSWORDS_KEY').encode()
        key = argon2.hash_password_raw(main_key, current_user.salt, hash_len=32, type=argon2.Type.ID)
        iv = get_random_bytes(16)
        aes = AES.new(key, AES.MODE_CBC, iv)
        pswd.service_password = aes.encrypt(pad(str.encode(form.service_password.data), AES.block_size))
        pswd.date_modified = datetime.now()
        pswd.iv = iv
        db.session.commit()
        flash('Twoje hasło do serwisu ' + form.service_name.data + ' zostało zaktualizowane!', 'success')
        return redirect(url_for('service_passwords.password', password_id=pswd.id))
    elif request.method == 'GET':
        form.service_name.data = pswd.service_name
        main_key = os.environ.get('PASSWORDS_KEY').encode()
        key = argon2.hash_password_raw(main_key, current_user.salt, hash_len=32, type=argon2.Type.ID)
        iv = pswd.iv
        aes = AES.new(key, AES.MODE_CBC, iv)
        decrypted = unpad(aes.decrypt(pswd.service_password), AES.block_size).decode('utf-8')
        form.service_password.data = decrypted
    else:
        if 'csrf_token' in form.errors:
            flash('Zablokowano próbę wykonania żądania.', 'danger')
    return render_template('create_password.html', title='Zaktualizuj hasło', form=form, legend='Zaktualizuj hasło')


@service_passwords.route('/password/<int:password_id>/delete', methods=['POST'])
@login_required
def delete_password(password_id):
    pswd = Password.query.get_or_404(password_id)
    service_name = pswd.service_name
    if pswd.owner != current_user:
        abort(403)
    db.session.delete(pswd)
    db.session.commit()
    flash('Twoje hasło do serwisu ' + service_name + ' zostało usunięte!', 'success')
    return redirect(url_for('users.my_passwords'))


@service_passwords.route('/password/<int:password_id>/share', methods=['GET', 'POST'])
@login_required
def share_password(password_id):
    pswd = Password.query.get_or_404(password_id)
    if pswd.owner != current_user:
        abort(403)
    form = SharePasswordForm()
    if form.validate_on_submit():
        pepper = os.environ.get("PEPPER").encode()
        if bcrypt.checkpw(form.password.data.encode() + pepper, current_user.password):
            with_user = User.query.filter_by(username=form.username.data).first()
            if with_user is not None:
                if with_user not in pswd.users_shared:
                    pswd.users_shared.append(with_user)
                    db.session.commit()
                    flash('Twoje hasło do serwisu ' + pswd.service_name + ' zostało udostępnione!', 'success')
                    return redirect(url_for('service_passwords.password', password_id=pswd.id))
                else:
                    flash('To hasło już jest udostępnione użytkownikowi o nazwie ' + form.username.data, 'danger')
            else:
                flash('Użytkownik o nazwie ' + form.username.data + ' nie istnieje', 'danger')
        else:
            flash('Niepoprawne hasło', 'danger')
    else:
        if 'csrf_token' in form.errors:
            flash('Zablokowano próbę wykonania żądania.', 'danger')
    return render_template('share_password.html', title='Udostępnij hasło', form=form)


@service_passwords.route('/password/<int:password_id>/delete/<string:username>', methods=['GET', 'POST'])
@login_required
def delete_with_user_password(password_id, username):
    pswd = Password.query.get_or_404(password_id)
    if pswd.owner != current_user:
        abort(403)
    user = User.query.filter_by(username=username).first()
    pswd.users_shared.remove(user)
    db.session.commit()
    flash('Użytkownik ' + username + ' już nie ma dostępu do hasła serwisu ' + pswd.service_name, 'success')
    return redirect(url_for('users.my_passwords'))
