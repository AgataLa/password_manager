import datetime
import os
import secrets
import math
from datetime import datetime
from PIL import Image
from flask import url_for, current_app
from flask_mail import Message
from passkeeper import mail


def save_picture(form_picture):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(current_app.root_path, 'static/profile_pics', picture_fn)

    output_size = (125, 125)
    i = Image.open(form_picture)
    i.thumbnail(output_size)
    i.save(picture_path)

    return picture_fn


def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message('Password Reset Request',
                  sender='passKeeper2022@gmail.com',
                  recipients=[user.email])
    msg.body = f'''Aby zresetować hasło kliknij w link poniżej:\n
{url_for('users.reset_token', token=token, _external=True)}

Jeśli prośba o zresetowanie hasła nie pochodzi od Ciebie, zignoruj tę wiadomość, a żadne zmiany nie zostaną wprowadzone'''
    mail.send(msg)


def send_new_ip_email(user, ip):
    msg = Message('Nowe podłączenie do konta',
                  sender='passKeeper2022@gmail.com',
                  recipients=[user.email])
    msg.body = f'''Dzisiaj o godzinie ''' + datetime.now().strftime('%H:%M:%S') + ''' nastąpiło logowanie z nowego adresu IP: '''+ ip + '''.'''
    mail.send(msg)


def entropy(text):
    characters = {}
    for i in text:
        if i not in characters:
            characters[i] = 1
        else:
            characters[i] += 1

    suma = sum(characters.values())
    ent = 0
    for i in characters.keys():
        p = characters[i] / suma
        if p != 0:
            ent -= p * math.log(p, 2)

    max_entropy = -math.log(1/len(text), 2)
    extent = ent / max_entropy
    return ent, extent

