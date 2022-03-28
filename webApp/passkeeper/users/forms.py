from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError, Regexp
from flask_login import current_user
from passkeeper.models import User


class RegistrationForm(FlaskForm):
    username = StringField('Nazwa użytkownika', validators=[DataRequired(),
                                                            Length(min=2, max=20),
                                                            Regexp('^[a-zA-Z0-9_ąęćżźóśłń]*$', message="Dozwolone są tylko litery i cyfry")])
    email = StringField('Email', validators=[DataRequired(),
                                             Length(min=3, max=40),
                                             Email(message="Nieprawidłowy format emaila."),
                                             Regexp('^[a-zA-Z0-9@_.-]*$', message="Dozwolone są tylko litery, cyfry i znaki \"-\", \"_\", \".\" oraz \"@\".")])
    password = PasswordField('Hasło', validators=[DataRequired(),
                                                  Regexp("^(?=.*[a-z])(?=.*[A-Z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-])[a-zA-Z0-9#?!@$%^&*-]{10,30}$",
                                                         message="Hasło musi zawierać co najmniej po 1 małej i wielkiej literze, cyfrze i znaku specjalnym. Długość może wynosić od 10 do 30 znaków.")])
    confirm_password = PasswordField('Potwierdź hasło', validators=[DataRequired(),
                                                                    EqualTo('password', message="Nowe hasło i potwierdzone hasło nie pasują do siebie."),
                                                                    Regexp("^(?=.*[a-z])(?=.*[A-Z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-])[a-zA-Z0-9#?!@$%^&*-]{10,30}$",
                                                         message="Hasło musi zawierać co najmniej po 1 małej i wielkiej literze, cyfrze i znaku specjalnym. Długość może wynosić od 10 do 30 znaków.")])
    submit = SubmitField('Zarejestruj')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Ta nazwa użytkownika jest już zajęta, musisz wybrać inną')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Ten email został już wykorzystany, musisz wybrać inny')



class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(),
                                             Length(min=3, max=40),
                                             Email(message="Nieprawidłowy format emaila."),
                                             Regexp('^[a-zA-Z0-9@_.-]*$',
                                                    message="Dozwolone są tylko litery, cyfry i znaki \"-\", \"_\", \".\" oraz \"@\".")])
    password = PasswordField('Hasło', validators=[DataRequired(),
                                                  Regexp(
                                                      "^(?=.*[a-z])(?=.*[A-Z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-])[a-zA-Z0-9#?!@$%^&*-]{10,30}$",
                                                      message="Hasło musi zawierać co najmniej po 1 małej i wielkiej literze, cyfrze i znaku specjalnym. Długość może wynosić od 10 do 30 znaków.")])
    submit = SubmitField('Zaloguj')


class UpdateAccountForm(FlaskForm):
    username = StringField('Nazwa użytkownika', validators=[DataRequired(),
                                                            Length(min=2, max=20),
                                                            Regexp('^[a-zA-Z0-9_ąęćżźóśłń]*$', message="Dozwolone są tylko litery i cyfry")])
    email = StringField('Email', validators=[DataRequired(),
                                             Length(min=3, max=40),
                                             Email(message="Nieprawidłowy format emaila."),
                                             Regexp('^[a-zA-Z0-9@_.-]*$', message="Dozwolone są tylko litery, cyfry i znaki \"-\", \"_\", \".\" oraz \"@\".")])
    submit = SubmitField('Zapisz')

    def validate_username(self, username):
        if username.data != current_user.username:
            user = User.query.filter_by(username=username.data).first()
            if user:
                raise ValidationError('Ta nazwa użytkownika jest już zajęta, musisz wybrać inną')

    def validate_email(self, email):
        if email.data != current_user.email:
            user = User.query.filter_by(email=email.data).first()
            if user:
                raise ValidationError('Ten email został już wykorzystany, musisz wybrać inny')


class RequestResetForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(),
                                             Length(min=3, max=40),
                                             Email(message="Nieprawidłowy format emaila."),
                                             Regexp('^[a-zA-Z0-9@_.-]*$',
                                                    message="Dozwolone są tylko litery, cyfry i znaki \"-\", \"_\", \".\" oraz \"@\".")])
    submit = SubmitField('Prośba o reset hasła')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is None:
            raise ValidationError('Nie istnieje konto powiązane z tym emailem, musisz się najpierw zarejestrować')


class ResetPasswordForm(FlaskForm):
    password = PasswordField('Hasło', validators=[DataRequired(),
                                                  Regexp(
                                                      "^(?=.*[a-z])(?=.*[A-Z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-])[a-zA-Z0-9#?!@$%^&*-]{10,30}$",
                                                      message="Hasło musi zawierać co najmniej po 1 małej i wielkiej literze, cyfrze i znaku specjalnym. Długość może wynosić od 10 do 30 znaków.")])
    confirm_password = PasswordField('Potwierdź hasło', validators=[DataRequired(),
                                                                    EqualTo('password'),
                                                                    Regexp(
                                                                        "^(?=.*[a-z])(?=.*[A-Z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-])[a-zA-Z0-9#?!@$%^&*-]{10,30}$",
                                                                        message="Hasło musi zawierać co najmniej po 1 małej i wielkiej literze, cyfrze i znaku specjalnym. Długość może wynosić od 10 do 30 znaków.")
                                                                    ])
    submit = SubmitField('Zresetuj hasło')


class ChangePasswordForm(FlaskForm):
    old_password = PasswordField('Stare hasło', validators=[DataRequired(),
                                                            Regexp(
                                                                "^(?=.*[a-z])(?=.*[A-Z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-])[a-zA-Z0-9#?!@$%^&*-]{10,30}$",
                                                                message="Hasło musi zawierać co najmniej po 1 małej i wielkiej literze, cyfrze i znaku specjalnym. Długość może wynosić od 10 do 30 znaków.")
                                                            ])
    new_password = PasswordField('Nowe hasło', validators=[DataRequired(),
                                                           Regexp(
                                                               "^(?=.*[a-z])(?=.*[A-Z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-])[a-zA-Z0-9#?!@$%^&*-]{10,30}$",
                                                               message="Hasło musi zawierać co najmniej po 1 małej i wielkiej literze, cyfrze i znaku specjalnym. Długość może wynosić od 10 do 30 znaków.")
                                                           ])
    confirm_new_password = PasswordField('Potwierdź nowe hasło', validators=[DataRequired(),
                                                                             EqualTo('new_password', message="Nowe hasło i potwierdzone hasło nie pasują do siebie."),
                                                                             Regexp(
                                                                                 "^(?=.*[a-z])(?=.*[A-Z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-])[a-zA-Z0-9#?!@$%^&*-]{10,30}$",
                                                                                 message="Hasło musi zawierać co najmniej po 1 małej i wielkiej literze, cyfrze i znaku specjalnym. Długość może wynosić od 10 do 30 znaków.")
                                                                             ])
    submit = SubmitField('Zresetuj hasło')

