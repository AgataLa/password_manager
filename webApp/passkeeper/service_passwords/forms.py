from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, Regexp, Length


class PasswordForm(FlaskForm):
    service_name = StringField('Nazwa serwisu', validators=[DataRequired(),
                                                            Length(max=40),
                                                            Regexp('^[a-zA-Z0-9 ąęćżźóśłń_-]*$', message="Dozwolone są tylko litery, cyfry, spacja oraz znaki \"-\" i \"_\".")])
    service_password = StringField('Hasło', validators=[DataRequired()])
    submit = SubmitField('Zapisz')


class SharePasswordForm(FlaskForm):
    username = StringField('Nazwa użytkownika, któremu hasło zostanie udostępnione', validators=[DataRequired(),
                                                                                                 Length(min=2, max=20),
                                                                                                 Regexp(
                                                                                                     '^[a-zA-Z0-9_ąęćżźóśłń]*$',
                                                                                                     message="Dozwolone są tylko litery i cyfry")
    ])
    password = PasswordField('Potwierdź hasłem', validators=[DataRequired(), Regexp("^(?=.*[a-z])(?=.*[A-Z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-])[a-zA-Z0-9#?!@$%^&*-]{10,30}$",
                                                         message="Hasło może zawierać co najmniej po 1 małej i wielkiej literze, cyfrze i znaku specjalnym. Długość może wynosić od 10 do 30 znaków.")])
    submit = SubmitField('Udostępnij')