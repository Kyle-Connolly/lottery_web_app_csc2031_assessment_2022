from flask_wtf import FlaskForm
from flask_wtf import RecaptchaField
from wtforms import StringField, SubmitField, PasswordField, ValidationError
from wtforms.validators import DataRequired, Email, regexp, Length, EqualTo


def character_check(form, field):
    # Special characters to search for within the field data
    excluded_chars = "*?!'^+%&/()=}][{$#@<>"
    # Search each char within the field data
    for char in field.data:
        # if it's one of the excluded chars raise error and display message with erroneous char
        if char in excluded_chars:
            raise ValidationError(f"Character {char} is not allowed. ")


# DataRequired() for ALL fields to make sure they're all populated before submission
class RegisterForm(FlaskForm):
    email = StringField(validators=[DataRequired(), Email()])
    # character_check calls above function to make sure first and last name don't contain special characters
    firstname = StringField(validators=[DataRequired(), character_check])
    lastname = StringField(validators=[DataRequired(), character_check])
    # checks if input are digits of the form: XXXX-XXX-XXXX (including the dashes)
    phone = StringField(validators=[DataRequired(), regexp(r'(^[0-9]{4}-[0-9]{3}-[0-9]{4}$)',
                                                           message="Must be in the format XXXX-XXX-XXXX")])
    # checks if between 6 and 12 characters in length, contains at least 1 digit
    # AND contains at least 1 lowercase and 1 uppercase word character, and at least 1 special character
    password = PasswordField(validators=[DataRequired(), Length(min=6, max=12),
                                         regexp(r'(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[!@# $%^&*]+)',
                                                message="Must contain at least one digit, one lowercase and "
                                                        "uppercase, and one special character")])
    # checks if between 6 and 12 characters in length and matches password data field
    confirm_password = PasswordField(validators=[DataRequired(), Length(min=6, max=12), EqualTo('password',
                                                                                                message='Passwords '
                                                                                                        'must match')])
    submit = SubmitField()


# define class for user login form
class LoginForm(FlaskForm):
    email = StringField(validators=[DataRequired(), Email()])
    password = PasswordField(validators=[DataRequired()])
    recaptcha = RecaptchaField()
    pin = StringField(validators=[DataRequired()])
    submit = SubmitField()
