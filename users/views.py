# IMPORTS
import logging
from datetime import datetime
from functools import wraps

import bcrypt
import pyotp
from flask import Blueprint, render_template, flash, redirect, url_for, session, request
from flask_login import login_user, logout_user, current_user
from markupsafe import Markup

from app import db
from models import User
from users.forms import RegisterForm, LoginForm

# CONFIG
users_blueprint = Blueprint('users', __name__, template_folder='templates')


# VIEWS
# view registration
@users_blueprint.route('/register', methods=['GET', 'POST'])
def register():
    # create signup form object
    form = RegisterForm()

    # if request method is POST or form is valid
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        # if this returns a user, then the email already exists in database

        # if email already exists redirect user back to signup page with error message so user can try again
        if user:
            flash('Email address already exists')
            return render_template('users/register.html', form=form)

        # create a new user with the form data
        new_user = User(email=form.email.data,
                        firstname=form.firstname.data,
                        lastname=form.lastname.data,
                        phone=form.phone.data,
                        password=form.password.data,
                        role='user')

        # add the new user to the database
        db.session.add(new_user)
        db.session.commit()

        # log successful registration to log file
        logging.warning('SECURITY - User registration [%s, %s]',
                        form.email.data,
                        request.remote_addr)

        # sends user to login page
        return redirect(url_for('users.login'))
    # if request method is GET or form not valid re-render signup page
    return render_template('users/register.html', form=form)


# view user login
@users_blueprint.route('/login', methods=['GET', 'POST'])
def login():
    # check the key – value pair is in the session and add it if not.
    if not session.get('authentication_attempts'):
        session['authentication_attempts'] = 0

    form = LoginForm()
    # if form is being submitted - POST request. So validate form data
    if form.validate_on_submit():
        # get user from database with the submitted username
        user = User.query.filter_by(email=form.email.data).first()
        # check if user is null and if passwords match
        if not user \
                or not bcrypt.checkpw(form.password.data.encode('utf-8'), user.password) \
                or not pyotp.TOTP(user.pinkey).verify(form.pin.data):
            # each time program enters if statement authentication attempts is increased by 1
            session['authentication_attempts'] += 1
            # check if the allowed limit of attempts has been reached (3 attempts)
            if session.get('authentication_attempts') >= 3:
                # attempts succeeded so send error message
                flash(Markup('Login attempts exceeded. Please go to <a href="/reset">here</a> to reset'))
                # write exceeded failed login attempts to log file
                logging.warning('SECURITY - Login attempts exceeded [%s, %s]',
                                form.email.data,
                                request.remote_addr)
                return render_template('users/login.html')
            # login has failed
            flash('Please check your login details and try again, {} login attempts remaining'.format(
                3 - session.get('authentication_attempts')))
            # write failed log in to log file
            logging.warning('SECURITY - Login attempt failed [%s, %s]',
                            form.email.data,
                            request.remote_addr)
            return render_template('users/login.html', form=form)
        # login successful
        user.last_login = user.current_login
        user.current_login = datetime.now()
        # current login and last login updated so amend user's entry in database
        db.session.add(user)
        db.session.commit()
        # log the user in
        login_user(user)
        # write successful log in to log file
        logging.warning('SECURITY - Log in [%s, %s, %s]',
                        current_user.id,
                        current_user.email,
                        request.remote_addr
                        )
        if current_user.role == 'admin':
            return redirect(url_for('admin.admin'))
        return redirect(url_for('users.profile'))
    # else form is being requested - GET request. So render login template with form
    return render_template('users/login.html', form=form)


# custom wrapper function - used for enforcing RBAC. Takes authorised roles as a parameter
def requires_roles(*roles):
    # f - function to wrap with roles_required decorator
    def wrapper(f):
        @wraps(f)
        # takes any number of parameters or keyword parameters - they are parameters of wrapped function f
        def wrapped(*args, **kwargs):
            # if role of user attempting to access view function is not authorised then rend 403 forbidden template
            if current_user.role not in roles:
                # write record of forbidden access to log file
                logging.warning('SECURITY - Access denied[%s, %s, %s, %s]',
                                current_user.id,
                                current_user.email,
                                current_user.role,
                                request.remote_addr
                                )
                return render_template('errors/403.html')
            # else return view function f and execute as normal
            return f(*args, **kwargs)

        return wrapped

    return wrapper


@users_blueprint.route('/logout')
@requires_roles('user', 'admin')  # admin and user access allowed
def logout():
    # write log out to log file
    logging.warning('SECURITY - Log out [%s, %s, %s]',
                    current_user.id,
                    current_user.email,
                    request.remote_addr
                    )
    logout_user()
    return redirect(url_for('users.login'))


# to "unlock" the account after max number of authentication attempts has been reached. Reset attempts back to 0 and
# returns to login page
@users_blueprint.route('/reset')
def reset():
    session['authentication_attempts'] = 0
    return redirect(url_for('users.login'))


# view user profile
@users_blueprint.route('/profile')
@requires_roles('user')  # user access only
def profile():
    return render_template('users/profile.html', name=current_user.firstname)


# view user account
@users_blueprint.route('/account')
@requires_roles('user', 'admin')  # admin and user access allowed
def account():
    return render_template('users/account.html',
                           acc_no=current_user.id,
                           email=current_user.email,
                           firstname=current_user.firstname,
                           lastname=current_user.lastname,
                           phone=current_user.phone)
