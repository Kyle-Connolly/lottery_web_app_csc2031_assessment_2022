# IMPORTS
import os
import logging


# Logging user events
class SecurityFilter(logging.Filter):
    def filter(self, record):
        return 'SECURITY' in record.getMessage()


logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
file_handler = logging.FileHandler('lottery.log', 'a')
file_handler.setLevel(logging.WARNING)
file_handler.addFilter(SecurityFilter())
formatter = logging.Formatter('%(asctime)s : %(message)s', '%m/%d/%Y %I:%M:%S %p')
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_talisman import Talisman

# CONFIG
app = Flask(__name__)
app.config['SECRET_KEY'] = 'LongAndRandomSecretKey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///lottery.db'
app.config['SQLALCHEMY_ECHO'] = True
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# configure the public and private keys for reCAPTCHA
app.config['RECAPTCHA_PUBLIC_KEY'] = os.getenv('RECAPTCHA_PUBLIC_KEY')
app.config['RECAPTCHA_PRIVATE_KEY'] = os.getenv('RECAPTCHA_PRIVATE_KEY')

# initialise database
db = SQLAlchemy(app)
# create custom CSP to allow Bulma, ReCaptcha and luckydip function
csp = {
    'default-src': [
        '\'self\'',
        'https://cdnjs.cloudflare.com/ajax/libs/bulma/0.7.2/css/bulma.min.css'
    ],
    'frame-src': [
        '\'self\'',
        'https://www.google.com/recaptcha/',
        'https://recaptcha.google.com/recaptcha/'
    ],
    'script-src': [
        '\'self\'',
        '\'unsafe-inline\'',
        'https://www.google.com/recaptcha/',
        'https://www.gstatic.com/recaptcha/'
    ]
}
# registering Talisman, CSP passed as an argument
talisman = Talisman(app, content_security_policy=csp)

# HOME PAGE VIEW
@app.route('/')
def index():
    return render_template('main/index.html')


# BLUEPRINTS
# import blueprints
from users.views import users_blueprint
from admin.views import admin_blueprint
from lottery.views import lottery_blueprint

#
# # register blueprints with app
app.register_blueprint(users_blueprint)
app.register_blueprint(admin_blueprint)
app.register_blueprint(lottery_blueprint)


# display error pages for corresponding errors
@app.errorhandler(400)
def page_forbidden(error):
    return render_template("errors/400.html"), 400


@app.errorhandler(403)
def page_forbidden(error):
    return render_template("errors/403.html"), 403


@app.errorhandler(404)
def page_forbidden(error):
    return render_template("errors/404.html"), 404


@app.errorhandler(500)
def page_forbidden(error):
    return render_template("errors/500.html"), 500


@app.errorhandler(503)
def page_forbidden(error):
    return render_template("errors/503.html"), 503


from flask_login import LoginManager

# instance of LoginManager initialised
login_manager = LoginManager()
# instance should be set with the name of the view function that renders the login page
# - for redirecting anonymous users attempting to access protected areas
login_manager.login_view = 'users.login'
# register instance with the application instance
login_manager.init_app(app)

# import statement above load_user to avoid cyclic import error
from models import User


# When request is received, need the application to get an instance of the user sending the request from the database
@login_manager.user_loader
def load_user(id):
    # queries User table in database for user with the id
    return User.query.get(int(id))


if __name__ == "__main__":
    app.run()
