from datetime import datetime
import bcrypt
import pyotp
from flask_login import UserMixin
from app import db, app
from cryptography.fernet import Fernet


class User(db.Model, UserMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)

    # User authentication information.
    email = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(100), nullable=False)

    # User information
    firstname = db.Column(db.String(100), nullable=False)
    lastname = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(100), nullable=False, default='user')
    # column for encryption key for lottery draws - generated and stored for each user
    lottokey = db.Column(db.BLOB)
    # column for login PIN
    pinkey = db.Column(db.String(100), nullable=False)
    # variables to store the date and time the user registered, logged in and previous login
    registered_on = db.Column(db.DateTime, nullable=False)
    current_login = db.Column(db.DateTime, nullable=True)
    last_login = db.Column(db.DateTime, nullable=True)

    # Define the relationship to Draw
    draws = db.relationship('Draw')

    def __init__(self, email, firstname, lastname, phone, password, role):
        self.email = email
        self.firstname = firstname
        self.lastname = lastname
        self.phone = phone
        # hash password before storing in database
        self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        self.role = role
        # initialise key
        self.lottokey = Fernet.generate_key()
        # generate the PIN key
        self.pinkey = pyotp.random_base32()
        # set variable to store the date and time the user registered
        self.registered_on = datetime.now()
        # set variable to store the date and time the user logged in
        self.current_login = None
        # set variable to store the date and time the user last logged in
        self.last_login = None


# function takes data and uses provided encryption key to encrypt the data
def encrypt(data, lottokey):
    return Fernet(lottokey).encrypt(bytes(data, 'utf-8'))


# function takes data and uses provided encryption key to decrypt the data
def decrypt(data, lottokey):
    return Fernet(lottokey).decrypt(data).decode('utf-8')


class Draw(db.Model):
    __tablename__ = 'draws'

    id = db.Column(db.Integer, primary_key=True)

    # ID of user who submitted draw
    user_id = db.Column(db.Integer, db.ForeignKey(User.id), nullable=False)

    # 6 draw numbers submitted
    numbers = db.Column(db.String(100), nullable=False)

    # Draw has already been played (can only play draw once)
    been_played = db.Column(db.BOOLEAN, nullable=False, default=False)

    # Draw matches with master draw created by admin (True = draw is a winner)
    matches_master = db.Column(db.BOOLEAN, nullable=False, default=False)

    # True = draw is master draw created by admin. User draws are matched to master draw
    master_draw = db.Column(db.BOOLEAN, nullable=False)

    # Lottery round that draw is used
    lottery_round = db.Column(db.Integer, nullable=False, default=0)

    # used to decrypt numbers, makes use of the decrypt function.
    def view_numbers(self, lottokey):
        self.numbers = decrypt(self.numbers, lottokey)

    # used to decrypt numbers, makes use of the decrypt function.
    def update_numbers(self, lottokey):
        self.numbers = encrypt(self.numbers, lottokey)

    def __init__(self, user_id, numbers, master_draw, lottery_round, lottokey):
        self.user_id = user_id
        # encrypt users numbers using provided key
        self.numbers = encrypt(numbers, lottokey)
        self.been_played = False
        self.matches_master = False
        self.master_draw = master_draw
        self.lottery_round = lottery_round


def init_db():
    with app.app_context():
        db.drop_all()
        db.create_all()
        admin = User(email='admin@email.com',
                     password='Admin1!',
                     firstname='Alice',
                     lastname='Jones',
                     phone='0191-123-4567',
                     role='admin')

        db.session.add(admin)
        db.session.commit()
