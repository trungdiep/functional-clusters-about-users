import os
import binascii

from sqlalchemy.ext.hybrid import hybrid_property
from werkzeug.security import check_password_hash
from werkzeug.security import generate_password_hash
from datetime import datetime

from app import db, create_app
from authlib.jose import jwt

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True, nullable=False)
    _password = db.Column("password", db.String, nullable=False)
    _token = db.Column("token", db.String, nullable=True)
    create_at = db.Column(db.DateTime, nullable=False, default=datetime.now())
    update_at = db.Column(db.DateTime, nullable=False, default=datetime.now())


    @hybrid_property
    def password(self):
        return self._password

    @password.setter
    def password(self, value):
        """Store the password as a hash for security."""
        self._password = generate_password_hash(value)

    def check_password(self, value):
        return check_password_hash(self.password, value)

    def set_token(self):
        self._token = binascii.hexlify(os.urandom(20)).decode()

    def get_token(self):
        return self._token

    def del_token(self):
        self._token = None

    # def get_reset_token(self, expires_sec=1800):
    #     app = create_app()
    #     s = jwt.encode()
    #     return s.dumps({'user_id': self.id}).decode('utf-8')
