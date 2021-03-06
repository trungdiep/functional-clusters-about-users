
from crypt import methods
import functools
import json
from lib2to3.pgen2 import token

from flask import Blueprint
from flask import request
from flask import Response

from flask_mail import Mail
from flask_mail import Message


from app import db
from app import create_app
from auth.models import User


bp = Blueprint("auth", __name__, url_prefix="/auth")


def loggin_required(view):
    @functools.wraps(view)
    def wrapper(**kwargs):
        if request.headers.get('token', None) is None:
            return Response('Authentication credentials were not provided', status=401)
        return view(**kwargs)
    return wrapper


@bp.route('/register', methods=('POST',))
def register():
    body = json.loads(request.data)
    username = body.get('username', None)
    password = body.get('password', None)

    error = None
    if not username:
        error = 'Username is required.'
    elif not password:
        error = 'Password is required.'
    elif db.session.query(
        User.query.filter_by(username=username).exists()
    ).scalar():
        error = 'User is already registered'

    if error is None:
        user = User(username=username, password=password)
        db.session.add(user)
        db.session.commit()
        return Response('success', status=200)
    else:
        return Response(error, status=400)


@bp.route('/login', methods=['POsT'])
def login():
    body = json.loads(request.data)
    username = body.get('username', None)
    password = body.get('password', None)

    error = None
    if not username:
        error = 'Username is required.'
    elif not password:
        error = 'Password is required.'

    if error is None:
        user = User.query.filter_by(username=username).first()
        if user:
            if user.check_password(password):
                user.set_token()
                db.session.add(user)
                db.session.commit()
            else:
                error = "Incorrect password."
        else:
            error = "Incorrect username."

    if error is None:
        return Response(json.dumps({'token': user.get_token()}), status=200)
    else:
        return Response(error, status=400)


@bp.route('/logout', methods=['POST'])
@loggin_required
def logout():
    token = request.headers.get('token')
    error = None

    if error is None:
        user = User.query.filter_by(_token=token).first()
        if user:
            user.del_token()
            db.session.add(user)
            db.session.commit()
            return Response('success', status=200)
        else:
            error = "User doesn't exists."
    return Response(json.dumps({'error': error}), status=400)


@bp.route('/change-password', methods=['POST'])
@loggin_required
def change_password():
    body = json.loads(request.data)
    token = request.headers.get('token')
    password = body.get('password', None)
    new_password = body.get('new_password', None)

    error = None
    if password is None:
        error = 'Password is required.'
    elif new_password is None:
        error = 'New password is required.'
    
    user = User.query.filter_by(_token=token).first()
    if user is not None and error is not None:
        if user.check_password(password):
            user.password = new_password
            user.del_token()
            user.set_token()
            db.session.add(user)
            db.session.commit()
            return Response({'token': user.get_token()}, status=200)
        else:
            error = 'Wrong password'
    else:
        error = "User doesn't exists"
    
    return Response(json.dumps({'error': error}), status=400)


@bp.route('/reset-password', methods=['POST'])
def reset_password():
    body = json.loads(request.data)

    email = body.get('email', None)

    error = None
    if email is None:
        error = "Email is required"

    if error is None:
        app = create_app()
        mail = Mail(app)
        body = f'''
        '''
        msg = Message(
            'Reset password'
        )


@bp.route('/update-user', methods=['PATCH'])
@loggin_required
def update_user():
    body = json.loads(request.data)
    token = request.headers.get('token')

    if 'password' in body:
        body.pop('password')

    user = User.query.filter_by(_token=token).first()
    if user is not None and body:
        for k, v in body.items():
            setattr(user,k, v)
        db.session.add(user)
        db.session.commit()
        return Response(json.dumps({'status': 'succes'}), status=200)
    
    return Response(json.dumps({'error': "User doesn't exists"}), status=400)
