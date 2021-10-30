import functools
import os
from base64 import b64encode

from flask import request
from werkzeug.exceptions import abort
from werkzeug.security import generate_password_hash, check_password_hash

from .db import get_db


class EnrollmentError(Exception):
    pass


class OpenFlaskAuth(object):
    def __init__(self, app):
        self.app = app

    def enroll(self, user_id):
        error = None

        if not user_id:
            error = 'User ID is required.'

        public_bytes = os.urandom(16)
        public_key = b64encode(public_bytes).decode('utf-8')

        secret_bytes = os.urandom(32)
        secret_key = b64encode(secret_bytes).decode('utf-8')
        secret_hash = generate_password_hash(secret_key)

        if error is None:
            try:
                with self.app.app_context():
                    db = get_db()
                    db.execute(
                        'INSERT into enrollments (user_id, public_key, secret_hash) VALUES (?, ?, ?)',
                        (user_id, public_key, secret_hash)
                    )
                    db.commit()
            except db.IntegrityError:
                error = f"User ID {user_id} is already enrolled."
            else:
                return public_key, secret_key

        raise EnrollmentError(error)

    def token(self, public_key, secret_key, scope):
        error = None

        with self.app.app_context():
            db = get_db()
            enrollment = db.execute(
                'SELECT * FROM enrollments WHERE public_key = ?', (public_key,)
            ).fetchone()

        if enrollment is None:
            error = 'Unauthorized.'
        elif not check_password_hash(enrollment['secret_hash'], secret_key):
            error = 'Incorrect public / secret key.'

        if error is None:
            return 'passed'

        return error

    def require_token(self, scope):
        def wrapper(f):
            @functools.wraps(f)
            def decorator(**kwargs):
                authz = request.headers.get('Authorization')
                if authz:
                    authz_token = authz.split(" ")[1]
                else:
                    authz_token = ""
                if authz_token:
                    # decode
                    with self.app.app_context():
                        db = get_db()
                        print(db)

                    print(authz_token)
                    print(scope)
                else:
                    abort(401)

                return f(**kwargs)
            return decorator
        return wrapper


