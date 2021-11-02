import datetime
import functools
import os
import uuid
from base64 import b64encode

from flask import request, jsonify
from werkzeug.exceptions import abort
from werkzeug.security import generate_password_hash, check_password_hash
import jwt

from .db import get_db


class EnrollmentError(Exception):
    pass


class OpenFlaskAuth(object):
    def __init__(self, app, secret):
        self.app = app
        self.key = secret
        self.audience = "http://localhost"

        @app.route('/oauth2/token', methods=['POST'])
        def get_token():
            authz = request.authorization
            scope = request.form.get('scope', None)
            grant_type = request.form.get('grant_type', None)

            if scope is None or grant_type != 'client_credentials':
                abort(400)

            token, expires = self.token(authz.username, authz.password, scope)
            return jsonify(
                access_token=token,
                token_type='Bearer',
                expires_in=expires.timestamp(),
                scope=scope
            ), {"Cache-Control": "no-store", "Pragma": "no-cache"}

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
            now = datetime.datetime.now(tz=datetime.timezone.utc)
            expires = now + datetime.timedelta(minutes=15)
            encoded = jwt.encode({
                "exp": expires,
                "nbf": now,
                "aud": "http://localhost",
                "scp": scope,
                "tid": str(uuid.uuid4())
            }, self.key, algorithm="HS256")
            return encoded, expires

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
                    decoded = jwt.decode(authz_token, self.key, algorithms="HS256",
                                         audience=self.audience)

                    if decoded['scp'] != scope:
                        abort(401)

                else:
                    abort(401)

                return f(**kwargs)

            return decorator

        return wrapper
