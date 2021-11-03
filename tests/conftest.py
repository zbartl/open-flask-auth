import os
import tempfile

import pytest
from flask import Flask

from open_flask_auth.oauth import OpenFlaskAuth
from open_flask_auth.db import OpenFlaskAuthDbProvider, get_db


# read in SQL for populating test data
with open(os.path.join(os.path.dirname(__file__), "data.sql"), "rb") as f:
    _data_sql = f.read().decode("utf8")


@pytest.fixture
def app():
    """Create and configure a new app instance for each test."""
    # create a temporary file to isolate the database for each test
    db_fd, db_path = tempfile.mkstemp()
    # create the app with common test config

    app = Flask(__name__, instance_relative_config=True)
    app.config.update({"TESTING": True, "DATABASE": db_path})

    # create the database and load test data
    with app.app_context():
        db_provider = OpenFlaskAuthDbProvider(app)
        db_provider.init_db()
        get_db().executescript(_data_sql)

        oauth = OpenFlaskAuth(app, "secret")
        oauth.register_routes()

        @app.route('/hello')
        @oauth.require_token('/hello')
        def hello():
            return 'Hello, World!'

    yield app

    # close and remove the temporary database
    os.close(db_fd)
    os.unlink(db_path)


@pytest.fixture
def client(app):
    """A test client for the app."""
    return app.test_client()
