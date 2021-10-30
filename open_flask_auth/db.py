import pkgutil
import sqlite3

from flask import current_app, g


def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(
            current_app.config['DATABASE'],
            detect_types=sqlite3.PARSE_DECLTYPES
        )
        g.db.row_factory = sqlite3.Row

    return g.db


class OpenFlaskAuthDbProvider(object):
    def __init__(self, app):
        self.app = app

    def init_db(self):
        with self.app.app_context():
            db = get_db()

            init_script = pkgutil.get_data(__name__, "schema.sql")
            db.executescript(init_script.decode('utf-8'))
