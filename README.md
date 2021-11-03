# open_flask_auth

experimental, minimal OAuth 2.0 implementation for Flask apps

## usage

`__init__.py`
```python
from open_flask_auth import OpenFlaskAuth
# ...

oauth_provider = OpenFlaskAuth(app, "secret")
oauth_provider.register_routes()

@app.route('/hello')
@oauth_provider.require_oauth('/hello')
def hello():
  return 'Hello, World!'
```

`db.py`
```python
from open_flask_auth import OpenFlaskAuthDbProvider
# ...

oauth_db_provider = OpenFlaskAuthDbProvider(current_app)
oauth_db_provider.init_db()
```

`enroll.py`
```python
from open_flask_auth import EnrollmentError
# ...

try:
    public, secret = self.oauth_provider.enroll(g.user['id'])
except EnrollmentError:
    abort(400)
```


## example
https://github.com/zbartl/flask/tree/main/examples/tutorial