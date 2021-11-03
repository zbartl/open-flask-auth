import pytest

from open_flask_auth import OpenFlaskAuth


def test_token(client, app):
    user_id = 1234
    oauth = OpenFlaskAuth(app, "secret")
    public, secret = oauth.enroll(user_id)

    token_resp = client.post("/oauth2/token", auth=(public, secret),
                       data={'scope': '/hello', 'grant_type': 'client_credentials'})
    assert token_resp.status_code == 200
    body = token_resp.json
    token = body.get('access_token', None)
    assert token is not None

    authed_headers = {"Authorization": f"Bearer {token}"}
    hello_resp = client.get("/hello", headers=authed_headers)
    assert hello_resp.status_code == 200

    revoke_resp = client.post("/oauth2/revoke", auth=(public, secret),
                              data={'token': token})
    assert revoke_resp.status_code == 204

    authed_headers = {"Authorization": f"Bearer {token}"}
    un_authed_hello_resp = client.get("/hello", headers=authed_headers)
    assert un_authed_hello_resp.status_code == 401


def test_token_auth_required(client, app):
    user_id = 1234
    oauth = OpenFlaskAuth(app, "secret")
    public, secret = oauth.enroll(user_id)

    # public key required
    token_resp = client.post("/oauth2/token", auth=('', secret),
                             data={'scope': '/hello', 'grant_type': 'client_credentials'})
    assert token_resp.status_code == 401

    # secret key required
    token_resp = client.post("/oauth2/token", auth=(public, ''),
                             data={'scope': '/hello', 'grant_type': 'client_credentials'})
    assert token_resp.status_code == 401

    # grant_type must equal client_credentials
    token_resp = client.post("/oauth2/token", auth=(public, secret),
                             data={'scope': '/hello', 'grant_type': 'something_else'})
    assert token_resp.status_code == 400
