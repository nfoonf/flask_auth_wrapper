from flask import Flask
from flask import render_template, jsonify, abort, request, make_response, url_for, session, redirect, g
from flask.ext.sqlalchemy import SQLAlchemy
import random
import hmac
import functools
from datetime import datetime
from hashlib import sha1


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/test.db'
db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True)
    email = db.Column(db.String(120), unique=True)

    def __init__(self, username, email):
        self.username = username
        self.email = email

    def __repr__(self):
        return '<User %r>' % self.username

class Client(db.Model):
    __tablename__ = 'mormont_clients'
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.String, nullable=False)
    secret = db.Column(db.String, nullable=False)


class AccessToken(db.Model):
    __tablename__ = 'mormont_accesstokens'
    id = db.Column(db.Integer, primary_key=True)
    access_token = db.Column(db.String, nullable=False)
    client = db.Column(
        db.Integer,
        db.ForeignKey('mormont_clients.id'),
        nullable=False,
    )
    salt = db.Column(db.String, nullable=False)
    creation_date = db.Column(db.DateTime, nullable=False)
    active = db.Column(db.Boolean, nullable=False, default=False)


@app.route('/login', methods=['POST', 'GET'])
def login():

    def check_permission(client, hash):
        own_hash = hmac.new(str(client.secret), str(client.id), sha1).hexdigest()
        print(own_hash)
        if hash == own_hash:
            return True

    def create_token():
        client_id = request.form["client"]
        hash = request.form["hash"]

        client = db.session.query(Client).filter(Client.client_id == client_id).first()
        if client and check_permission(client, hash):
            auth_token = {
                'token': generate_token(client)
            }
        return auth_token

    def generate_token(client):

        rand = random.Random()
        token = AccessToken()

        token.client = client.id
        token.salt = rand.randint(0, 2**48)
        token.creation_date = datetime.now()

        hash = hmac.new(str(client.secret), str('client={}'.format(client.client_id)), sha1)
        hash.update(str('salt={}'.format(token.salt)))
        hash.update(str('timestamp={}'.format(token.creation_date.isoformat())))
        token.access_token = hash.hexdigest()
        token.active = True
        print(token.access_token)

        db.session.add(token)
        db.session.commit()
        return token.access_token

    if request.method == 'POST':
        token = create_token()
        return make_response(jsonify(token))

    if request.method == 'GET':
        return render_template('login.html')

def get_authenticated_user(session, request):

    try:
        if 'X-Access-Token' in request.headers:
            #import ipdb; ipdb.set_trace()
            token = request.headers['X-Access-Token']
            access_token = db.session.query(
                AccessToken
            ).filter(
                AccessToken.access_token == token
            ).first()

            if access_token.active:
                client = db.session.query(Client).get(access_token.client)

                return client
    except:
        return None


def authenticated(method):
    """Decorate methods with this to require that the user be logged in.

    If the user is not logged in, they will be redirected to the configured
    `login url <RequestHandler.get_login_url>`.
    """
    @functools.wraps(method)
    def wrapper(*args, **kwargs):
        client = get_authenticated_user(session , request)
        if not client:
            return redirect(url_for('.login'))
        else:
            g.client = client
        return method(*args, **kwargs)
    return wrapper

@app.route('/logout')
@authenticated
def logout():
    client = g.get('client', None)
    if client:
        db.session.query('AccessToken').filter(client == client.id)
        import ipdb; ipdb.set_trace()

@app.route('/')
@authenticated
def hello_world():
    client = g.get('client')
    return 'Hello, {}!'.format(client.client_id)

if __name__ == '__main__':
    app.debug = True
    app.secret_key = "fooo"
    app.run()


