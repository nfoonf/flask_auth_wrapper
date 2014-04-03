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


class Client(db.Model):
    __tablename__ = 'mormont_clients'
    pk = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.String, nullable=False)
    secret = db.Column(db.String, nullable=False)


class AccessToken(db.Model):
    __tablename__ = 'mormont_accesstokens'
    pk = db.Column(db.Integer, primary_key=True)
    access_token = db.Column(db.String, nullable=False)
    client = db.Column(
        db.Integer,
        db.ForeignKey('mormont_clients.pk'),
        nullable=False,
    )
    salt = db.Column(db.String, nullable=False)
    creation_date = db.Column(db.DateTime, nullable=False)
    active = db.Column(db.Boolean, nullable=False, default=False)


@app.route('/login', methods=['POST', 'GET'])
def login():

    def check_permission(client, hash):
        '''
        check if the hash, a client sent us is valid
        '''
        own_hash = hmac.new(
            str(client.secret),
            str(client.pk),
            sha1
        )
        own_hash.update(app.secret_key)
        if app.debug:
            print(own_hash.hexdigest())
        if hash == own_hash.hexdigest():
            return True

    def create_token():
        '''
        create a new token and deactivate all other tokens
        '''
        client_id = request.form["client"]
        print client_id
        hash = request.form["hash"]
        print hash
        client = db.session.query(Client) \
            .filter(Client.client_id == client_id) \
            .first()

        if client and check_permission(client, hash):
            access_tokens = db.session.query(AccessToken).filter(AccessToken.client == client.pk).filter(AccessToken.active is True)

            for token in access_tokens:
                token.active = False
                db.session.add(token)
            db.session.commit()
            token = generate_token(client, hash)
            if token:
                auth_token = {
                    'token': token
                }
                return auth_token
            else:
                return None
        else:
            return None

    def generate_token(client, hash):
        '''
        generate an access-token for a client
        '''
        own_hash = hmac.new(str(client.secret),
                            str(client.pk),
                            sha1
        ).hexdigest()
        print(own_hash)
        if hash == own_hash:
            return True

        rand = random.Random()
        token = AccessToken()

        token.client = client.pk
        token.salt = rand.randint(0, 2 ** 48)
        token.creation_date = datetime.now()

        hash = hmac.new(
            str(client.secret),
            str('client={}'.format(client.client_id)),
            sha1,
        )
        hash.update(str('salt={}'.format(token.salt)))
        hash.update(str('timestamp={}'.format(token.creation_date.isoformat())))
        token.access_token = hash.hexdigest()
        token.active = True
        if app.debug:
            print(token.access_token)

        db.session.add(token)
        db.session.commit()
        return token.access_token

    if request.method == 'POST':
        token = create_token()
        if token:
            return make_response(jsonify(token))
        else:
            return make_response('access denied', 403)

    if request.method == 'GET':
        return render_template('login.html')


def get_authenticated_user():
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
    `login`-URL.
    """
    @functools.wraps(method)
    def wrapper(*args, **kwargs):
        client = get_authenticated_user()
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
        access_tokens = db.session.query(AccessToken).filter(
            AccessToken.client == client.pk
        ).filter(
            AccessToken.active is True
        )
        for token in access_tokens:
            token.active = False
            db.session.add(token)
        db.session.commit()
    return make_response('OK', 200)


@app.route('/')
@authenticated
def hello_world():
    client = g.get('client')
    return 'Hello, {}!'.format(client.client_id)


if __name__ == '__main__':

    db.create_all()

    if not db.session.query(Client).all():
        print ("create dummy client")
        dummy = Client()
        dummy.client_id = 'foo'
        print "foo"
        dummy.secret = 'foo'
        db.session.add(dummy)
        db.session.commit()


    app.debug = True
    app.secret_key = "fooo"
    app.run()


