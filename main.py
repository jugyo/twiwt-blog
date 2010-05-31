from time import time
import datetime
from hashlib import sha1
from markdown2 import markdown

import conf

# ---------------------------------------- app setup

from flask import Flask, redirect, url_for, session,\
  request, render_template, abort, flash, get_flashed_messages, g

app = Flask(__name__)
#app.debug = True
# set the secret key.  keep this really secret:
app.secret_key = conf.secret_key
app.debug = conf.debug

token_term = 7

# ---------------------------------------- db

from google.appengine.ext import db

class Model(db.Model):
    @classmethod
    def find_by(self, property_operator, value):
        return self.all().filter(property_operator, value).get()

class User(Model):
    name                      = db.StringProperty()
    twitter_id                = db.IntegerProperty()
    oauth_token               = db.StringProperty()
    oauth_secret              = db.StringProperty()
    remember_token            = db.StringProperty()
    remember_token_expires_at = db.DateTimeProperty()
    date                      = db.DateTimeProperty()

    def update_remember_token(self):
        token = self.name + '-' + sha1('%s%s%s' % (self.name, conf.secret_key, time())).hexdigest()
        self.remember_token = token
        expires_at = datetime.datetime.now() + datetime.timedelta(days=token_term)
        self.remember_token_expires_at = expires_at

    def delete_remember_token(self):
        self.remember_token = None
        self.remember_token_expires_at = None


class Entry(Model):
    hashcode = db.StringProperty()
    title    = db.StringProperty()
    body     = db.TextProperty()
    user     = db.ReferenceProperty(User)
    date     = db.DateTimeProperty()

    def formated_body(self):
        return markdown(self.body)

# ---------------------------------------- auth

from flaskext.oauth import OAuth

oauth = OAuth()
# Use Twitter as example remote application
twitter = oauth.remote_app('twitter',
    # unless absolute urls are used to make requests, this will be added
    # before all URLs.  This is also true for request_token_url and others.
    base_url='http://api.twitter.com/1/',
    # where flask should look for new request tokens
    request_token_url='http://api.twitter.com/oauth/request_token',
    # where flask should exchange the token with the remote application
    access_token_url='http://api.twitter.com/oauth/access_token',
    # twitter knows two authorizatiom URLs.  /authorize and /authenticate.
    # they mostly work the same, but for sign on /authenticate is
    # expected because this will give the user a slightly different
    # user interface on the twitter side.
    authorize_url='http://api.twitter.com/oauth/authenticate',
    # the consumer keys from the twitter application registry.
    consumer_key=conf.consumer_key,
    consumer_secret=conf.consumer_secret
)

@app.before_request
def before_request():
    g.user = None
    if 'remember_token' in session:
        user = User.find_by('remember_token =', session['remember_token'])
        if user is not None:
            if user.remember_token_expires_at and user.remember_token_expires_at > datetime.datetime.now():
                g.user = user
                if user.remember_token_expires_at < datetime.datetime.now() + datetime.timedelta(days=1):
                    # update remember_token
                    user.update_remember_token()
                    session['remember_token'] = user.remember_token
                    db.put(user)
            else:
                user.delete_remember_token()
                db.put(user)

    g.twitter_api_key = conf.consumer_key

@twitter.tokengetter
def get_twitter_token():
    """This is used by the API to look for the auth token and secret
    it should use for API calls.  During the authorization handshake
    a temporary set of token and secret is used, but afterwards this
    function has to return the token and secret.  If you don't want
    to store this in the database, consider putting it into the
    session instead.
    """
    user = g.user
    if user is not None:
        return user.oauth_token, user.oauth_secret
    return None

@app.route('/login')
def login():
    return twitter.authorize(callback=url_for('oauth_authorized',
        next=request.args.get('next') or request.referrer or None))


@app.route('/logout')
def logout():
    if g.user is not None:
        g.user.delete_remember_token()
        db.put(g.user)
        # flash('You were signed out')
    return redirect(request.referrer or url_for('index'))


@app.route('/oauth-authorized')
@twitter.authorized_handler
def oauth_authorized(resp):
    """Called after authorization.  After this function finished handling,
    the OAuth information is removed from the session again.  When this
    happened, the tokengetter from above is used to retrieve the oauth
    token and secret.

    Because the remote application could have re-authorized the application
    it is necessary to update the values in the database.

    If the application redirected back after denying, the response passed
    to the function will be `None`.  Otherwise a dictionary with the values
    the application submitted.  Note that Twitter itself does not really
    redirect back unless the user clicks on the application name.
    """
    next_url = request.args.get('next') or url_for('index')
    if resp is None:
        # flash(u'You denied the request to sign in.')
        return redirect(next_url)

    user = User.find_by('twitter_id =', int(resp['user_id']))

    if user is None:
        user = User(twitter_id = int(resp['user_id']),
                    name = resp['screen_name'],
                    oauth_token = resp['oauth_token'],
                    oauth_secret = resp['oauth_token_secret'],
                    date = datetime.datetime.now()
                    )
        user.update_remember_token()
        db.put(user)

    if user.remember_token is None:
        user.update_remember_token()
        db.put(user)

    session['remember_token'] = user.remember_token

    # flash('You were signed in')
    return redirect(next_url)

# ---------------------------------------- main

@app.route('/', methods=['GET', 'POST'])
def index():
    entries = None
    if g.user is not None:
        entries = Entry.all().filter('user =', g.user).order('-date').fetch(20)
    return render_template('index.html', entries=entries)


# --------- entry


@app.route('/e', methods=['POST'])
def post():
    if g.user is None:
        abort(401)

    sha1hash = sha1(('%s%s' % (request.form['title'], request.form['body'])).encode('UTF-8')).hexdigest()

    hashcode = ''
    for s in sha1hash:
        hashcode = hashcode + s
        if len(hashcode) < 6:
            continue
        if Entry.find_by('hashcode =', hashcode) is None:
            break

    entry = Entry(title = request.form['title'],
              body = request.form['body'],
              user = g.user,
              hashcode = hashcode,
              date = datetime.datetime.now()
              )
    db.put(entry)

    return redirect(url_for('entry', hashcode=entry.hashcode))


@app.route('/e/<hashcode>', methods=['GET', 'POST'])
def entry(hashcode):
    entry = Entry.find_by('hashcode =', hashcode)
    if request.method == 'POST':
        if g.user is None or entry.user.key() != g.user.key():
            abort(401)
        else:
            if '_delete' in request.form:
                entry.delete()
                return redirect(url_for('index'))
            else:
                entry.title = request.form['title']
                entry.body = request.form['body']
                db.put(entry)
                return redirect(url_for('entry', hashcode=entry.hashcode))
    else:
        return render_template('entry.html',
                                entry=entry)


@app.route('/e/<hashcode>/edit')
def edit(hashcode):
    entry = Entry.find_by('hashcode =', hashcode)
    return render_template('edit.html', entry=entry)


@app.route('/e/<hashcode>', )

# --------- user


@app.route('/<username>')
def user(username):
    user = User.find_by('name =', username)
    if user is None:
        abort(404)
    entries = Entry.all().filter('user =', user).order('-date').fetch(20)
    return render_template('user.html', user=user, entries=entries)

# ----------------------------------------

if __name__ == '__main__':
    from wsgiref.handlers import CGIHandler
    CGIHandler().run(app)
