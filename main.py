from time import time
import datetime
from hashlib import sha1

import conf

# ---------------------------------------- app setup

from flask import Flask, redirect, url_for, session, request, render_template, abort, flash, get_flashed_messages, g
app = Flask(__name__)
#app.debug = True
# set the secret key.  keep this really secret:
app.secret_key = conf.secret_key

token_term = 7

# ---------------------------------------- db

from google.appengine.ext import db

class User(db.Model):
    name = db.StringProperty()
    twitter_id = db.IntegerProperty()
    oauth_token = db.StringProperty()
    oauth_secret = db.StringProperty()
    remember_token = db.StringProperty()
    remember_token_expires_at = db.DateTimeProperty()

    def update_remember_token(self):
        token = self.name + '-' + sha1('%s%s%s' % (self.name, conf.secret_key, time())).hexdigest()
        self.remember_token = token
        expires_at = datetime.datetime.now() + datetime.timedelta(days=token_term)
        self.remember_token_expires_at = expires_at

    @classmethod
    def find_by_twitter_id(self, twitter_id):
        query = User.all()
        query.filter('twitter_id =', int(twitter_id))
        return query.get()

    @classmethod
    def find_by_remember_token(self, remember_token):
        query = User.all()
        query.filter('remember_token =', remember_token)
        return query.get()

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
        user = User.find_by_remember_token(session['remember_token'])
        if user is not None:
            if user.remember_token_expires_at and user.remember_token_expires_at > datetime.datetime.now():
                g.user = user

                if user.remember_token_expires_at < datetime.datetime.now() + datetime.timedelta(days=1):
                    # update remember_token
                    user.update_remember_token()
                    session['remember_token'] = user.remember_token
                    db.put(user)

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
    session.pop('remember_token', None)
    flash('You were signed out')
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
        flash(u'You denied the request to sign in.')
        return redirect(next_url)

    user = User.find_by_twitter_id(resp['user_id'])

    if user is None:
        user = User(twitter_id = int(resp['user_id']),
                    name = resp['screen_name'],
                    oauth_token = resp['oauth_token'],
                    oauth_secret = resp['oauth_token_secret']
                    )

    # update remember_token
    user.update_remember_token()
    session['remember_token'] = user.remember_token
    db.put(user)

    flash('You were signed in')
    return redirect(next_url)

# ---------------------------------------- main

@app.route('/')
def index():
    tweets = None
    if g.user is not None:
        resp = twitter.get('statuses/home_timeline.json')
        if resp.status == 200:
            tweets = resp.data
        else:
            flash('Unable to load tweets from Twitter. Maybe out of '
                  'API calls or Twitter is overloaded.')
    return render_template('index.html', tweets=tweets)

# ----------------------------------------

if __name__ == '__main__':
    from wsgiref.handlers import CGIHandler
    CGIHandler().run(app)
