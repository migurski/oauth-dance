from urllib import urlencode
from urlparse import urlparse, parse_qsl
from uuid import uuid4
import json

from flask import Flask, request, redirect, session, jsonify, render_template
from requests import post
import oauth2

github_authorize_url = 'https://github.com/login/oauth/authorize'
github_access_token_url = 'https://github.com/login/oauth/access_token'
github_user_info_url = 'https://api.github.com/user'

twitter_authorize_url = 'https://api.twitter.com/oauth/authorize'
twitter_request_token_url = 'https://api.twitter.com/oauth/request_token'
twitter_access_token_url = 'https://api.twitter.com/oauth/access_token'

google_authorize_url = 'https://accounts.google.com/o/oauth2/auth'
google_access_token_url = 'https://accounts.google.com/o/oauth2/token'

app = Flask(__name__)
app.secret_key = 'fake'

@app.route('/')
def index():
    '''
    '''
    callback_url = '{0}://{1}/callback'.format(request.scheme, request.host)
    return render_template('index.html', callback_url=callback_url, host=request.host)

@app.route('/authorize', methods=['POST'])
def authorize():
    vars = 'provider', 'key', 'secret'
    provider, key, secret = (request.form.get(var) for var in vars)
    callback = '{0}://{1}/callback'.format(request.scheme, request.host)

    if provider == 'github':
        return authorize_github(key, secret, callback, str(uuid4()))
        
    elif provider == 'twitter':
        return authorize_twitter(key, secret)
    
    elif provider == 'google':
        return authorize_google(key, secret, callback, str(uuid4()))
    
    else:
        raise Exception()

@app.route('/callback')
def callback():
    callback = '{0}://{1}/callback'.format(request.scheme, request.host)

    if session['provider'] == 'github':
        args = (session['client_id'], session['client_secret'],
                request.args.get('code'), request.args.get('state'))

        return callback_github(*args)
    
    elif session['provider'] == 'twitter':
        args = (session['consumer_key'], session['consumer_secret'],
                session['oauth_token'], session['oauth_token_secret'],
                request.args.get('oauth_verifier'))

        return callback_twitter(*args)
    
    elif session['provider'] == 'google':
        args = (session['client_id'], session['client_secret'],
                request.args.get('code'), request.args.get('state'),
                callback)

        return callback_google(*args)
    
    else:
        raise Exception()

def authorize_github(client_id, client_secret, redirect_uri, state):
    '''
    '''
    session['provider'] = 'github'
    session['client_id'] = client_id
    session['client_secret'] = client_secret
    session['state'] = state
    
    query_string = urlencode(dict(client_id=client_id, redirect_uri=redirect_uri,
                                  scope='', state=state))
    
    return redirect(github_authorize_url + '?' + query_string)

def authorize_twitter(consumer_key, consumer_secret):
    '''
    '''
    client = oauth2.Client(oauth2.Consumer(consumer_key, consumer_secret))
    resp, content = client.request(twitter_request_token_url, 'GET')
    
    if resp['status'] != '200':
        raise Exception()
    
    token = dict(parse_qsl(content))
    oauth_token, oauth_token_secret = token['oauth_token'], token['oauth_token_secret']

    session['provider'] = 'twitter'
    session['consumer_key'] = consumer_key
    session['consumer_secret'] = consumer_secret
    session['oauth_token'] = oauth_token
    session['oauth_token_secret'] = oauth_token_secret
    
    query_string = urlencode(dict(oauth_token=oauth_token))
    
    return redirect(twitter_authorize_url + '?' + query_string)

def authorize_google(client_id, client_secret, redirect_uri, state):
    '''
    '''
    session['provider'] = 'google'
    session['client_id'] = client_id
    session['client_secret'] = client_secret
    session['state'] = state
    
    query_string = urlencode(dict(client_id=client_id, redirect_uri=redirect_uri,
                                  scope='profile', state=state, response_type='code',
                                  access_type='offline', approval_prompt='force'))
    
    return redirect(google_authorize_url + '?' + query_string)

def callback_github(client_id, client_secret, code, state):
    '''
    '''
    if state != session['state']:
        raise Exception()

    data = dict(client_id=client_id, client_secret=client_secret,
                code=code, redirect_uri='')
    
    resp = post(github_access_token_url, data=data)
    access = dict(parse_qsl(resp.content))
    access_token, token_type = access['access_token'], access['token_type']
    
    consumer = oauth2.Consumer(client_id, client_secret)
    
    token = oauth2.Token(access_token, '')
    client = oauth2.Client(consumer, token)
    
    resp, content = client.request(github_user_info_url, 'GET')
    
    if resp['status'] != '200':
        raise Exception()
    
    return jsonify(dict(client_id=client_id, client_secret=client_secret,
                        access_token=access_token, token_type=token_type))

def callback_twitter(consumer_key, consumer_secret, oauth_token, oauth_token_secret, oauth_verifier):
    '''
    '''
    consumer = oauth2.Consumer(consumer_key, consumer_secret)
    token = oauth2.Token(oauth_token, oauth_token_secret)
    token.set_verifier(oauth_verifier)
    client = oauth2.Client(consumer, token)
    
    resp, content = client.request(twitter_access_token_url, 'POST')
    
    if resp['status'] != '200':
        raise Exception()
    
    token = dict(parse_qsl(content))
    oauth_token, oauth_token_secret = token['oauth_token'], token['oauth_token_secret']
    
    return jsonify(dict(consumer_key=consumer_key, consumer_secret=consumer_secret,
                        oauth_token=oauth_token, oauth_token_secret=oauth_token_secret))

def callback_google(client_id, client_secret, code, state, redirect_uri):
    '''
    '''
    if state != session['state']:
        raise Exception()
    
    data = dict(client_id=client_id, client_secret=client_secret,
                code=code, redirect_uri=redirect_uri,
                grant_type='authorization_code')
    
    resp = post(google_access_token_url, data=data)
    access = json.loads(resp.content)
    access_token, token_type = access['access_token'], access['token_type']
    refresh_token = access['refresh_token']
    
    return jsonify(dict(client_id=client_id, client_secret=client_secret,
                        access_token=access_token, token_type=token_type,
                        refresh_token=refresh_token))

if __name__ == '__main__':
    app.run(debug=True)
