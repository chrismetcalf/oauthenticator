"""
Custom Authenticator to use Socrata OAuth with JupyterHub

Adapted from the Github Oauthenticator
"""


import json
import os

from tornado.auth import OAuth2Mixin
from tornado import gen, web

from tornado.httputil import url_concat
from tornado.httpclient import HTTPRequest, AsyncHTTPClient, HTTPError

from jupyterhub.auth import LocalAuthenticator

from traitlets import Unicode

from .oauth2 import OAuthLoginHandler, OAuthenticator

# Support github.com and github enterprise installations
SOCRATA_HOST = os.environ.get('SOCRATA_HOST') or 'opendata.socrata.com'

class SocrataMixin(OAuth2Mixin):
    _OAUTH_AUTHORIZE_URL = "https://%s/oauth/authorize" % SOCRATA_HOST
    _OAUTH_ACCESS_TOKEN_URL = "https://%s/oauth/access_token" % SOCRATA_HOST

class SocrataLoginHandler(OAuthLoginHandler, SocrataMixin):
    pass

class SocrataOAuthenticator(OAuthenticator):

    login_service = "Socrata"

    client_id_env = 'SOCRATA_APP_TOKEN'
    client_secret_env = 'SOCRATA_SECRET_TOKEN'
    login_handler = SocrataLoginHandler

    @gen.coroutine
    def authenticate(self, handler, data=None):
        code = handler.get_argument("code", False)
        if not code:
            raise web.HTTPError(400, "oauth callback made without a token")

        # TODO: Configure the curl_httpclient for tornado
        http_client = AsyncHTTPClient()

        # POST request yet requires URL parameters
        params = dict(
            client_id=self.client_id,
            client_secret=self.client_secret,
            grant_type='authorization_code',
            redirect_uri=self.oauth_callback_url,
            code=code
        )

        url = url_concat("https://%s/oauth/access_token" % SOCRATA_HOST,
                         params)

        req = HTTPRequest(url,
                          method="POST",
                          headers={"Accept": "application/json"},
                          body='' # Body is required for a POST...
                          )
        # Our OAuth has issues sometimes. Send them back through the flow until we stop getting 400's
        try:
            resp = yield http_client.fetch(req)
        except HTTPError as e:
            if e.code == 400:
                print("Received 400 error, retrying: %s" % e.response.body)
                self.login_handler.redirect(handler.hub.server.base_url)
            else:
                print("Received unhandled %s error, rethrowing: %s" % (e.code, e.response.body))
                raise e

        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        access_token = resp_json['access_token']

        # Determine who the logged in user is
        headers={"Accept": "application/json",
                 "User-Agent": "JupyterHub",
                 "Authorization": "OAuth {}".format(access_token)
        }
        req = HTTPRequest("https://%s/api/users/current" % SOCRATA_HOST,
                          method="GET",
                          headers=headers
                          )
        resp = yield http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        return resp_json["email"].replace("@", "_at_")
