"""
Generic OIDC authenticator for JupyterHub
"""


import base64
import json
import urllib

from tornado.httputil import url_concat
from tornado.httpclient import HTTPRequest, AsyncHTTPClient


from traitlets import Unicode 

from oauthenticator.generic import GenericOAuthenticator

class OIDCAuthenticator(GenericOAuthenticator):
    client_auth_method = Unicode(
        "client_secret_basic",
        config=True
    )

    @gen.coroutine
    def authenticate(self, handler, data=None):
        code = handler.get_argument("code")
        # TODO: Configure the curl_httpclient for tornado
        http_client = AsyncHTTPClient()

        params = dict(
            redirect_uri=self.get_callback_url(handler),
            code=code,
            grant_type='authorization_code'
        )
        params.update(self.extra_params)

        if self.token_url:
            url = self.token_url
        else:
            raise ValueError("Please set the OAUTH2_TOKEN_URL environment variable")

        headers = {
            "Accept": "application/json",
            "User-Agent": "JupyterHub",
        }

        if self.client_auth_method == "client_secret_basic":
            b64key = base64.b64encode(
                bytes(
                    "{}:{}".format(self.client_id, self.client_secret),
                    "utf8"
                    )
                )
            headers.update({
                "Authorization": "Basic {}".format(b64key.decode("utf8"))
            })
        elif self.client_auth_method == "client_secret_post":
            params.update(dict(client_id=self.client_id, client_secret=self.client_secret))
        else:
            raise ValueError("Unsupported client auth method: %s" % self.client_auth_method)

        req = HTTPRequest(url,
                          method="POST",
                          headers=headers,
                          validate_cert=self.tls_verify,
                          body=urllib.parse.urlencode(params)  # Body is required for a POST...
                          )
        self.log.error("HERE: %s", req.url)
        self.log.error("HERE: %s", req.body)
        self.log.error("HERE: %s", req.headers)
        resp = yield http_client.fetch(req)
        self.log.error("THERE: %s", resp)

        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        access_token = resp_json['access_token']
        refresh_token = resp_json.get('refresh_token', None)
        token_type = resp_json['token_type']
        scope = (resp_json.get('scope', '')).split(' ')

        # Determine who the logged in user is
        headers = {
            "Accept": "application/json",
            "User-Agent": "JupyterHub",
            "Authorization": "{} {}".format(token_type, access_token)
        }
        if self.userdata_url:
            url = url_concat(self.userdata_url, self.userdata_params)
        else:
            raise ValueError("Please set the OAUTH2_USERDATA_URL environment variable")

        req = HTTPRequest(url,
                          method=self.userdata_method,
                          headers=headers,
                          validate_cert=self.tls_verify,
                          )
        resp = yield http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        if not resp_json.get(self.username_key):
            self.log.error("OAuth user contains no key %s: %s", self.username_key, resp_json)
            return

        return {
            'name': resp_json.get(self.username_key),
            'auth_state': {
                'access_token': access_token,
                'refresh_token': refresh_token,
                'oauth_user': resp_json,
                'scope': scope,
            }
        }
