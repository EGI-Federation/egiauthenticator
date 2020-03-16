"""
Generic OIDC authenticator for JupyterHub
"""


import base64
import json
import urllib

from tornado import gen
from tornado.httputil import url_concat
from tornado.httpclient import HTTPRequest, AsyncHTTPClient, HTTPError

from traitlets import Unicode 

from oauthenticator.generic import GenericOAuthenticator

class OIDCAuthenticator(GenericOAuthenticator):
    client_auth_method = Unicode(
        "client_secret_basic",
        config=True
    )

    onezone_url = Unicode(default_value='',
                          config=True,
                          help="""Onedata onezone URL""")
    oneprovider_host = Unicode(default_value='',
                               config=True,
                               help="""Onedata oneprovider hostname""")
    onezone_idp = Unicode(default_value='',
                          config=True,
                          help="""Onezone idp name""")

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
        resp = yield http_client.fetch(req)

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

        auth_state =  {
                'access_token': access_token,
                'refresh_token': refresh_token,
                'oauth_user': resp_json,
                'scope': scope,
            }

        if self.onezone_url:
            onedata_token = None
            # We now go to the datahub to get a token
            req = HTTPRequest(self.onezone_url + '/api/v3/onezone/user/client_tokens',
                              headers={'content-type': 'application/json',
                                       'x-auth-token': '%s:%s' % (self.onezone_idp, access_token)},
                              method='GET')
            try:
                resp = yield http_client.fetch(req)
                datahub_response = json.loads(resp.body.decode('utf8', 'replace'))
                if datahub_response['tokens']:
                    onedata_token = datahub_response['tokens'].pop(0)
            except HTTPError as e:
                self.log.info("Something failed! %s", e)
                raise e
            if not onedata_token:
                # we don't have a token, create one
                req = HTTPRequest(self.onezone_url + '/api/v3/onezone/user/client_tokens',
                                  headers={'content-type': 'application/json',
                                           'x-auth-token': '%s:%s' % (self.onezone_idp, access_token)},
                                  method='POST',
                                  body='')
                try:
                    resp = yield http_client.fetch(req)
                    datahub_response = json.loads(resp.body.decode('utf8', 'replace'))
                    onedata_token = datahub_response['token']
                except HTTPError as e:
                    self.log.info("Something failed! %s", e)
                    raise e
            auth_state['onezone_token'] = onedata_token

        return {
            'name': resp_json.get(self.username_key),
            'auth_state': auth_state,
        }
