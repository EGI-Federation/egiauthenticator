"""
EGI Check-in authenticator for JupyterHub

Uses OpenID Connect with aai.egi.eu
"""


import base64
import json
import os
import urllib
import time

from tornado.auth import OAuth2Mixin
from tornado import web

from tornado.httputil import url_concat
from tornado.httpclient import HTTPRequest, AsyncHTTPClient

from jupyterhub.auth import LocalAuthenticator
from jupyterhub.handlers import BaseHandler

from traitlets import Unicode, List, Bool, validate

from oauthenticator.generic import GenericOAuthenticator
from oauthenticator.oauth2 import OAuthLoginHandler


def login_handler(checkin_host):
    class _EGICheckinMixin(OAuth2Mixin):
        _OAUTH_ACCESS_TOKEN_URL = "https://%s/oidc/token" % checkin_host
        _OAUTH_AUTHORIZE_URL = "https://%s/oidc/authorize" % checkin_host

    class _EGICheckinLoginHandler(OAuthLoginHandler, _EGICheckinMixin):
        pass

    e = _EGICheckinLoginHandler
    print("HELLO!")
    print("checkin_host: %s" % checkin_host)
    print(e._OAUTH_ACCESS_TOKEN_URL)
    print(e._OAUTH_AUTHORIZE_URL)
    return e


class EGICheckinAuthenticator(GenericOAuthenticator):
    login_service = "EGI Check-in"

    chechin_host_env = "EGICHECKIN_HOST"
    checkin_host = Unicode(config=True, help="""The EGI Check-in host to use""")

    def _client_id_default(self):
        default = "aai.egi.eu"
        if self.checkin_host_env:
            return os.getenv(self.checkin_host_env, default)
        return default

    client_id_env = "EGICHECKIN_CLIENT_ID"
    client_secret_env = "EGICHECKIN_CLIENT_SECRET"

    scope = List(
        Unicode(),
        default_value=[
            "openid",
            "profile",
            "eduperson_scoped_affiliation",
            "eduperson_entitlement",
            "offline_access",
        ],
        config=True,
        help="""The OAuth scopes to request.

        See https://wiki.egi.eu/wiki/AAI_guide_for_SPs#OpenID_Connect_Service_Provider for details.
        At least 'openid' is required.
        """,
    )

    @validate("scope")
    def _validate_scope(self, proposal):
        """ensure openid is requested"""
        if "openid" not in proposal.value:
            return ["openid"] + proposal.value
        return proposal.value

    entitlements_key = Unicode(
        "edu_person_entitlements",
        config=True,
        help="Claim name used to whitelist users",
    )

    entitlements_whitelist = List(
        config=True, help="""A list of user claims that are authorized to login.""",
    )

    affiliations_key = Unicode(
        "edu_person_scoped_affiliations",
        config=True,
        help="Claim name used to whitelist affiliations",
    )

    affiliations_whitelist = List(
        config=True,
        help="""A list of user affiliations that are authorized to login.""",
    )

    #  User name in Check-in comes in sub, but we are defaulting to
    # preferred_username as sub is too long to be used as id for
    # volumes
    username_key = Unicode(
        "preferred_username",
        config=True,
        help="""
        Claim name to use for getting the user name. 'sub' is unique but it's
        too long.
        """,
    )

    @property
    def token_url(self):
        return "https://%s/oidc/token" % self.checkin_host

    @property
    def userdata_url(self):
        return "https://%s/oidc/userinfo" % self.checkin_host

    @property
    def login_handler(self):
        return login_handler(self.checkin_host)

    def check_attrs_whitelist(self, user_info, whitelist, key):
        # our check whitelist uses affiliations and entitlements
        if not whitelist:
            return True
        gotten_claims = user_info(key, "")
        self.log.debug("These are the claims: %s", gotten_claims)
        return any(x in gotten_claims for x in whitelist)

    def check_whitelist(self, username, authentication=None):
        user_info = authentication.get("oauth_user", {})
        # this clearly needs some thought
        # does it make sense to have both?
        affiliations = self.check_attrs_whitelist(
            user_info, self.affiliations_whitelist, self.affiliations_key
        )
        entitlements = self.check_attrs_whitelist(
            user_info, self.entitlements_whitelist, self.entitlements_key
        )
        return (
            affiliations
            and entitlements
            and super().check_whitelist(username, authentication)
        )

    # Refresh auth data for user
    async def refresh_user(self, user, handler=None):
        self.log.debug("Refreshing credentials for user")
        auth_state = await user.get_auth_state()
        if not auth_state or "refresh_token" not in auth_state:
            self.log.warning("Trying to refresh user info without refresh token")
            return False

        now = time.time()
        refresh_info = auth_state.get("refresh_info", {})
        # if the token is still valid, avoid refreshing
        if refresh_info.get("expiry_time", 0) > now:
            self.log.debug("Credentials still valid!")
            return True

        # performing the refresh token call
        self.log.debug("Refresh call to Check-in")
        http_client = AsyncHTTPClient()
        headers = {
            "Accept": "application/json",
            "User-Agent": "JupyterHub",
        }
        params = dict(
            client_id=self.client_id,
            client_secret=self.client_secret,
            grant_type="refresh_token",
            refresh_token=auth_state["refresh_token"],
            scope=" ".join(self.scope),
        )
        url = url_concat(self.token_url, params)
        req = HTTPRequest(
            url,
            auth_username=self.client_id,
            auth_password=self.client_secret,
            headers=headers,
            method="POST",
            body="",
        )
        resp = await http_client.fetch(req)
        refresh_info = json.loads(resp.body.decode("utf8", "replace"))
        refresh_info["expiry_time"] = now + refresh_info["expires_in"]
        auth_state["refresh_info"] = refresh_info
        auth_state["access_token"] = refresh_info["access_token"]
        return {"auth_state": auth_state}


class LocalEGICheckinAuthenticator(LocalAuthenticator, EGICheckinAuthenticator):
    """A version that mixes in local system user creation"""

    pass
