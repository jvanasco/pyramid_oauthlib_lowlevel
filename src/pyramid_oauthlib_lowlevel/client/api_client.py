import logging

log = logging.getLogger(__name__)

# pypi
import requests
from requests.auth import HTTPBasicAuth
from requests_oauthlib import OAuth1, OAuth2
from twython.compat import json, urlencode, parse_qsl, quote_plus, str, is_py2
import six

# ==============================================================================


class ApiError(Exception):

    error_code = None
    msg = None

    """Generic error class, catch-all for most issues."""

    def __init__(self, msg, error_code=None, retry_after=None):
        self.error_code = error_code
        super(ApiError, self).__init__(msg)

    @property
    def msg(self):  # pragma: no cover
        return self.args[0]


class ApiAuthError(ApiError):
    pass


# ==============================================================================


class ApiClient(object):
    """
    This is entirely based on the excellent Twython client which is MIT licensed

        https://github.com/ryanmcgrath/twython
    """

    _user_agent = "PyramidOAuthlibLowlevel v0"

    # override these in a subclass
    OAUTH1_SERVER_ACCESS_TOKEN = None
    OAUTH1_SERVER_REQUEST_TOKEN = None
    OAUTH1_SERVER_AUTHENTICATE = None

    OAUTH2_SERVER_AUTH = "NotImplementedYet"
    OAUTH2_SERVER_TOKEN = "NotImplementedYet"

    oauth_version = None
    _url_obtain_token = None
    _url_revoke_token = None

    def __init__(
        self,
        app_key=None,
        app_secret=None,
        oauth_token=None,
        oauth_token_secret=None,
        access_token=None,
        token_type="bearer",
        oauth_version=1,
        api_version="v1",
        client_args=None,
        auth_endpoint="authorize",
    ):
        # API urls, OAuth urls and API version; needed for hitting that there
        # API.
        self.api_version = api_version

        self.app_key = app_key
        self.app_secret = app_secret
        self.oauth_token = oauth_token
        self.oauth_token_secret = oauth_token_secret
        self.access_token = access_token

        # OAuth 1
        self.request_token_url = self.OAUTH1_SERVER_REQUEST_TOKEN
        self.access_token_url = self.OAUTH1_SERVER_ACCESS_TOKEN
        self.authenticate_url = self.OAUTH1_SERVER_AUTHENTICATE

        if self.access_token:  # If they pass an access token, force OAuth 2
            oauth_version = 2

        self.oauth_version = oauth_version

        # OAuth 2
        if oauth_version == 2:
            self.request_token_url = self.OAUTH2_SERVER_TOKEN

        self.client_args = client_args or {}
        default_headers = {"User-Agent": self._user_agent}
        if "headers" not in self.client_args:
            # If they didn't set any headers, set our defaults for them
            self.client_args["headers"] = default_headers
        elif "User-Agent" not in self.client_args["headers"]:
            # If they set headers, but didn't include User-Agent.. set
            # it for them
            self.client_args["headers"].update(default_headers)

        # Generate OAuth authentication object for the request
        # If no keys/tokens are passed to __init__, auth=None allows for
        # unauthenticated requests, although I think all v1.1 requests
        # need auth
        auth = None
        if oauth_version == 1:
            # User Authentication is through OAuth 1
            if (
                self.app_key is not None
                and self.app_secret is not None
                and self.oauth_token is None
                and self.oauth_token_secret is None
            ):
                auth = OAuth1(self.app_key, self.app_secret)

            if (
                self.app_key is not None
                and self.app_secret is not None
                and self.oauth_token is not None
                and self.oauth_token_secret is not None
            ):
                auth = OAuth1(
                    self.app_key,
                    self.app_secret,
                    self.oauth_token,
                    self.oauth_token_secret,
                )
        elif oauth_version == 2 and self.access_token:
            # Application Authentication is through OAuth 2
            token = {"token_type": token_type, "access_token": self.access_token}
            auth = OAuth2(self.app_key, token=token)

        self.client = requests.Session()
        self.client.auth = auth

        # Make a copy of the client args and iterate over them
        # Pop out all the acceptable args at this point because they will
        # Never be used again.
        client_args_copy = self.client_args.copy()
        for (k, v) in client_args_copy.items():
            if k in ("cert", "hooks", "max_redirects", "proxies", "verify"):
                setattr(self.client, k, v)
                self.client_args.pop(k)  # Pop, pop!

        # Headers are always present, so we unconditionally pop them and merge
        # them into the session headers.
        self.client.headers.update(self.client_args.pop("headers"))

        self._last_call = None

    def __repr__(self):
        return "<pyramid_oauthlib_lowlevel.ApiClient: %s>" % (self.app_key)

    # ------------------------------------------------------------------------------

    def get_authentication_tokens(
        self, callback_url=None, extra_args=None, force_login=False
    ):
        """Returns a dict including an authorization URL, ``auth_url``, to
           direct a user to
        :param callback_url: (optional) Url the user is returned to after
                             they authorize your app (web clients only)
        :param force_login: (optional) Forces the user to enter their
                            credentials to ensure the correct users
                            account is authorized.
        :rtype: dict
        """
        if self.oauth_version != 1:
            raise ApiError(
                "This method can only be called when your \
                               OAuth version is 1.0."
            )

        # we toggle this in, then fix
        _callback_uri_old = self.client.auth.client.callback_uri
        if callback_url:
            # python2 - this can be unicode or string
            # python3 - no issues i think
            if isinstance(callback_url, six.text_type):
                callback_url = callback_url
            else:
                callback_url = six.u(callback_url)
            self.client.auth.client.callback_uri = callback_url

        request_args = {}
        if extra_args:
            for (k, v) in extra_args.items():
                if k not in request_args:
                    request_args[k] = v

        response = self.client.get(self.request_token_url, params=request_args)
        if callback_url:
            self.client.auth.client.callback_uri = _callback_uri_old

        if response.status_code == 401:
            # requests: response.text is the decoded response; .content is raw bytes
            raise ApiAuthError(response.text, error_code=response.status_code)
        elif response.status_code != 200:
            # requests: response.text is the decoded response; .content is raw bytes
            raise ApiError(response.text, error_code=response.status_code)

        # requests: response.text is the decoded response; .content is raw bytes
        # requests/iso-http-spec defaults to latin-1 if no encoding is present
        # we know this is utf-8 because of the oauth spec
        # so we force utf-8 here off the .content
        request_tokens = dict(parse_qsl(response.content.decode("utf-8")))
        if not request_tokens:
            raise ApiError("Unable to decode request tokens.")

        oauth_callback_confirmed = (
            request_tokens.get("oauth_callback_confirmed") == "true"
        )

        auth_url_params = {"oauth_token": request_tokens["oauth_token"]}

        # Use old-style callback argument if server didn't accept new-style
        if callback_url and not oauth_callback_confirmed:
            auth_url_params["oauth_callback"] = self.callback_url

        request_tokens["auth_url"] = (
            self.authenticate_url + "?" + urlencode(auth_url_params, True)
        )

        return request_tokens

    def get_authorized_tokens(self, oauth_verifier, extra_args=None):
        """Returns a dict of authorized tokens after they go through the
        :class:`get_authentication_tokens` phase.

        :param oauth_verifier: (required) The oauth_verifier (or a.k.a PIN
        for non web apps) retrieved from the callback url querystring
        :rtype: dict

        """
        if self.oauth_version != 1:
            raise ApiError(
                "This method can only be called when your OAuth version is 1.0."
            )

        request_args = {}
        if extra_args:
            for (k, v) in extra_args.items():
                if k not in request_args:
                    request_args[k] = v

        self.client.auth.client.verifier = oauth_verifier
        response = self.client.get(
            self.access_token_url,
            params=request_args,
            headers={"Content-Type": "application/json"},
        )
        self.client.auth.client.verifier = None

        if response.status_code != 200:
            # we already catch these
            if response.status_code not in (400, 401):
                raise ApiError("invalid status code")

        if response.status_code in (400, 401):
            try:
                try:
                    # try to get json
                    content = response.json()
                except AttributeError:  # pragma: no cover
                    # if unicode detected
                    content = json.loads(response.text)
            except ValueError:
                content = {}

            raise ApiError(
                content.get("error", "Invalid / expired Token"),
                error_code=response.status_code,
            )

        # requests: response.text is the decoded response; .content is raw bytes
        # requests/iso-http-spec defaults to latin-1 if no encoding is present
        # we know this is utf-8 because of the oauth spec
        # so we force utf-8 here off the .content
        authorized_tokens = dict(parse_qsl(response.content.decode("utf-8")))
        if not authorized_tokens:
            raise ApiError("Unable to decode authorized tokens.")

        return authorized_tokens  # pragma: no cover

    # ------------------------------------------------------------------------------

    def obtain_access_token(self, extra_args=None):
        """Returns an OAuth 2 access token to make OAuth 2 authenticated read-only calls.
        :rtype: json
        """
        if self.oauth_version != 2:
            raise ApiError(
                "This method can only be called when your OAuth version is 2.0."
            )

        data = {"grant_type": "client_credentials"}
        basic_auth = HTTPBasicAuth(self.app_key, self.app_secret)
        content = None
        request_args = {}
        if extra_args:
            for (k, v) in extra_args.items():
                if k not in request_args:
                    request_args[k] = v
        try:
            response = self.client.post(
                self._url_obtain_token, params=request_args, data=data, auth=basic_auth
            )
            # requests: response.text is the decoded response; .content is raw bytes
            # requests/iso-http-spec defaults to latin-1 if no encoding is present
            # we know this is utf-8 because of the oauth spec
            # so we force utf-8 here off the .content
            content = response.content.decode("utf-8")
            try:
                content = content.json()
            except AttributeError:
                content = json.loads(content)

            _bearer_token = content["access_token"]
            _token_type = content["token_type"]
            if _token_type != "Bearer":
                raise ValueError()

        except (KeyError, ValueError, requests.exceptions.RequestException) as ex_og:
            log.debug(content)
            ex = ApiAuthError("Unable to obtain OAuth 2 access token.")
            ex.original_exception = ex_og
            ex.original_response = response
            ex.original_content = content
            raise ex
        else:
            return content

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    def revoke_access_token(self, token=None, token_type_hint=None):
        if self.oauth_version != 2:
            raise ApiError(
                "This method can only be called when your OAuth version is 2.0."
            )

        data = {"token": token}
        if token_type_hint:
            data["token_type_hint"] = token_type_hint
        basic_auth = HTTPBasicAuth(self.app_key, self.app_secret)
        try:
            response = self.client.post(
                self._url_revoke_token, data=data, auth=basic_auth
            )
            if response.status_code == 200:
                log.debug("Revoked OAuth 2 Token.")
                return True
            log.debug(
                "Unable to revoke OAuth 2 Token. Status code: %s" % response.status_code
            )
            return False
        except Exception as exc:
            raise ApiAuthError("Unable to revoke OAuth 2 token. Exception: %s" % exc)
