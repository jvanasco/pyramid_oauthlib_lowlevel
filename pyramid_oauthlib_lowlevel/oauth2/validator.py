import logging

log = logging.getLogger(__name__)


# stdlib
import os
import datetime
import pdb

# pypi, upstream
from oauthlib.oauth2.rfc6749.errors import InvalidClientIdError
from oauthlib.oauth2.rfc6749.request_validator import RequestValidator

# pyramid
from pyramid.authentication import extract_http_basic_credentials
from pyramid.authentication import HTTPBasicCredentials


# ==============================================================================


class OAuth2RequestValidator_Hooks(object):
    """
    Subclass this to implement database connectivity hooks.
    OAuth2RequestValidator creates an instance of this object and calls it's methods.

    This class encapsulates all the database access your application should require.
    """

    pyramid_request = None  # stash the pyramid request object

    def __init__(self, pyramid_request):
        """
        :param request: oauthlib.common.Request
        """
        self.pyramid_request = pyramid_request
        self._config = pyramid_request.registry.settings or {}

    def ensure_request_client(self, request, client_id):
        """
        This is a utility method based on the flask-oauthlib implementation.
        It is used to ensure a request.client object based on the client_id if one is not set-up yet

        :param client_id: The client/consumer key.
        """
        if not request.client:
            request.client = self.client_getter(client_id=client_id)
        # should this be in the client_getter ?
        if not request.client:
            raise InvalidClientIdError("Invalid Client")

    #
    # access token getter and setter
    #
    def client_getter(self, client_id=None):
        """
        Retreive a valid client

        :param client_id: Unicode client identifier

        this is the non-secret key

        returns a client compatible with `docs.oauth2.object_interfaces.Client()`

        OR

        raise InvalidClientIdError("Invalid Client")

        EXAMPLE:

            def client_getter(self, client_id=None):
                client = dbSession.get(client_id)
                if not client_id:
                    raise InvalidClientIdError("Invalid Client")
                return client

        EXAMPLE ARGS:

            client_id = u'1kbjabsd8o7bkjbsdfbsdf'

        The method accepts one parameter `client_id`, and it returns
        a `client` object with at least the following information:

            - client_id: A random string
            - client_secret: A random string
            - is_confidential: A bool represents if it is confidential
            - redirect_uris: A list of redirect uris
            - default_redirect_uri: One of the redirect uris
            - default_scopes: Default scopes of the client

        The client may contain more information, which is suggested:

            - allowed_grant_types: A list of grant types
            - allowed_response_types: A list of response types
            - validate_scopes: A function to validate scopes
        """
        raise NotImplementedError("Subclasses must implement this function.")

    #
    # grant getter and setter | oAuth1 = request_token_(getter|setter)
    #
    def grant_setter(self, client_id, code, request, *args, **kwargs):
        """
        A method to save the grant code.

        :param client_id: Unicode client identifier
        :param code: A dict of the authorization code grant and, optionally, state.
        :param request: The HTTP Request (oauthlib.common.Request)

        def set_grant(client_id, code, request, *args, **kwargs):
            save_grant(client_id, code, request.user, request.scopes)
        """
        raise NotImplementedError("Subclasses must implement this function.")

    def grant_getter(self, client_id, code, *args, **kwargs):
        """
        A method to load a grant.

        :param client_id: Unicode client identifier
        :param code: Unicode authorization_code
        """
        raise NotImplementedError("Subclasses must implement this function.")

    def grant_invalidate(self, grantObject):
        """
        This method expects a `grantObject` as a single argument.
        The grant should be deleted or otherwise marked as revoked.

        :param grantObject: The grant object loaded by ``grant_getter```
        """
        raise NotImplementedError("Subclasses must implement this function.")

    #
    # bearer_token setter
    #
    def bearer_token_setter(self, token, request, *args, **kwargs):
        """
        :param token: A Bearer token dict
        :param request: The HTTP Request (oauthlib.common.Request)

            def bearer_token_setter(token, request, *args, **kwargs):
                save_token(token, request.client, request.user)

        The parameter token is a dict, that looks like::

            {
                u'access_token': u'6JwgO77PApxsFCU8Quz0pnL9s23016',
                u'token_type': u'Bearer',
                u'expires_in': 3600,
                u'scope': u'email address'
            }

        see `save_bearer_token` for full docs on the Bearer Token
        """
        raise NotImplementedError("Subclasses must implement this function.")

    def token_getter(self, access_token=None, refresh_token=None):
        """
        This method accepts an `access_token` or `refresh_token` parameters,
        and it returns a token object with at least these information:

            - access_token: A string token
            - refresh_token: A string token
            - client_id: ID of the client
            - scopes: A list of scopes
            - expires: A `datetime.datetime` object
            - user: The user object

        :param access_token: Unicode access token
        :param refresh_token: Unicode refresh token
        """
        raise NotImplementedError("Subclasses must implement this function.")

    def token_revoke(self, tokenObject):
        """
        This method expects a `tokenObject` as a single argument.

        The token should be deleted or otherwise marked as revoked.

            def token_revoke(self, tokenObject):
                tokenObject.is_active = False
                self.pyramid_request.dbSession.flush()

            def token_revoke(self, tokenObject):
                self.pyramid_request.dbSession.delete(tokenObject)
                self.pyramid_request.dbSession.flush()

        :param tokenObject: The grant object loaded by ``token_getter```
        """
        raise NotImplementedError("Subclasses must implement this function.")

    def user_getter(self, username, password, client, request, *args, **kwargs):
        """
        This method is only required for **password credential** authorization::

        Known implementations that have worked include:

            def user_getter(self, username, password, client, request, *args, **kwargs):
                # client: current request client
                if not client.has_password_credential_permission:
                    return None
                user = User.get_user_by_username(username)
                if not user.validate_password(password):
                    return None

                # parameter `request` is an OAuthlib Request object.
                # maybe you will need it somewhere
                return user

            def user_getter(self, username, password, *args, **kwargs):
                user = self.query.filter_by(username=username).first()
                if user and user.check_password(password):
                    return user
                return None
        """
        raise NotImplementedError("Subclasses must implement this function.")


class OAuth2RequestValidator(RequestValidator):
    """
    Validator Integration
    """

    request = None
    _config = None
    _config_prefix = "oauth1.provider."
    _api_hooks = None

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    token_expires_in = None  # 3600
    token_generator = None
    refresh_token_generator = None

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    def __init__(self, pyramid_request, validator_api_hooks=None):
        """Builds a new RequestValidator

        :param pyramid_request: pyramid `request` object.
        :param validator_api_hooks: A subclass of `OAuth2RequestValidator_Hooks`
        """
        self.pyramid_request = pyramid_request
        self._config = pyramid_request.registry.settings or {}
        self._api_hooks = validator_api_hooks

    # --------------------------------------------------------------------------

    def _get_client_creds_from_request(self, request):
        """Return client credentials based on the current request.

        According to the rfc6749, client MAY use the HTTP Basic authentication
        scheme as defined in [RFC2617] to authenticate with the authorization
        server. The client identifier is encoded using the
        "application/x-www-form-urlencoded" encoding algorithm per Appendix B,
        and the encoded value is used as the username; the client password is
        encoded using the same algorithm and used as the password. The
        authorization server MUST support the HTTP Basic authentication scheme
        for authenticating clients that were issued a client password.
        See `Section 2.3.1`_.

        .. _`Section 2.3.1`: https://tools.ietf.org/html/rfc6749#section-2.3.1

        IMPORTANT:

        When dealing with an AUTHORIZATION header:
            flask-oauthlib precomputes this via Werkzeug into a dict
            pyramid's integration does not precompute right now
        """
        if request.client_id is not None:
            return request.client_id, request.client_secret

        auth = request.headers.get("Authorization")
        if auth:
            # flask-oauthlib precomputes this via Werkzeug into a dict
            if isinstance(auth, dict):
                return auth["username"], auth["password"]
            # fallback on a full extraction
            _auth = extract_http_basic_credentials(request)
            if isinstance(_auth, HTTPBasicCredentials):
                return _auth.username, _auth.password

        return None, None

    def client_authentication_required(self, request, *args, **kwargs):
        """
        Determine if client authentication is required for current request.

        According to the rfc6749, client authentication is required in the
        following cases:

        Resource Owner Password Credentials Grant: see `Section 4.3.2`_.
        Authorization Code Grant: see `Section 4.1.3`_.
        Refresh Token Grant: see `Section 6`_.

        :param request: oauthlib.common.Request
        :rtype: True or False

        Method is used by:
            - Authorization Code Grant
            - Resource Owner Password Credentials Grant
            - Refresh Token Grant

        .. _`Section 4.3.2`: http://tools.ietf.org/html/rfc6749#section-4.3.2
        .. _`Section 4.1.3`: http://tools.ietf.org/html/rfc6749#section-4.1.3
        .. _`Section 6`: http://tools.ietf.org/html/rfc6749#section-6
        """

        def is_confidential(client):
            if hasattr(client, "is_confidential"):
                return client.is_confidential
            client_type = getattr(client, "client_type", None)
            if client_type:
                return client_type == "confidential"
            return True

        grant_types = ("password", "authorization_code", "refresh_token")
        client_id, _ = self._get_client_creds_from_request(request)
        if client_id and request.grant_type in grant_types:
            client = self._api_hooks.client_getter(client_id)
            if client:
                return is_confidential(client)
        return False

    def authenticate_client(self, request, *args, **kwargs):
        """Authenticate itself in other means.

        :param request: oauthlib.common.Request
        :rtype: True or False

        Method is used by:
            - Authorization Code Grant
            - Resource Owner Password Credentials Grant (may be disabled)
            - Client Credentials Grant
            - Refresh Token Grant

        .. _`HTTP Basic Authentication Scheme`: http://tools.ietf.org/html/rfc1945#section-11.1
        """
        client_id, client_secret = self._get_client_creds_from_request(request)
        log.debug("Authenticate client %r", client_id)

        client = self._api_hooks.client_getter(client_id)
        if not client:
            log.debug("Authenticate client failed, client not found.")
            return False

        request.client = client

        # http://tools.ietf.org/html/rfc6749#section-2
        # The client MAY omit the parameter if the client secret is an empty string.
        if hasattr(client, "client_secret") and (client.client_secret != client_secret):
            log.debug("Authenticate client failed, secret not match.")
            return False

        log.debug("Authenticate client success.")
        return True

    def authenticate_client_id(self, client_id, request, *args, **kwargs):
        """Authenticate a non-confidential client.

        :param client_id: Unicode client identifier
        :param request: oauthlib.common.Request
        """
        if client_id is None:
            client_id, _ = self._get_client_creds_from_request(request)
        log.debug("Authenticate client %r.", client_id)

        client = request.client or self._api_hooks.client_getter(client_id)
        if not client:
            log.debug("Authenticate failed, client not found.")
            return False

        # attach client on request for convenience
        request.client = client
        return True

    def confirm_redirect_uri(
        self, client_id, code, redirect_uri, client, *args, **kwargs
    ):
        """Ensure client is authorized to redirect to the redirect_uri.

        This method is used in the authorization code grant flow. It will
        compare redirect_uri and the one in grant token strictly, you can
        add a `validate_redirect_uri` function on grant for a customized
        validation.

        :param client_id: Unicode client identifier
        :param code: Unicode authorization_code.
        :param redirect_uri: Unicode absolute URI
        :param client: Client object set by you, see authenticate_client.
        :param request: The HTTP Request (oauthlib.common.Request)
        :rtype: True or False

        Method is used by:
            - Authorization Code Grant (during token request)
        """
        client = client or self._api_hooks.client_getter(client_id)
        log.debug(
            "Confirm redirect uri for client %r and code %r.", client.client_id, code
        )
        grant = self._api_hooks.grant_getter(client_id=client.client_id, code=code)
        if not grant:
            log.debug("Grant not found.")
            return False
        if (
            hasattr(grant, "validate_redirect_uri") and grant.validate_redirect_uri
        ):  # ensure it is defined
            return grant.validate_redirect_uri(redirect_uri)
        log.debug(
            "Compare redirect uri for grant %r and %r.",
            grant.redirect_uri,
            redirect_uri,
        )

        testing = "OAUTHLIB_INSECURE_TRANSPORT" in os.environ
        if testing and redirect_uri is None:
            # For testing
            return True

        return grant.redirect_uri == redirect_uri

    def get_default_redirect_uri(self, client_id, request, *args, **kwargs):
        """Default redirect_uri for the given client.

        :param client_id: Unicode client identifier
        :param request: The HTTP Request (oauthlib.common.Request)
        :rtype: The default redirect URI for the client

        Method is used by:
            - Authorization Code Grant
            - Implicit Grant
        """
        request.client = request.client or self._api_hooks.client_getter(client_id)
        redirect_uri = request.client.default_redirect_uri
        log.debug("Found default redirect uri %r", redirect_uri)
        return redirect_uri

    def get_default_scopes(self, client_id, request, *args, **kwargs):
        """Default scopes for the given client.

        :param client_id: Unicode client identifier
        :param request: The HTTP Request (oauthlib.common.Request)
        :rtype: List of default scopes

        Method is used by all core grant types:
            - Authorization Code Grant
            - Implicit Grant
            - Resource Owner Password Credentials Grant
            - Client Credentials grant
        """
        request.client = request.client or self._api_hooks.client_getter(client_id)
        scopes = request.client.default_scopes
        log.debug("Found default scopes %r", scopes)
        return scopes

    def get_original_scopes(self, refresh_token, request, *args, **kwargs):
        """Get the list of scopes associated with the refresh token.

        This method is used in the refresh token grant flow.  We return
        the scope of the token to be refreshed so it can be applied to the
        new access token.

        :param refresh_token: Unicode refresh token
        :param request: The HTTP Request (oauthlib.common.Request)
        :rtype: List of scopes.

        Method is used by:
            - Refresh token grant
        """
        log.debug("Obtaining scope of refreshed token.")
        tok = self._api_hooks.token_getter(refresh_token=refresh_token)
        return tok.scopes

    def is_within_original_scope(
        self, request_scopes, refresh_token, request, *args, **kwargs
    ):
        """Check if requested scopes are within a scope of the refresh token.

        When access tokens are refreshed the scope of the new token
        needs to be within the scope of the original token. This is
        ensured by checking that all requested scopes strings are on
        the list returned by the get_original_scopes. If this check
        fails, is_within_original_scope is called. The method can be
        used in situations where returning all valid scopes from the
        get_original_scopes is not practical.

        :param request_scopes: A list of scopes that were requested by client
        :param refresh_token: Unicode refresh_token
        :param request: The HTTP Request (oauthlib.common.Request)
        :rtype: True or False

        Method is used by:
            - Refresh token grant
        """
        return False

    def invalidate_authorization_code(self, client_id, code, request, *args, **kwargs):
        """Invalidate an authorization code after use.

        We keep the temporary code in a grant, which has a `delete`
        function to destroy itself.

        :param client_id: Unicode client identifier
        :param code: The authorization code grant (request.code).
        :param request: The HTTP Request (oauthlib.common.Request)

        Method is used by:
            - Authorization Code Grant
        """
        log.debug("Destroy grant token for client %r, %r", client_id, code)
        grantObject = self._api_hooks.grant_getter(client_id=client_id, code=code)
        if grantObject:
            self._api_hooks.grant_invalidate(grantObject)

    def revoke_token(self, token, token_type_hint, request, *args, **kwargs):
        """Revoke an access or refresh token.

        :param token: The token string.
        :param token_type_hint: access_token or refresh_token.
        :param request: The HTTP Request (oauthlib.common.Request)

        Method is used by:
            - Revocation Endpoint
        """
        if token_type_hint:
            tokenObject = self._api_hooks.token_getter(**{token_type_hint: token})
        else:
            tokenObject = self._api_hooks.token_getter(access_token=token)
            if not tokenObject:
                tokenObject = self._api_hooks.token_getter(refresh_token=token)

        if tokenObject:
            request.client_id = tokenObject.client_id
            request.user = tokenObject.user
            self._api_hooks.token_revoke(tokenObject)
            return True

        msg = "Invalid token supplied."
        log.debug(msg)
        request.error_message = msg
        return False

    def rotate_refresh_token(self, request):
        """Determine whether to rotate the refresh token. Default, yes.

        When access tokens are refreshed the old refresh token can be kept
        or replaced with a new one (rotated). Return True to rotate and
        and False for keeping original.

        :param request: oauthlib.common.Request
        :rtype: True or False

        Method is used by:
            - Refresh Token Grant
        """
        return True

    def save_authorization_code(self, client_id, code, request, *args, **kwargs):
        """Persist the authorization code.

        :param client_id: Unicode client identifier
        :param code: A dict of the authorization code grant and, optionally, state.
        :param request: The HTTP Request (oauthlib.common.Request)

        Method is used by:
            - Authorization Code Grant
        """
        log.debug("Persist authorization code %r for client %r", code, client_id)
        request.client = request.client or self._api_hooks.client_getter(client_id)
        self._api_hooks.grant_setter(client_id, code, request, *args, **kwargs)
        return request.client.default_redirect_uri

    def save_token(self, token, request, *args, **kwargs):
        """Persist the token with a token type specific method.

        Currently, only save_bearer_token is supported **WITHIN oauthlib**.

        :param token: A (Bearer) token dict
        :param request: The HTTP Request (oauthlib.common.Request)
        """
        return self.save_bearer_token(token, request, *args, **kwargs)

    def save_bearer_token(self, token, request, *args, **kwargs):
        """Persist the Bearer token.

        The Bearer token should at minimum be associated with:
            - a client and it's client_id, if available
            - a resource owner / user (request.user)
            - authorized scopes (request.scopes)
            - an expiration time
            - a refresh token, if issued
            - a claims document, if present in request.claims

        The Bearer token dict may hold a number of items::

            {
                'token_type': 'Bearer',
                'access_token': 'askfjh234as9sd8',
                'expires_in': 3600,
                'scope': 'string of space separated authorized scopes',
                'refresh_token': '23sdf876234',  # if issued
                'state': 'given_by_client',  # if supplied by client
            }

        Note that while "scope" is a string-separated list of authorized scopes,
        the original list is still available in request.scopes.

        The token dict is passed as a reference so any changes made to the dictionary
        will go back to the user.  If additional information must return to the client
        user, and it is only possible to get this information after writing the token
        to storage, it should be added to the token dictionary.  If the token
        dictionary must be modified but the changes should not go back to the user,
        a copy of the dictionary must be made before making the changes.

        Also note that if an Authorization Code grant request included a valid claims
        parameter (for OpenID Connect) then the request.claims property will contain
        the claims dict, which should be saved for later use when generating the
        id_token and/or UserInfo response content.

        :param token: A Bearer token dict
        :param request: The HTTP Request (oauthlib.common.Request)
        :rtype: The default redirect URI for the client

        Method is used by all core grant types issuing Bearer tokens:
            - Authorization Code Grant
            - Implicit Grant
            - Resource Owner Password Credentials Grant (might not associate a client)
            - Client Credentials grant
        """
        log.debug("Save bearer token %r", token)
        self._api_hooks.bearer_token_setter(token, request, *args, **kwargs)
        return request.client.default_redirect_uri

    def validate_bearer_token(self, token, scopes, request):
        """Validate access token.

        Detailed docs in `oauthlib.oauth2.rfc6749.request_validator.RequestValidator.validate_bearer_token`

        :param token: A string of random characters.
        :param scopes: A list of scopes associated with the protected resource.
        :param request: The HTTP Request (oauthlib.common.Request)
        :rtype: True or False

        The validation validates:

            1) if the token is available
            2) if the token has expired
            3) if the scopes are available

        Method is indirectly used by all core Bearer token issuing grant types:
            - Authorization Code Grant
            - Implicit Grant
            - Resource Owner Password Credentials Grant
            - Client Credentials Grant
        """
        log.debug("Validate bearer token %r", token)
        tok = self._api_hooks.token_getter(access_token=token)
        if not tok:
            msg = "Bearer token not found."
            request.error_message = msg
            log.debug(msg)
            return False

        # validate expires
        if tok.expires is not None and datetime.datetime.utcnow() > tok.expires:
            msg = "Bearer token is expired."
            request.error_message = msg
            log.debug(msg)
            return False

        # validate scopes
        if scopes and not set(tok.scopes) & set(scopes):
            msg = "Bearer token scope not valid."
            request.error_message = msg
            log.debug(msg)
            return False

        request.access_token = tok
        request.user = tok.user
        request.scopes = scopes

        if hasattr(tok, "client"):
            request.client = tok.client
        elif hasattr(tok, "client_id"):
            request.client = self._api_hooks.client_getter(tok.client_id)
        return True

    def validate_client_id(self, client_id, request, *args, **kwargs):
        """Ensure client_id belong to a valid and active client.

        Note, while not strictly necessary it can often be very convenient
        to set request.client to the client object associated with the
        given client_id.

        :param client_id: Unicode client identifier
        :param request: oauthlib.common.Request
        :rtype: True or False

        Method is used by:
            - Authorization Code Grant
            - Implicit Grant
        """
        log.debug("Validate client %r", client_id)
        client = request.client or self._api_hooks.client_getter(client_id)
        if client:
            # attach client to request object
            request.client = client
            return True
        return False

    def validate_code(self, client_id, code, client, request, *args, **kwargs):
        """Verify that the authorization_code is valid and assigned to the given
        client.

        Before returning true, set the following based on the information stored
        with the code in 'save_authorization_code':

            - request.user
            - request.state (if given)
            - request.scopes
            - request.claims (if given)
        OBS! The request.user attribute should be set to the resource owner
        associated with this authorization code. Similarly request.scopes
        must also be set.

        The request.claims property, if it was given, should assigned a dict.

        :param client_id: Unicode client identifier
        :param code: Unicode authorization code
        :param client: Client object set by you, see authenticate_client.
        :param request: The HTTP Request (oauthlib.common.Request)
        :rtype: True or False

        Method is used by:
            - Authorization Code Grant
        """
        client = client or self._api_hooks.client_getter(client_id)
        log.debug("Validate code for client %r and code %r", client.client_id, code)
        grant = self._api_hooks.grant_getter(client_id=client.client_id, code=code)
        if not grant:
            log.debug("Grant not found.")
            return False
        if hasattr(grant, "expires") and datetime.datetime.utcnow() > grant.expires:
            log.debug("Grant is expired.")
            return False

        request.state = kwargs.get("state")
        request.user = grant.user
        request.scopes = grant.scopes
        return True

    def validate_grant_type(
        self, client_id, grant_type, client, request, *args, **kwargs
    ):
        """
        Ensure the client is authorized to use the grant type requested.

        It will allow any of the four grant types (`authorization_code`,
        `password`, `client_credentials`, `refresh_token`) by default.
        Implemented `allowed_grant_types` for client object to authorize
        the request.

        It is suggested that `allowed_grant_types` should contain at least
        `authorization_code` and `refresh_token`.

        :param client_id: Unicode client identifier
        :param grant_type: Unicode grant type, i.e. authorization_code, password.
        :param client: Client object set by you, see authenticate_client.
        :param request: The HTTP Request (oauthlib.common.Request)
        :rtype: True or False

        Method is used by:
            - Authorization Code Grant
            - Resource Owner Password Credentials Grant
            - Client Credentials Grant
            - Refresh Token Grant
        """
        if self._api_hooks.user_getter is None and grant_type == "password":
            log.debug("Password credential authorization is disabled.")
            return False

        default_grant_types = (
            "authorization_code",
            "password",
            "client_credentials",
            "refresh_token",
        )

        # Grant type is allowed if it is part of the 'allowed_grant_types'
        # of the selected client or if it is one of the default grant types
        if hasattr(client, "allowed_grant_types") and (
            client.allowed_grant_types is not None
        ):
            if grant_type not in client.allowed_grant_types:
                return False
        else:
            if grant_type not in default_grant_types:
                return False

        if grant_type == "client_credentials":
            try:
                # handle this as a try/except instead of testing
                # why? a cached object may not have the attribute on the object,
                #      but may fallback onto a dict presence or other method to
                #      provide a `user` when the attribute is touched.
                request.user = client.user
            except AttributeError:
                log.debug("Client should have a user property")
                return False

        return True

    def validate_redirect_uri(self, client_id, redirect_uri, request, *args, **kwargs):
        """Ensure client is authorized to redirect to the redirect_uri.

        This method is used in the authorization code grant flow and also
        in implicit grant flow. It will detect if redirect_uri in client's
        redirect_uris strictly, you can add a `validate_redirect_uri`
        function on grant for a customized validation.
        """
        request.client = request.client or self._api_hooks.client_getter(client_id)
        client = request.client
        if (
            hasattr(client, "validate_redirect_uri") and client.validate_redirect_uri
        ):  # ensure it is defined
            return client.validate_redirect_uri(redirect_uri)
        return redirect_uri in client.redirect_uris

    def validate_refresh_token(self, refresh_token, client, request, *args, **kwargs):
        """Ensure the token is valid and belongs to the client

        OBS! The request.user attribute should be set to the resource owner
        associated with this refresh token.

        This method is used by the authorization code grant indirectly by
        issuing refresh tokens, resource owner password credentials grant
        (also indirectly) and the refresh token grant.

        :param client_id: Unicode client identifier
        :param redirect_uri: Unicode absolute URI
        :param request: The HTTP Request (oauthlib.common.Request)
        :rtype: True or False

        Method is used by:
            - Authorization Code Grant
            - Implicit Grant
        """
        token = self._api_hooks.token_getter(refresh_token=refresh_token)

        if token and token.client_id == client.client_id:
            # Make sure the request object contains user and client_id
            request.client_id = token.client_id
            request.user = token.user
            return True
        return False

    def validate_response_type(
        self, client_id, response_type, client, request, *args, **kwargs
    ):
        """Ensure client is authorized to use the response type requested.

        It will allow any of the two (`code`, `token`) response types by
        default. Implemented `allowed_response_types` for client object
        to authorize the request.

        :param client_id: Unicode client identifier
        :param response_type: Unicode response type, i.e. code, token.
        :param client: Client object set by you, see authenticate_client.
        :param request: The HTTP Request (oauthlib.common.Request)
        :rtype: True or False

        Method is used by:
            - Authorization Code Grant
            - Implicit Grant
        """
        if response_type not in ("code", "token"):
            return False

        if hasattr(client, "allowed_response_types") and (
            client.allowed_response_types is not None
        ):
            return response_type in client.allowed_response_types
        return True

    def validate_scopes(self, client_id, scopes, client, request, *args, **kwargs):
        """Ensure the client is authorized access to requested scopes.

        :param client_id: Unicode client identifier
        :param scopes: List of scopes (defined by you)
        :param client: Client object set by you, see authenticate_client.
        :param request: The HTTP Request (oauthlib.common.Request)
        :rtype: True or False

        Method is used by all core grant types:
            - Authorization Code Grant
            - Implicit Grant
            - Resource Owner Password Credentials Grant
            - Client Credentials Grant
        """
        if scopes is None:
            scopes = []
        if hasattr(client, "validate_scopes") and client.validate_scopes:
            return client.validate_scopes(scopes)
        return set(client.default_scopes).issuperset(set(scopes))

    def validate_silent_authorization(self, request):
        """Ensure the logged in user has authorized silent OpenID authorization.

        Silent OpenID authorization allows access tokens and id tokens to be
        granted to clients without any user prompt or interaction.

        :param request: The HTTP Request (oauthlib.common.Request)
        :rtype: True or False

        Method is used by:
            - OpenIDConnectAuthCode
            - OpenIDConnectImplicit
            - OpenIDConnectHybrid
        """
        raise NotImplementedError("Subclasses must implement this method.")

    def validate_silent_login(self, request):
        """Ensure session user has authorized silent OpenID login.

        If no user is logged in or has not authorized silent login, this
        method should return False.

        If the user is logged in but associated with multiple accounts and
        not selected which one to link to the token then this method should
        raise an oauthlib.oauth2.AccountSelectionRequired error.

        :param request: The HTTP Request (oauthlib.common.Request)
        :rtype: True or False

        Method is used by:
            - OpenIDConnectAuthCode
            - OpenIDConnectImplicit
            - OpenIDConnectHybrid
        """
        raise NotImplementedError("Subclasses must implement this method.")

    def validate_user(self, username, password, client, request, *args, **kwargs):
        """Ensure the username and password is valid.

        OBS! The validation should also set the user attribute of the request
        to a valid resource owner, i.e. request.user = username or similar. If
        not set you will be unable to associate a token with a user in the
        persistance method used (commonly, save_bearer_token).

        :param username: Unicode username
        :param password: Unicode password
        :param client: Client object set by you, see authenticate_client.
        :param request: The HTTP Request (oauthlib.common.Request)
        :rtype: True or False

        Method is used by:
            - Resource Owner Password Credentials Grant
        """
        log.debug("Validating username %r and its password", username)
        if self._api_hooks.user_getter is not None:
            user = self._api_hooks.user_getter(
                username, password, client, request, *args, **kwargs
            )
            if user:
                request.user = user
                return True
            return False
        log.debug("Password credential authorization is disabled.")
        return False

    def validate_user_match(self, id_token_hint, scopes, claims, request):
        """Ensure client supplied user id hint matches session user.

        If the sub claim or id_token_hint is supplied then the session
        user must match the given ID.

        :param id_token_hint: User identifier string.
        :param scopes: List of OAuth 2 scopes and OpenID claims (strings).
        :param claims: OpenID Connect claims dict.
        :param request: The HTTP Request (oauthlib.common.Request)
        :rtype: True or False

        Method is used by:
            - OpenIDConnectAuthCode
            - OpenIDConnectImplicit
            - OpenIDConnectHybrid
        """
        raise NotImplementedError("Subclasses must implement this method.")
