import logging

log = logging.getLogger(__name__)


# pypi, upstream
from oauthlib.oauth1 import RequestValidator
from oauthlib.oauth1 import WebApplicationServer as Server
from oauthlib.common import to_unicode, add_params_to_uri, urlencode
from oauthlib.oauth1.rfc5849 import errors


# ==============================================================================


class OAuth1RequestValidator_Hooks(object):
    """
    Subclass this and implement.  OAuth1RequestValidator calls this object.

    This class encapsulates all the database access you should require.
    """

    pyramid_request = None  # stash the pyramid request object

    def __init__(self, pyramid_request):
        self.pyramid_request = pyramid_request
        self._config = pyramid_request.registry.settings or {}

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    def ensure_request_client(self, request, client_key):
        """
        This is a utility method based on the flask-oauthlib implementation.
        It is used to ensure a request.client object based on the client_key if one is not set-up yet
        """
        if not request.client:
            request.client = self.client_getter(client_key=client_key)
        # should this be in the client_getter ?
        if not request.client:
            raise errors.InvalidClientError("Invalid Client")

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    #
    # client getter
    #
    def client_getter(self, client_key=None):
        """Retreive a valid client

        :param client_key: The client/consumer key.

        returns `docs.oauth1.object_interfaces.Client()`

        OR

        raise oauth1_errors.InvalidClientError("Invalid Client")

        EXAMPLE:

            def client_getter(self, client_key=None):
                client = dbSession.get(client_key)
                if not client_key:
                    raise errors.InvalidClientError("Invalid Client")
                return client

        EXAMPLE ARGS:

            client_key = u'ExampleApp'
        """
        raise NotImplementedError("Subclasses must implement this function.")

    #
    # access token getter and setter
    #
    def access_token_getter(self, client_key=None, token=None):
        """
        :param client_key: The client/consumer key.
        :param token: The access token string.

        returns `docs.oauth1.object_interfaces.AccessToken()`
        """
        raise NotImplementedError("Subclasses must implement this function.")

    def access_token_setter(self, token=None, request=None):
        """
        The function accepts `client_key` and `token` parameters

        :param token: A `docs.oauth1.object_interfaces.AccessTokenDict` (dict)
        :param request: An oauthlib.common.Request object.

        returns `None`

        The access token dictionary will at minimum include

        docs.oauth1.object_interfaces.AccessTokenDict
        * ``oauth_token`` the access token string.
        * ``oauth_token_secret`` the token specific secret used in signing.
        * ``oauth_authorized_realms`` a space separated list of realms.

        In order to get the Useraccount.id, we need to pull in the linked RequestToken/Verifier

        The following params can be used for the lookup:
            * ``request.verifier``
            * ``request.oauth_params['oauth_verifier']``
            * ``request.oauth_params['oauth_token']``
        """
        raise NotImplementedError("Subclasses must implement this function.")

    def create_access_token_existing(self, request, credentials):
        """
        THIS IS A DEV; NOT IMPLEMENTED IN MAIN
        """
        return self._api_hooks.create_access_token_existing(request, credentials)

    #
    # request token getter and setter | AKA grantsetter grantgetter
    #
    def request_token_getter(self, token=None):
        """
        :param token: The request token string.
        Note that the returned key must be in plaintext.

        returns `docs.oauth1.object_interfaces.RequestToken()`

        EXAMPLE ARGS:

            token = u'CdTQe0UY5P8qJspbhzSgDUUkG81laZ
        """
        raise NotImplementedError("Subclasses must implement this function.")

    def request_token_setter(self, token=None, request=None):
        """
        :param token docs.oauth1.object_interfaces.RequestTokenDict:
        :param request: An oauthlib.common.Request object.

        The ``token`` dictionary will at minimum include

        docs.oauth1.object_interfaces.RequestTokenDict
        * ``oauth_token`` the request token string.
        * ``oauth_token_secret`` the token specific secret used in signing.
        * ``oauth_callback_confirmed`` the string ``true``.

        returns `None`

        EXAMPLE ARGS:

            token = {u'oauth_token_secret': u'nKACQqFNUXuN6nuBsKp4n2KZ5pLw0U',
                     u'oauth_token': u'TSNpTbV4nGJUNk8DPDfYjcs13aNstK',
                     u'oauth_callback_confirmed': u'true'
                     }

        USED AT ENDPOINTS:
            * request_token
        """
        raise NotImplementedError("Subclasses must implement this function.")

    def request_token_invalidator(self, request, client_key, request_token):
        """
        :param request: An oauthlib.common.Request object.
        :param client_key: The client/consumer key.
        :param request_token: The request token string.
        :returns: The rsa public key as a string.

        EXAMPLE ARGS:

        USED AT ENDPOINTS:
            * access_token
        """
        raise NotImplementedError("Subclasses must implement this function.")

    #
    # nonce and timestamp
    #
    def nonce_getter(
        self,
        client_key=None,
        timestamp=None,
        nonce=None,
        request_token=None,
        access_token=None,
        request=None,
    ):
        """A nonce and timestamp make each request unique.

        :param client_key: The client/consure key
        :param timestamp: The ``oauth_timestamp`` parameter
        :param nonce: The ``oauth_nonce`` parameter
        :param request_token: Request token string, if any
        :param access_token: Access token string, if any
        :param request: An oauthlib.common.Request object.

        returns `bool` (True or False)

        EXAMPLE ARGS:

            client_key: u'ExampleApp'
            timestamp: u'1439077768'
            nonce = u'999808839934571754|1439077768'
            request_token: None
            access_token: None
        """
        raise NotImplementedError("Subclasses must implement this function.")

    def nonce_setter(
        self,
        client_key=None,
        timestamp=None,
        nonce=None,
        request_token=None,
        access_token=None,
        request=None,
    ):
        """The timestamp will be expired in 60s, it would be a better design
        if you put timestamp and nonce object in a cache.

        You should check for the client
            if not request.client:
                return False

        The parameters are the same with :meth:`noncegetter`::

        returns `None`

        USED AT ENDPOINTS:
            * request_token
        """
        raise NotImplementedError("Subclasses must implement this function.")

    #
    # verifier getter and setter
    #
    def verifier_getter(self, verifier=None, token=None):
        """
        :param verifier: The authorization verifier string.
        :param token: A request token string.

        returns `docs.oauth1.object_interfaces.RequestToken()`

        EXAMPLE ARGS:

            token = u'CdTQe0UY5P8qJspbhzSgDUUkG81laZ
            verifier = u'M01sY5eH9qqI8OblqQ0RLN4H6jPzSG'
        """
        raise NotImplementedError("Subclasses must implement this function.")

    def verifier_setter(self, token=None, verifier=None, request=None):
        """
        :param token: A request token string.
        :param verifier A dictionary implementing ``docs.oauth1.object_interfaces.VerifierDict`` (containing ``oauth_verifier`` and ``oauth_token``)
        :param request: An oauthlib.common.Request object.

        returns `None`

        EXAMPLE ARGS:

            token = u'CdTQe0UY5P8qJspbhzSgDUUkG81laZ
            verifier = {u'oauth_verifier': u'M01sY5eH9qqI8OblqQ0RLN4H6jPzSG',
                        u'oauth_token': u'CdTQe0UY5P8qJspbhzSgDUUkG81laZ',
                        }

        USED AT ENDPOINTS:
            * authorize
        """
        raise NotImplementedError("Subclasses must implement this function.")


# ------------------------------------------------------------------------------


class OAuth1RequestValidator(RequestValidator):
    """Subclass of Request Validator.'

    inspired by flask.oauthlib but based largely on oauthlib directly


    Not overridden:
        * @safe_characters -> (character set)

    """

    request = None
    _config = None
    _config_prefix = "oauth1.provider."
    _api_hooks = None

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    def __init__(self, pyramid_request, validator_api_hooks=None):
        """Builds a new RequestValidator

        :param pyramid_request: pyramid `request` object.
        :param validator_api_hooks: A subclass of `OAuth1RequestValidator_Hooks`
        """
        self.pyramid_request = pyramid_request
        self._config = pyramid_request.registry.settings or {}
        self._api_hooks = validator_api_hooks

    def _get_RequestTokenObject(self, request, token, client_key=None):
        """
        :param token: a `token` string.
        :param client_key: a `client_key` string, optional.

        This is a utility method based on the flask-oauthlib implementation.
        It is used to get/stash a RequestTokenObject based on a token string

        if `client_key` is passed in, the `RequestTokenObject` is ensured to have the corresponding client_key

        RequestTokenObject implements the docs.oauth1.object_interfaces.RequestTokenObject
        """
        try:
            if hasattr(request, "RequestTokenObject") and request.RequestTokenObject:
                tokenObj = request.RequestTokenObject
            else:
                tokenObj = self._api_hooks.request_token_getter(token=token)
            if tokenObj:
                if client_key is None or (client_key == tokenObj.client_key):
                    # set the token object
                    request.RequestTokenObject = tokenObj
                else:
                    tokenObj = None
            return tokenObj
        except Exception as exc:
            raise

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @property
    def allowed_signature_methods(self):
        """Allowed signature methods.

        Default value: SIGNATURE_HMAC and SIGNATURE_RSA.

        You can customize with app Config:

            - "%sSIGNATURE_METHODS" % _config_prefix
        """
        return self._config.get(
            "%sSIGNATURE_METHODS" % self._config_prefix,
            super(OAuth1RequestValidator, self).allowed_signature_methods,
        )

    @property
    def client_key_length(self):
        """defaults to oauthlib.oauth1.RequestValidator.client_key_length if not configured"""
        return self._config.get(
            "%sCLIENT_KEY_LENGTH" % self._config_prefix,
            super(OAuth1RequestValidator, self).client_key_length,
        )

    @property
    def request_token_length(self):
        """defaults to oauthlib.oauth1.RequestValidator.request_token_length if not configured"""
        return self._config.get(
            "%sREQUEST_TOKEN_LENGTH" % self._config_prefix,
            super(OAuth1RequestValidator, self).request_token_length,
        )

    @property
    def access_token_length(self):
        """defaults to oauthlib.oauth1.RequestValidator.access_token_length if not configured"""
        return self._config.get(
            "%sACCESS_TOKEN_LENGTH" % self._config_prefix,
            super(OAuth1RequestValidator, self).access_token_length,
        )

    @property
    def nonce_length(self):
        """defaults to oauthlib.oauth1.RequestValidator.nonce_length if not configured"""
        return self._config.get(
            "%sNONCE_LENGTH" % self._config_prefix,
            super(OAuth1RequestValidator, self).nonce_length,
        )

    @property
    def verifier_length(self):
        """defaults to oauthlib.oauth1.RequestValidator.verifier_length if not configured"""
        return self._config.get(
            "%sVERIFIER_LENGTH" % self._config_prefix,
            super(OAuth1RequestValidator, self).verifier_length,
        )

    @property
    def realms(self):
        """defaults to oauthlib.oauth1.RequestValidator.realms if not configured"""
        return self._config.get(
            "%sREALMS" % self._config_prefix, super(OAuth1RequestValidator, self).realms
        )

    @property
    def enforce_ssl(self):
        """Enforce SSL request.

        Default is True. You can customize with:

            - '%sENFORCE_SSL' % self._config_prefix
        """
        return self._config.get("%sENFORCE_SSL" % self._config_prefix, True)

    @property
    def dummy_client(self):
        return to_unicode("dummy_client", "utf-8")

    @property
    def dummy_request_token(self):
        return to_unicode("dummy_request_token", "utf-8")

    @property
    def dummy_access_token(self):
        return to_unicode("dummy_access_token", "utf-8")

    def get_client_secret(self, client_key, request):
        """Retrieves the client secret associated with the client key

        :param client_key: The client/consumer key.
        :param request: An oauthlib.common.Request object.
        :returns: The client secret as a string.

        Note that the returned key must be in plaintext.
        """
        log.debug("OAuth1RequestValidator.get_client_secret(%r)", client_key)
        self._api_hooks.ensure_request_client(request, client_key=client_key)
        if request.client:
            return request.client.client_secret
        return None

    def get_request_token_secret(self, client_key, token, request):
        """Retrieves the shared secret associated with the request token.

        :param client_key: The client/consumer key.
        :param token: The request token string.
        :param request: An oauthlib.common.Request object.
        :returns: The token secret as a string.

        Note that the returned key must be in plaintext.
        """
        log.debug(
            "OAuth1RequestValidator.get_request_token_secret(%r, %r)", client_key, token
        )
        tok = self._get_RequestTokenObject(request, token, client_key=client_key)
        if tok and tok.client_key == client_key:
            return tok.secret
        return None

    def get_access_token_secret(self, client_key, token, request):
        """Retrieves the shared secret associated with the access token.

        :param client_key: The client/consumer key.
        :param token: The access token string.
        :param request: An oauthlib.common.Request object.
        :returns: The token secret as a string.

        Note that the returned key must be in plaintext.
        """
        log.debug(
            "OAuth1RequestValidator.get_access_token_secret(%r, %r)", client_key, token
        )
        tok = request.access_token or self._api_hooks.access_token_getter(
            client_key=client_key, token=token
        )
        if tok:
            request.access_token = tok
            return tok.secret
        return None

    def get_default_realms(self, client_key, request):
        """Get the default realms for a client.

        :param client_key: The client/consumer key.
        :param request: An oauthlib.common.Request object.
        :returns: The list of default realms associated with the client.

        The list of default realms will be set during client registration and
        is outside the scope of OAuthLib.
        """
        log.debug("OAuth1RequestValidator.get_default_realms(%r)", client_key)
        self._api_hooks.ensure_request_client(request, client_key=client_key)
        if hasattr(request.client, "default_realms"):
            return request.client.default_realms
        return []

    def get_realms(self, token, request):
        """Get realms associated with a request token.

        :param token: The request token string.
        :param request: An oauthlib.common.Request object.
        :returns: The list of realms associated with the request token.
        """
        log.debug("OAuth1RequestValidator.get_realms(%r)", token)
        tok = self._get_RequestTokenObject(request, token)
        if not tok:
            return []
        if hasattr(tok, "realms"):
            return tok.realms or []
        return []

    def get_redirect_uri(self, token, request):
        """Get the redirect URI associated with a request token.

        :param token: The request token string.
        :param request: An oauthlib.common.Request object.
        :returns: The redirect URI associated with the request token.
        """
        log.debug("OAuth1RequestValidator.get_redirect_uri(%r)", token)
        tok = self._get_RequestTokenObject(request, token)
        return tok.redirect_uri

    def get_rsa_key(self, client_key, request):
        """Retrieves a previously stored client provided RSA key.

        :param client_key: The client/consumer key.
        :param request: An oauthlib.common.Request object.
        :returns: The rsa public key as a string.
        """
        log.debug("OAuth1RequestValidator.get_rsa_key(%r)", client_key)
        self._api_hooks.ensure_request_client(request, client_key=client_key)
        if hasattr(request.client, "rsa_key"):
            return request.client.rsa_key
        return None

    def invalidate_request_token(self, client_key, request_token, request):
        """Invalidates a used request token.

        :param client_key: The client/consumer key.
        :param request_token: The request token string.
        :param request: An oauthlib.common.Request object.
        :returns: None
        """
        log.debug(
            "OAuth1RequestValidator.invalidate_request_token(%r, %r)",
            client_key,
            request_token,
        )
        self._api_hooks.request_token_invalidator(request, client_key, request_token)

    def validate_client_key(self, client_key, request):
        """Validates that supplied client key is a registered and valid client.

        :param client_key: The client/consumer key.
        :param request: An oauthlib.common.Request object.
        :returns: True or False
        """
        log.debug("OAuth1RequestValidator.validate_client_key(%r, )", client_key)
        self._api_hooks.ensure_request_client(request, client_key=client_key)
        if request.client:
            return True
        return False

    def validate_request_token(self, client_key, token, request):
        """Validates that supplied request token is registered and valid.

        :param client_key: The client/consumer key.
        :param token: The request token string.
        :param request: An oauthlib.common.Request object.
        :returns: True or False
        """
        log.debug(
            "OAuth1RequestValidator.validate_request_token(%r, %r)", client_key, token
        )
        tok = self._get_RequestTokenObject(request, token, client_key=client_key)
        if tok and tok.client_key == client_key:
            return True
        return False

    def validate_access_token(self, client_key, token, request):
        """Validates that supplied access token is registered and valid.

        :param client_key: The client/consumer key.
        :param token: The access token string.
        :param request: An oauthlib.common.Request object.
        :returns: True or False
        """
        log.debug(
            "OAuth1RequestValidator.validate_access_token(%r, %r)", client_key, token
        )
        tok = request.access_token or self._api_hooks.access_token_getter(
            client_key=client_key, token=token
        )
        if tok:
            request.access_token = tok
            return True
        return False

    def validate_timestamp_and_nonce(
        self,
        client_key,
        timestamp,
        nonce,
        request,
        request_token=None,
        access_token=None,
    ):
        """Validates that the nonce has not been used before.

        :param client_key: The client/consumer key.
        :param timestamp: The ``oauth_timestamp`` parameter.
        :param nonce: The ``oauth_nonce`` parameter.
        :param request_token: Request token string, if any.
        :param access_token: Access token string, if any.
        :param request: An oauthlib.common.Request object.

        :returns: True or False

        Logic:
        1. Calls `self._api_hooks.nonce_getter` to see if the nonce has been used
        2. If the nonce has been used, returns False
        3. If the nonce has not been used, sets the nonce
        4. Returns True
        """
        log.debug(
            "OAuth1RequestValidator.validate_timestamp_and_nonce(%r, %r, %r)",
            client_key,
            timestamp,
            nonce,
        )
        nonce_exists = self._api_hooks.nonce_getter(
            client_key=client_key,
            timestamp=timestamp,
            nonce=nonce,
            request_token=request_token,
            access_token=access_token,
            request=request,
        )
        if nonce_exists:
            return False
        self._api_hooks.nonce_setter(
            client_key=client_key,
            timestamp=timestamp,
            nonce=nonce,
            request_token=request_token,
            access_token=access_token,
            request=request,
        )
        return True

    def validate_redirect_uri(self, client_key, redirect_uri, request):
        """Validates the client supplied redirection URI.

        :param client_key: The client/consumer key.
        :param redirect_uri: The URI the client which to redirect back to after
                             authorization is successful.
        :param request: An oauthlib.common.Request object.
        :returns: True or False
        """
        log.debug(
            "OAuth1RequestValidator.validate_redirect_uri(%r, %r)",
            client_key,
            redirect_uri,
        )
        self._api_hooks.ensure_request_client(request, client_key=client_key)
        if not request.client:
            return False
        if not request.client.redirect_uris and redirect_uri is None:
            return True
        request.redirect_uri = redirect_uri
        return redirect_uri in request.client.redirect_uris

    def validate_requested_realms(self, client_key, realms, request):
        """Validates that the client may request access to the realm.

        :param client_key: The client/consumer key.
        :param realms: The list of realms that client is requesting access to.
        :param request: An oauthlib.common.Request object.
        :returns: True or False
        """
        log.debug(
            "OAuth1RequestValidator.validate_requested_realms(%r, %r)",
            client_key,
            realms,
        )
        self._api_hooks.ensure_request_client(request, client_key=client_key)
        if not request.client:
            return False
        # the client might not have an attribute, or might have one set to `None`
        if (
            hasattr(request.client, "validate_realms")
            and request.client.validate_realms
        ):
            return request.client.validate_realms(realms)
        if set(request.client.default_realms).issuperset(set(realms)):
            return True
        return True

    def validate_realms(self, client_key, token, request, uri=None, realms=None):
        """Validates access to the request realm.

        :param client_key: The client/consumer key.
        :param token: A request token string.
        :param request: An oauthlib.common.Request object.
        :param uri: The URI the realms is protecting.
        :param realms: A list of realms that must have been granted to
                       the access token.
        :returns: True or False
        """
        log.debug("OAuth1RequestValidator.validate_realms(%r, %r)", client_key, token)
        if request.access_token:
            tok = request.access_token
        else:
            tok = self._api_hooks.access_token_getter(
                client_key=client_key, token=token
            )
            request.access_token = tok
        if not tok:
            return False
        return set(tok.realms).issuperset(set(realms))

    def validate_verifier(self, client_key, token, verifier, request):
        """Validates a verification code.

        :param client_key: The client/consumer key.
        :param token: A request token string.
        :param verifier: The authorization verifier string.
        :param request: An oauthlib.common.Request object.
        :returns: True or False
        """
        log.debug(
            "OAuth1RequestValidator.validate_verifier(%r, %r, %r)",
            client_key,
            token,
            verifier,
        )
        data = self._api_hooks.verifier_getter(verifier=verifier, token=token)
        if not data:
            return False
        if False:
            if not hasattr(data, "user"):
                log.debug("Verifier should have `user` attribute")
                return False
            request.user = data.user
        if hasattr(data, "client_key"):
            return data.client_key == client_key
        return True

    def verify_request_token(self, token, request):
        """Verify that the given OAuth1 request token is valid.

        :param token: A request token string.
        :param request: An oauthlib.common.Request object.
        :returns: True or False
        """
        log.debug("OAuth1RequestValidator.verify_request_token(%r)", token)
        tok = self._get_RequestTokenObject(request, token)
        if tok:
            return True
        return False

    def verify_realms(self, token, realms, request):
        """Verify authorized realms to see if they match those given to token.

        :param token: An access token string.
        :param realms: A list of realms the client attempts to access.
        :param request: An oauthlib.common.Request object.
        :returns: True or False
        """
        log.debug("OAuth1RequestValidator.verify_realms(%r, %r)", token, realms)
        tok = self._get_RequestTokenObject(request, token)
        if not tok:
            return False
        if not hasattr(tok, "realms"):
            # realms not enabled
            return True
        return set(tok.realms) == set(realms)

    def save_access_token(self, token, request):
        """Save an OAuth1 access token.

        :param token: A dict with token credentials, implementing ``docs.oauth1.object_interfaces.AccessTokenDict``
        :param request: An oauthlib.common.Request object.

        The token dictionary will at minimum include

        * ``oauth_token`` the access token string.
        * ``oauth_token_secret`` the token specific secret used in signing.
        * ``oauth_authorized_realms`` a space separated list of realms.
        """
        log.debug("OAuth1RequestValidator.save_access_token(%r)", token)
        self._api_hooks.access_token_setter(token, request)

    def save_request_token(self, token, request):
        """Save an OAuth1 request token.

        :param token: A dict with token credentials, implementing ``docs.oauth1.object_interfaces.RequestTokenDict``
        :param request: An oauthlib.common.Request object.

        The token dictionary Implements the ``docs.oauth1.object_interfaces.RequestTokenDict``
        and will at minimum include:
        * ``oauth_token`` the request token string.
        * ``oauth_token_secret`` the token specific secret used in signing.
        * ``oauth_callback_confirmed`` the string ``true``.

        Note: Client key can be obtained from ``request.client_key``.
        """
        log.debug("OAuth1RequestValidator.save_request_token(%r)", token)
        self._api_hooks.request_token_setter(token, request)

    def save_verifier(self, token, verifier, request):
        """Associate an authorization verifier with a request token.

        :param token: A request token string.
        :param verifier A dictionary implementing ``docs.oauth1.object_interfaces.VerifierDict`` (containing ``oauth_verifier`` and ``oauth_token``)
        :param request: An oauthlib.common.Request object.

        The `verifier` dictionary implements the ``docs.oauth1.object_interfaces.VerifierDict``:
        * ``oauth_verifier``
        * ``oauth_token``

        We need to associate verifiers with tokens for validation during the
        access token request.

        Note that unlike save_x_token token here is the ``oauth_token`` token
        string from the request token saved previously.
        """
        log.debug("OAuth1RequestValidator.save_verifier(%r, %r)", token, verifier)
        self._api_hooks.verifier_setter(token=token, verifier=verifier, request=request)

    def create_access_token_existing(self, request, credentials):
        """
        THIS IS A DEV; NOT IMPLEMENTED IN MAIN

        returns `None`
                or
                {
                    'oauth_token': existing_token.oauth_token,
                    'oauth_token_secret': existing_token.oauth_token_secret,
                    'oauth_authorized_realms': ' '.join(existing_token.realms)
                }
        """
        log.debug(
            "OAuth1RequestValidator.create_access_token_existing(%r)", credentials
        )
        return self._api_hooks.create_access_token_existing(request, credentials)
