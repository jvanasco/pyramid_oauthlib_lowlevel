# stdlib
import datetime
import pdb
import time

# pypi
import sqlalchemy
import sqlalchemy.orm
from oauthlib.oauth1.rfc5849 import errors as oauthlib_oauth1_errors

# local module
from pyramid_oauthlib_lowlevel.oauth1.validator import OAuth1RequestValidator_Hooks
from pyramid_oauthlib_lowlevel.oauth1.validator import OAuth1RequestValidator
from pyramid_oauthlib_lowlevel.oauth1 import provider as oauth1_provider
from pyramid_oauthlib_lowlevel.client.api_client import ApiClient
from pyramid_oauthlib_lowlevel.utils import catch_backend_failure

# local tests
from . import oauth1_model
from .oauth1_model import Developer_oAuth1Server_TokenAccess
from .oauth1_model import Developer_oAuth1Server_TokenRequest
from .oauth1_model import Developer_oAuth1Server_Nonce
from .oauth1_model import DeveloperApplication
from .oauth1_model import DeveloperApplication_Keyset
from .oauth1_model import OAUTH1__APP_ID
from .oauth1_model import OAUTH1__APP_KEY
from .oauth1_model import OAUTH1__APP_SECRET
from .oauth1_model import OAUTH1__URL_APP_FLOW_REGISTER_CALLBACK
from .oauth1_model import OAUTH1__URL_AUTHORITY_AUTHENTICATE
from .oauth1_model import OAUTH1__URL_AUTHORITY_ACCESS_TOKEN
from .oauth1_model import OAUTH1__URL_AUTHORITY_REQUEST_TOKEN

# ==============================================================================


class CustomApiClient(ApiClient):
    _user_agent = "CustomApiClient v0"

    OAUTH1_SERVER_AUTHENTICATE = OAUTH1__URL_AUTHORITY_AUTHENTICATE
    OAUTH1_SERVER_ACCESS_TOKEN = OAUTH1__URL_AUTHORITY_ACCESS_TOKEN
    OAUTH1_SERVER_REQUEST_TOKEN = OAUTH1__URL_AUTHORITY_REQUEST_TOKEN


class ApiPermissionsError(Exception):
    pass


class CustomValidator(OAuth1RequestValidator):
    """some validator methods do need overrides.  sigh"""

    @property
    def client_key_length(self):
        return (40, 64)

    @property
    def request_token_length(self):
        # oauth1 /authority/oauth1/access_token | oauth_token="XQWzz9jMgIjZvPwk4iMHO6nxKlZQvq", oauth_verifier="k4kp0FZT0XSWFr6CQ1p2jMPZ5i4fLr",
        return (30, 64)

    @property
    def access_token_length(self):
        return (20, 64)

    @property
    def verifier_length(self):
        return (20, 64)

    @property
    def realms(self):
        return ["platform.actor"]


# ------------------------------------------------------------------------------


class CustomValidator_Hooks(OAuth1RequestValidator_Hooks):
    """
    This custom object expects a SqlAlchemy connection on `self.pyramid_request.dbSession`
    """

    @catch_backend_failure
    def _get_TokenRequest_by_verifier(self, verifier, request=None):
        """
        :param verifier: The verifier string.
        :param request: An oauthlib.common.Request object.
        """
        verifierObject = (
            self.pyramid_request.dbSession.query(Developer_oAuth1Server_TokenRequest)
            .filter(
                Developer_oAuth1Server_TokenRequest.oauth_verifier == verifier,
                Developer_oAuth1Server_TokenRequest.is_active == True,  # noqa
            )
            .first()
        )
        return verifierObject

    @catch_backend_failure
    def _get_TokenRequest_by_token(self, token, request=None):
        """
        :param token: The token string.
        :param request: An oauthlib.common.Request object.
        """
        tokenObject = (
            self.pyramid_request.dbSession.query(Developer_oAuth1Server_TokenRequest)
            .filter(
                Developer_oAuth1Server_TokenRequest.oauth_token == token,
                Developer_oAuth1Server_TokenRequest.is_active == True,  # noqa
            )
            .first()
        )
        return tokenObject

    @catch_backend_failure
    def _get_NonceObject_by_nonce(self, nonce):
        """
        :param nonce: The nonce string.
        :param request: An oauthlib.common.Request object.
        """
        nonceObject = (
            self.pyramid_request.dbSession.query(Developer_oAuth1Server_Nonce)
            .filter(Developer_oAuth1Server_Nonce.nonce == nonce)
            .first()
        )
        return nonceObject

    #
    # client getter
    #
    @catch_backend_failure
    def client_getter(self, client_key=None):
        """Retreive a valid client

        :param client_key: The client/consumer key.

        returns `docs.oauth1.object_interfaces.Client()`

        EXAMPLE ARGS:

            client_key = u'ExampleApp'
        """
        clientObject = (
            self.pyramid_request.dbSession.query(DeveloperApplication)
            .join(
                DeveloperApplication_Keyset,
                DeveloperApplication.id
                == DeveloperApplication_Keyset.developer_application_id,
            )
            .filter(
                DeveloperApplication_Keyset.consumer_key == client_key,
                DeveloperApplication_Keyset.is_active == True,  # noqa
            )
            .options(sqlalchemy.orm.contains_eager("app_keyset_active"))
            .first()
        )
        # if not clientObject:
        #    raise oauthlib_oauth1_errors.InvalidClientError("Invalid Client")
        return clientObject

    #
    # access token getter and setter
    #
    @catch_backend_failure
    def access_token_getter(self, client_key=None, token=None):
        """
        :param client_key: The client/consumer key.
        :param token: The access token string.

        returns `docs.oauth1.object_interfaces.AccessToken()`
        """
        clientObject = self.client_getter(client_key=client_key)
        tokenObject = (
            self.pyramid_request.dbSession.query(Developer_oAuth1Server_TokenAccess)
            .filter(
                Developer_oAuth1Server_TokenAccess.developer_application_id
                == clientObject.id,
                Developer_oAuth1Server_TokenAccess.is_active == True,  # noqa
            )
            .first()
        )
        return tokenObject

    @catch_backend_failure
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
        verifierObject = self._get_TokenRequest_by_verifier(
            request.verifier, request=request
        )
        if not verifierObject:
            # we always have a verifier!
            raise ApiPermissionsError("Invalid Verifier")

        # do we have an existing token?
        existingToken = (
            self.pyramid_request.dbSession.query(Developer_oAuth1Server_TokenAccess)
            .filter(
                Developer_oAuth1Server_TokenAccess.developer_application_id
                == verifierObject.developer_application_id,
                Developer_oAuth1Server_TokenAccess.useraccount_id
                == verifierObject.useraccount_id,
                Developer_oAuth1Server_TokenAccess.is_active == True,  # noqa
            )
            .first()
        )
        if existingToken:
            # revoke it!
            pass

        tokenObject = Developer_oAuth1Server_TokenAccess()
        tokenObject.oauth_token = token["oauth_token"]
        tokenObject.oauth_token_secret = token["oauth_token_secret"]
        tokenObject._realms = token["oauth_authorized_realms"]
        tokenObject.timestamp_created = self.pyramid_request.datetime
        tokenObject.developer_application_id = request.client.id
        tokenObject.useraccount_id = verifierObject.useraccount_id
        tokenObject.oauth_version = "1"
        tokenObject.is_active = True

        self.pyramid_request.dbSession.add(tokenObject)
        self.pyramid_request.dbSession.flush()

    #
    # request token getter and setter
    #
    @catch_backend_failure
    def request_token_getter(self, token=None):
        """
        :param token: The request token string.
        Note that the returned key must be in plaintext.

        returns `docs.oauth1.object_interfaces.RequestToken()`

        EXAMPLE ARGS:

            token = u'CdTQe0UY5P8qJspbhzSgDUUkG81laZ
        """
        tokenObject = self._get_TokenRequest_by_token(token)
        return tokenObject

    @catch_backend_failure
    def request_token_setter(self, token=None, request=None):
        """
        :param token docs.oauth1.object_interfaces.RequestTokenDict:
        :param request: An oauthlib.common.Request object.

        returns `None`

        The token dictionary will at minimum include

        docs.oauth1.object_interfaces.RequestTokenDict
        * ``oauth_token`` the request token string.
        * ``oauth_token_secret`` the token specific secret used in signing.
        * ``oauth_callback_confirmed`` the string ``true``.

        EXAMPLE ARGS:

            token = {u'oauth_token_secret': u'nKACQqFNUXuN6nuBsKp4n2KZ5pLw0U',
                     u'oauth_token': u'TSNpTbV4nGJUNk8DPDfYjcs13aNstK',
                     u'oauth_callback_confirmed': u'true'
                     }

        USED AT ENDPOINTS:
            * request_token
        """
        tokenObject = Developer_oAuth1Server_TokenRequest()
        tokenObject.developer_application_id = request.client.id
        tokenObject.timestamp_created = self.pyramid_request.datetime
        tokenObject.timestamp_expires = (
            self.pyramid_request.datetime + datetime.timedelta(seconds=100)
        )
        tokenObject._realms = " ".join(request.realms)
        tokenObject.redirect_uri = request.redirect_uri
        tokenObject.oauth_token = token["oauth_token"]
        tokenObject.oauth_token_secret = token["oauth_token_secret"]
        tokenObject.oauth_callback_confirmed = token["oauth_callback_confirmed"]
        tokenObject.oauth_version = "1"
        tokenObject.is_active = True
        self.pyramid_request.dbSession.add(tokenObject)
        self.pyramid_request.dbSession.flush()
        return True

    @catch_backend_failure
    def request_token_invalidator(self, request, client_key, request_token):
        """
        :param request: An oauthlib.common.Request object.
        :param client_key: The client/consumer key.
        :param request_token: The request token string.
        :returns: None

        EXAMPLE ARGS:

        USED AT ENDPOINTS:
            * access_token
        """
        tokenObject = self._get_TokenRequest_by_token(request_token, request=request)
        if not tokenObject:
            raise ApiPermissionsError("Invalid Token")
        tokenObject.is_active = False
        self.pyramid_request.dbSession.flush()
        return True

    #
    # nonce and timestamp
    #
    @catch_backend_failure
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
        nonceObject = self._get_NonceObject_by_nonce(nonce)
        return bool(nonceObject)

    @catch_backend_failure
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

        The parameters are the same with :meth:`noncegetter`::

        returns `None`

        USED AT ENDPOINTS:
            * request_token
        """
        self.ensure_request_client(request, client_key)
        if not request.client:
            return False
        nonceObject = Developer_oAuth1Server_Nonce()
        nonceObject.nonce = nonce
        nonceObject.timestamp_created = timestamp
        nonceObject.developer_application_id = request.client.id
        nonceObject.request_token = request_token
        nonceObject.access_token = access_token
        self.pyramid_request.dbSession.add(nonceObject)
        self.pyramid_request.dbSession.flush()

    #
    # verifier getter and setter
    #
    @catch_backend_failure
    def verifier_getter(self, verifier=None, token=None):
        """
        :param verifier A verifier string
        :param token: A request token string.

        returns `docs.oauth1.object_interfaces.RequestToken()`

        EXAMPLE ARGS:

            token = u'CdTQe0UY5P8qJspbhzSgDUUkG81laZ
            verifier = u'M01sY5eH9qqI8OblqQ0RLN4H6jPzSG'
        """
        verifierObject = self._get_TokenRequest_by_verifier(verifier)
        return verifierObject

    @catch_backend_failure
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
        tokenObject = self._get_TokenRequest_by_token(token, request=request)
        if not tokenObject:
            # we always have a tokenObject!
            raise ApiPermissionsError("Invalid Token")
        tokenObject.oauth_verifier = verifier["oauth_verifier"]
        tokenObject.useraccount_id = self.pyramid_request.active_useraccount_id
        self.pyramid_request.dbSession.flush()
        return True

    @catch_backend_failure
    def create_access_token_existing(self, request, credentials):
        """

        DEVELOPMENT

        :param request: An oauthlib.common.Request object.
        :param credentials: probably None.

        returns `None`
                or
                {
                    'oauth_token': existing_token.oauth_token,
                    'oauth_token_secret': existing_token.oauth_token_secret,
                    'oauth_authorized_realms': ' '.join(existing_token.realms)
                }
        """
        verifierObject = self._get_TokenRequest_by_verifier(
            request.verifier, request=request
        )
        if not verifierObject:
            # we always have a verifier!
            raise ApiPermissionsError("Invalid Verifier")

        # do we have an existing token?
        existingToken = (
            self.pyramid_request.dbSession.query(Developer_oAuth1Server_TokenAccess)
            .filter(
                Developer_oAuth1Server_TokenAccess.developer_application_id
                == verifierObject.developer_application_id,
                Developer_oAuth1Server_TokenAccess.useraccount_id
                == verifierObject.useraccount_id,
                Developer_oAuth1Server_TokenAccess.is_active == True,  # noqa
            )
            .first()
        )
        if existingToken:
            if existingToken._realms != " ".join(request.realms):
                existingToken._realms = " ".join(request.realms)
                self.pyramid_request.dbSession.flush()
            return {
                "oauth_token": existingToken.oauth_token,
                "oauth_token_secret": existingToken.oauth_token_secret,
                "oauth_authorized_realms": " ".join(existingToken.realms),
            }
        return None


# ------------------------------------------------------------------------------


def get_ApiExampleAppData():
    app_data = {
        "client_key": OAUTH1__APP_KEY,
        "client_secret": OAUTH1__APP_SECRET,
        "callback_uri": OAUTH1__URL_APP_FLOW_REGISTER_CALLBACK,
        "scope": None,
        "id": OAUTH1__APP_ID,
    }
    return app_data


def new_oauth1Provider(pyramid_request):
    """this is used to build a new auth"""
    validatorHooks = CustomValidator_Hooks(pyramid_request)
    provider = oauth1_provider.OAuth1Provider(
        pyramid_request,
        validator_api_hooks=validatorHooks,
        validator_class=CustomValidator,
    )
    return provider


def oauth_time_now():
    return str(int(time.time()))
