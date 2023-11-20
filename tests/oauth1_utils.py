# stdlib
import datetime
import time
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple
from typing import TYPE_CHECKING

# pypi
import sqlalchemy
import sqlalchemy.orm
from typing_extensions import Literal

# local
from pyramid_oauthlib_lowlevel.client.api_client import ApiClient
from pyramid_oauthlib_lowlevel.oauth1.provider import OAuth1Provider
from pyramid_oauthlib_lowlevel.oauth1.validator import OAuth1RequestValidator
from pyramid_oauthlib_lowlevel.oauth1.validator import OAuth1RequestValidator_Hooks
from pyramid_oauthlib_lowlevel.utils import catch_backend_failure
from .oauth1_model import Developer_oAuth1Server_Nonce
from .oauth1_model import Developer_oAuth1Server_TokenAccess
from .oauth1_model import Developer_oAuth1Server_TokenRequest
from .oauth1_model import DeveloperApplication
from .oauth1_model import DeveloperApplication_Keyset
from .oauth1_model import OAUTH1__APP_ID
from .oauth1_model import OAUTH1__APP_KEY
from .oauth1_model import OAUTH1__APP_SECRET
from .oauth1_model import OAUTH1__URL_APP_FLOW_REGISTER_CALLBACK
from .oauth1_model import OAUTH1__URL_AUTHORITY_ACCESS_TOKEN
from .oauth1_model import OAUTH1__URL_AUTHORITY_AUTHENTICATE
from .oauth1_model import OAUTH1__URL_AUTHORITY_REQUEST_TOKEN

if TYPE_CHECKING:
    from oauthlib.common import Request as oAuth_Request
    from pyramid.request import Request as Pyramid_Request

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
    def client_key_length(self) -> Tuple[int, int]:
        return (40, 64)

    @property
    def request_token_length(self) -> Tuple[int, int]:
        # oauth1 /authority/oauth1/access_token | oauth_token="XQWzz9jMgIjZvPwk4iMHO6nxKlZQvq", oauth_verifier="k4kp0FZT0XSWFr6CQ1p2jMPZ5i4fLr",
        return (30, 64)

    @property
    def access_token_length(self) -> Tuple[int, int]:
        return (20, 64)

    @property
    def verifier_length(self) -> Tuple[int, int]:
        return (20, 64)

    @property
    def realms(self) -> List[str]:
        return ["platform.actor"]


# ------------------------------------------------------------------------------


class CustomValidator_Hooks(OAuth1RequestValidator_Hooks):
    """
    This custom object expects a SqlAlchemy connection on `self.pyramid_request.dbSession`
    """

    @catch_backend_failure
    def _get_TokenRequest_by_verifier(
        self,
        verifier_str: str,
        request: Optional["oAuth_Request"] = None,
    ) -> Optional[Developer_oAuth1Server_TokenRequest]:
        """
        :param verifier: The verifier string.
        :param request: An oauthlib.common.Request object.
        """
        verifierObject = (
            self.pyramid_request.dbSession.query(Developer_oAuth1Server_TokenRequest)
            .filter(
                Developer_oAuth1Server_TokenRequest.oauth_verifier == verifier_str,
                Developer_oAuth1Server_TokenRequest.is_active.is_(True),
            )
            .first()
        )
        return verifierObject

    @catch_backend_failure
    def _get_TokenRequest_by_token(
        self,
        token_str: str,
        request: Optional["oAuth_Request"] = None,
    ) -> Optional[Developer_oAuth1Server_TokenRequest]:
        """
        :param token_str: The token string.
        :param request: An oauthlib.common.Request object.
        """
        tokenObject = (
            self.pyramid_request.dbSession.query(Developer_oAuth1Server_TokenRequest)
            .filter(
                Developer_oAuth1Server_TokenRequest.oauth_token == token_str,
                Developer_oAuth1Server_TokenRequest.is_active.is_(True),
            )
            .first()
        )
        return tokenObject

    @catch_backend_failure
    def _get_NonceObject_by_nonce(
        self,
        nonce: str,
    ) -> Optional[Developer_oAuth1Server_Nonce]:
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
    def client_getter(self, client_key: str) -> Optional[DeveloperApplication]:
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
                DeveloperApplication_Keyset.is_active.is_(True),
            )
            .options(
                sqlalchemy.orm.contains_eager(DeveloperApplication.app_keyset_active)
            )
            .first()
        )
        # if not clientObject:
        #    raise oauthlib_oauth1_errors.InvalidClientError("Invalid Client")
        return clientObject

    #
    # access token getter and setter
    #
    @catch_backend_failure
    def access_token_getter(
        self, client_key: str, token: Optional[str] = None
    ) -> Developer_oAuth1Server_TokenAccess:
        """
        :param client_key: The client/consumer key.
        :param token: The access token string.

        returns `docs.oauth1.object_interfaces.AccessToken()`
        """
        clientObject = self.client_getter(client_key=client_key)
        if not clientObject:
            raise ApiPermissionsError("Invalid Client")
        tokenObject = (
            self.pyramid_request.dbSession.query(Developer_oAuth1Server_TokenAccess)
            .filter(
                Developer_oAuth1Server_TokenAccess.developer_application_id
                == clientObject.id,
                Developer_oAuth1Server_TokenAccess.is_active.is_(True),
            )
            .first()
        )
        return tokenObject

    @catch_backend_failure
    def access_token_setter(self, token: Dict, request: "oAuth_Request"):
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
        if not request.verifier:
            raise ApiPermissionsError("Invalid Verifier (1)")
        verifierObject = self._get_TokenRequest_by_verifier(
            request.verifier, request=request
        )
        if not verifierObject:
            # we always have a verifier!
            raise ApiPermissionsError("Invalid Verifier (2)")

        # do we have an existing token?
        existingToken = (
            self.pyramid_request.dbSession.query(Developer_oAuth1Server_TokenAccess)
            .filter(
                Developer_oAuth1Server_TokenAccess.developer_application_id
                == verifierObject.developer_application_id,
                Developer_oAuth1Server_TokenAccess.useraccount_id
                == verifierObject.useraccount_id,
                Developer_oAuth1Server_TokenAccess.is_active.is_(True),
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
        tokenObject.timestamp_created = self.pyramid_request.timestamp
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
    def request_token_getter(
        self, token_str: str
    ) -> Optional[Developer_oAuth1Server_TokenRequest]:
        """
        :param token_str: The request token string.
        Note that the returned key must be in plaintext.

        returns `docs.oauth1.object_interfaces.RequestToken()`

        EXAMPLE ARGS:

            token = u'CdTQe0UY5P8qJspbhzSgDUUkG81laZ
        """
        tokenObject = self._get_TokenRequest_by_token(token_str)
        return tokenObject

    @catch_backend_failure
    def request_token_setter(
        self,
        token: Dict,
        request: "oAuth_Request",
    ) -> Literal[True]:
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
        tokenObject.timestamp_created = self.pyramid_request.timestamp
        tokenObject.timestamp_expires = (
            self.pyramid_request.timestamp + datetime.timedelta(seconds=100)
        )
        tokenObject._realms = " ".join(request.realms) if request.realms else ""
        tokenObject.redirect_uri = request.redirect_uri or ""
        tokenObject.oauth_token = token["oauth_token"]
        tokenObject.oauth_token_secret = token["oauth_token_secret"]
        tokenObject.oauth_callback_confirmed = token["oauth_callback_confirmed"]
        tokenObject.oauth_version = "1"
        tokenObject.is_active = True
        self.pyramid_request.dbSession.add(tokenObject)
        self.pyramid_request.dbSession.flush()
        return True

    @catch_backend_failure
    def request_token_invalidator(
        self, request: "oAuth_Request", client_key: str, request_token: str
    ) -> Literal[True]:
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
        client_key: str,
        timestamp: str,
        nonce: str,
        request: "oAuth_Request",
        request_token_str: Optional[str] = None,
        access_token_str: Optional[str] = None,
    ) -> bool:
        """A nonce and timestamp make each request unique.

        :param client_key: The client/consure key
        :param timestamp: The ``oauth_timestamp`` parameter
        :param nonce: The ``oauth_nonce`` parameter
        :param request_token_str: Request token string, if any
        :param access_token_str: Access token string, if any
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
        client_key: str,
        timestamp: str,
        nonce: str,
        request: "oAuth_Request",
        request_token_str: Optional[str] = None,
        access_token_str: Optional[str] = None,
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

        # convert
        datetime_created = datetime.datetime.fromtimestamp(
            int(timestamp), tz=datetime.timezone.utc
        )

        nonceObject = Developer_oAuth1Server_Nonce()
        nonceObject.nonce = nonce
        nonceObject.timestamp_created = datetime_created
        nonceObject.developer_application_id = request.client.id
        nonceObject.request_token = request_token_str
        nonceObject.access_token = access_token_str
        self.pyramid_request.dbSession.add(nonceObject)
        self.pyramid_request.dbSession.flush()

    #
    # verifier getter and setter
    #
    @catch_backend_failure
    def verifier_getter(
        self,
        verifier_str: str,
        token_str: str,
    ) -> Optional[Developer_oAuth1Server_TokenRequest]:
        """
        :param verifier_str A verifier string
        :param token_str: A request token string.

        returns `docs.oauth1.object_interfaces.RequestToken()`

        EXAMPLE ARGS:

            token = u'CdTQe0UY5P8qJspbhzSgDUUkG81laZ
            verifier = u'M01sY5eH9qqI8OblqQ0RLN4H6jPzSG'
        """
        verifierObject = self._get_TokenRequest_by_verifier(verifier_str)
        return verifierObject

    @catch_backend_failure
    def verifier_setter(
        self,
        token_str: str,
        verifier_dict: Dict,
        request: "oAuth_Request",
    ) -> Literal[True]:
        """
        :param token_str: A request token string.
        :param verifier_dict A dictionary implementing ``docs.oauth1.object_interfaces.VerifierDict`` (containing ``oauth_verifier`` and ``oauth_token``)
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
        tokenObject = self._get_TokenRequest_by_token(token_str, request=request)
        if not tokenObject:
            # we always have a tokenObject!
            raise ApiPermissionsError("Invalid Token")
        tokenObject.oauth_verifier = verifier_dict["oauth_verifier"]
        tokenObject.useraccount_id = self.pyramid_request.active_useraccount_id
        self.pyramid_request.dbSession.flush()
        return True


# ------------------------------------------------------------------------------


def get_ApiExampleAppData() -> Dict:
    app_data = {
        "client_key": OAUTH1__APP_KEY,
        "client_secret": OAUTH1__APP_SECRET,
        "callback_uri": OAUTH1__URL_APP_FLOW_REGISTER_CALLBACK,
        "scope": None,
        "id": OAUTH1__APP_ID,
    }
    return app_data


def new_oauth1Provider(pyramid_request: "Pyramid_Request") -> OAuth1Provider:
    """this is used to build a new auth"""
    validatorHooks = CustomValidator_Hooks(pyramid_request)
    provider = OAuth1Provider(
        pyramid_request,
        validator_api_hooks=validatorHooks,
        validator_class=CustomValidator,
    )
    return provider


def oauth_time_now():
    return str(int(time.time()))
