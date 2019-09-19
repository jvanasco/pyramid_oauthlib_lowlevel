# stdlib
import pdb
import datetime

# pypi
import sqlalchemy
import sqlalchemy.orm
from oauthlib.oauth2 import Server
from oauthlib.oauth2 import WebApplicationServer


# local module
from pyramid_oauthlib_lowlevel.oauth2.validator import OAuth2RequestValidator_Hooks
from pyramid_oauthlib_lowlevel.oauth2.validator import OAuth2RequestValidator
from pyramid_oauthlib_lowlevel.oauth2 import provider as oauth2_provider
from pyramid_oauthlib_lowlevel.utils import catch_backend_failure
from pyramid_oauthlib_lowlevel.client.api_client import ApiClient

# local tests
from .oauth2_model import DeveloperApplication
from .oauth2_model import DeveloperApplication_Keyset
from .oauth2_model import Developer_OAuth2Server_BearerToken
from .oauth2_model import Developer_OAuth2Server_GrantToken
from .oauth2_model import OAUTH2__APP_ID
from .oauth2_model import OAUTH2__APP_KEY
from .oauth2_model import OAUTH2__APP_SECRET
from .oauth2_model import OAUTH2__URL_APP_FLOW_REGISTER_CALLBACK
from .oauth2_model import OAUTH2__URL_AUTHORITY_FLOWA_AUTHORIZATION
from .oauth2_model import OAUTH2__URL_AUTHORITY_FLOWA_TOKEN
from .oauth2_model import OAUTH2__URL_AUTHORITY_REVOKE_TOKEN
from .oauth2_model import OAUTH2__URL_AUTHORITY_FLOWB_TOKEN
from .oauth2_model import OAUTH2__URL_AUTHORITY_FLOWB_TOKEN_ALT
from .oauth2_model import OAUTH2__URL_AUTHORITY_FLOWC_TOKEN_LIMITED
from .oauth2_model import OAUTH2__URL_AUTHORITY_PROTECTED_RESOURCE
from .oauth2_model import OAUTH2__URL_APP_FETCH_PROTECTED_RESOURCE


# ==============================================================================


class CustomApiClient(ApiClient):
    _user_agent = "CustomApiClient v0"
    oauth_version = 2
    _url_authorization = OAUTH2__URL_AUTHORITY_FLOWA_AUTHORIZATION
    _url_callback = OAUTH2__URL_APP_FLOW_REGISTER_CALLBACK
    _url_obtain_token = OAUTH2__URL_AUTHORITY_FLOWA_TOKEN


class CustomApiClientB(ApiClient):
    _user_agent = "CustomApiClientB v0"
    oauth_version = 2
    _url_authorization = OAUTH2__URL_AUTHORITY_FLOWA_AUTHORIZATION
    _url_callback = redirect_uri = OAUTH2__URL_APP_FLOW_REGISTER_CALLBACK
    _url_obtain_token = OAUTH2__URL_AUTHORITY_FLOWB_TOKEN
    _url_obtain_token_alt = OAUTH2__URL_AUTHORITY_FLOWB_TOKEN_ALT
    _url_revoke_token = OAUTH2__URL_AUTHORITY_REVOKE_TOKEN
    _url_token_limited = OAUTH2__URL_AUTHORITY_FLOWC_TOKEN_LIMITED


class CustomValidator(OAuth2RequestValidator):
    def _rotate_refresh_token__True(self, request):
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

    def _rotate_refresh_token__False(self, request):
        return False


class CustomValidator_Hooks(OAuth2RequestValidator_Hooks):

    #
    # client getter
    #
    @catch_backend_failure
    def client_getter(self, client_id=None):
        """Retreive a valid client

        :param client_id: Unicode client identifier

        returns `docs.oauth2.object_interfaces.Client()`

        EXAMPLE ARGS:

            client_id = u'12312341'
        """
        if not client_id:
            return None
        clientObject = (
            self.pyramid_request.dbSession.query(DeveloperApplication)
            .join(
                DeveloperApplication_Keyset,
                DeveloperApplication.id
                == DeveloperApplication_Keyset.developer_application_id,
            )
            .filter(
                DeveloperApplication_Keyset.client_id == client_id,
                DeveloperApplication_Keyset.is_active == True,  # noqa
            )
            .options(sqlalchemy.orm.contains_eager("app_keyset_active"))
            .first()
        )
        # if not clientObject:
        #    raise oauthlib_oauth1_errors.InvalidClientError("Invalid Client")
        # if not clientObject:
        #    print "MISSING client"
        #    pdb.set_trace()
        return clientObject

    #
    # grant getter and setter | oAuth1 = request_token_(getter|setter)
    #
    def grant_setter(self, client_id, code, request, *args, **kwargs):
        """
        A function to save the grant code.

        :param client_id: Unicode client identifier
        :param code: A dict of the authorization code grant and, optionally, state.
        :param request: The HTTP Request (oauthlib.common.Request)

        def set_grant(client_id, code, request, *args, **kwargs):
            save_grant(client_id, code, request.user, request.scopes)
        """
        if not self.pyramid_request.active_useraccount_id:
            raise ValueError("The `user` MUST be logged in")

        grantObject = Developer_OAuth2Server_GrantToken()
        grantObject.useraccount_id = self.pyramid_request.active_useraccount_id
        grantObject.developer_application_id = request.client.id
        grantObject.scope = (
            request.scope
        )  # `Developer_OAuth2Server_GrantToken.scope` is TEXT field as is `request.scope`; `.scopes` are lists
        grantObject.timestamp_created = self.pyramid_request.datetime
        grantObject.is_active = True
        grantObject.redirect_uri = request.redirect_uri
        grantObject.code = code.get("code")  # this is a dict with code|state
        grantObject.timestamp_expires = (
            grantObject.timestamp_created + datetime.timedelta(minutes=10)
        )
        self.pyramid_request.dbSession.add(grantObject)
        self.pyramid_request.dbSession.flush()

        return True

    def grant_getter(self, client_id, code, *args, **kwargs):
        """
        A method to load a grant.

        :param client_id: Unicode client identifier
        :param code: Unicode authorization_code
        """
        grantObject = (
            self.pyramid_request.dbSession.query(Developer_OAuth2Server_GrantToken)
            .join(
                DeveloperApplication,
                Developer_OAuth2Server_GrantToken.developer_application_id
                == DeveloperApplication.id,
            )
            .join(
                DeveloperApplication_Keyset,
                DeveloperApplication.id
                == DeveloperApplication_Keyset.developer_application_id,
            )
            .filter(
                Developer_OAuth2Server_GrantToken.code == code,
                Developer_OAuth2Server_GrantToken.is_active == True,  # noqa
                DeveloperApplication_Keyset.client_id == client_id,
            )
            .options(
                sqlalchemy.orm.contains_eager("developer_application"),
                sqlalchemy.orm.contains_eager(
                    "developer_application.app_keyset_active"
                ),
            )
            .first()
        )
        if not grantObject:
            return None
        return grantObject

    def grant_invalidate(self, grantObject):
        """
        This method expects a `grantObject` as a single argument.
        The grant should be deleted or otherwise marked as revoked.

        :param grantObject: The grant object loaded by ``grant_getter```
        """
        grantObject.is_active = False
        self.pyramid_request.dbSession.flush()

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
        """
        # what is the context of the token?
        user_id = None
        original_grant_type = None
        if request.grant_type == "client_credentials":
            user_id = request.client.user.id
            original_grant_type = request.grant_type
        elif request.grant_type == "authorization_code":
            user_id = request.user.id
            original_grant_type = request.grant_type
        elif request.grant_type == "refresh_token":
            refreshTok = self.token_getter(refresh_token=request.refresh_token)
            if not refreshTok:
                raise ValueError("could not load refresh token")
            user_id = refreshTok.useraccount_id
            original_grant_type = refreshTok.original_grant_type
        else:
            raise ValueError("what?!? %s" % request.grant_type)

        # first, we want to EXPIRE all other bearer tokens for this user
        # this is not required by spec, but is optional
        # TODO: expire the ones that are active but have not hit an expiry date
        liveTokens = (
            self.pyramid_request.dbSession.query(Developer_OAuth2Server_BearerToken)
            .filter(
                Developer_OAuth2Server_BearerToken.developer_application_id
                == request.client.id,
                Developer_OAuth2Server_BearerToken.useraccount_id == user_id,
                Developer_OAuth2Server_BearerToken.is_active == True,  # noqa
                Developer_OAuth2Server_BearerToken.original_grant_type
                == original_grant_type,
            )
            .all()
        )
        if liveTokens:
            # note that _token, this way we don't overwrite the `token` dict
            for _token in liveTokens:
                _token.is_active = False
            self.pyramid_request.dbSession.flush()

        timestamp_expiry = self.pyramid_request.datetime + datetime.timedelta(
            seconds=token.get("expires_in")
        )

        bearerToken = Developer_OAuth2Server_BearerToken()
        bearerToken.developer_application_id = request.client.id
        bearerToken.useraccount_id = user_id
        bearerToken.timestamp_created = self.pyramid_request.datetime
        bearerToken.is_active = True
        bearerToken.access_token = token["access_token"]
        bearerToken.refresh_token = token.get("refresh_token", None)
        bearerToken.token_type = "Bearer"  # token['token_type']
        bearerToken.timestamp_expires = timestamp_expiry
        bearerToken.grant_type = request.grant_type
        bearerToken.original_grant_type = original_grant_type
        bearerToken.scope = token["scope"]  # this will be a space separated string

        self.pyramid_request.dbSession.add(bearerToken)
        self.pyramid_request.dbSession.flush()

        return bearerToken

    def token_getter(self, access_token=None, refresh_token=None):
        """
        The function accepts an `access_token` or `refresh_token` parameters,
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
        if all((access_token, refresh_token)) or not any((access_token, refresh_token)):
            raise ValueError("Submit `access_token` or `refresh_token`, not both.")

        if access_token:
            bearerToken = (
                self.pyramid_request.dbSession.query(Developer_OAuth2Server_BearerToken)
                .filter(
                    Developer_OAuth2Server_BearerToken.access_token == access_token,
                    Developer_OAuth2Server_BearerToken.token_type == "Bearer",
                    Developer_OAuth2Server_BearerToken.is_active == True,  # noqa
                )
                .options(
                    sqlalchemy.orm.joinedload("developer_application"),
                    sqlalchemy.orm.joinedload(
                        "developer_application.app_keyset_active"
                    ),
                )
                .first()
            )
            return bearerToken

        elif refresh_token:
            bearerToken = (
                self.pyramid_request.dbSession.query(Developer_OAuth2Server_BearerToken)
                .filter(
                    Developer_OAuth2Server_BearerToken.refresh_token == refresh_token,
                    Developer_OAuth2Server_BearerToken.token_type == "Bearer",
                    Developer_OAuth2Server_BearerToken.is_active == True,  # noqa
                )
                .options(
                    sqlalchemy.orm.joinedload("developer_application"),
                    sqlalchemy.orm.joinedload(
                        "developer_application.app_keyset_active"
                    ),
                )
                .first()
            )
            return bearerToken
        raise ValueError("foo")

    def token_revoke(self, tokenObject):
        """
        This method expects a `tokenObject` as a single argument.
        The token should be deleted or otherwise marked as revoked.

        :param tokenObject: The grant object loaded by ``token_getter```
        """
        tokenObject.is_active = False
        tokenObject.timestamp_revoked = self.pyramid_request.datetime
        self.pyramid_request.dbSession.flush()


# ==============================================================================


def new_oauth2Provider(pyramid_request):
    """this is used to build a new auth"""
    validatorHooks = CustomValidator_Hooks(pyramid_request)
    provider = oauth2_provider.OAuth2Provider(
        pyramid_request,
        validator_api_hooks=validatorHooks,
        validator_class=CustomValidator,
    )
    return provider


def new_oauth2ProviderLimited(pyramid_request):
    """this is used to build a new auth"""
    validatorHooks = CustomValidator_Hooks(pyramid_request)
    provider = oauth2_provider.OAuth2Provider(
        pyramid_request,
        validator_api_hooks=validatorHooks,
        validator_class=CustomValidator,
        server_class=WebApplicationServer,
    )
    return provider
