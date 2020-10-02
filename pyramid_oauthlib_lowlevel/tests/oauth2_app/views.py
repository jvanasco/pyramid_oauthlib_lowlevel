from __future__ import print_function
import logging

log = logging.getLogger(__name__)

"""
fake app for tests
"""

# stdlib
import os
import pdb
import logging
import datetime

# pyramid
from pyramid.renderers import render_to_response
from pyramid.view import view_config
from pyramid.csrf import get_csrf_token
from pyramid.httpexceptions import HTTPException
from pyramid.httpexceptions import HTTPSeeOther
from pyramid.httpexceptions import HTTPBadRequest
from pyramid.httpexceptions import HTTPForbidden
from pyramid.authentication import extract_http_basic_credentials

# local
from ..oauth2_model import USERID_ACTIVE__APPLICATION
from ..oauth2_model import USERID_ACTIVE__AUTHORITY
from ..oauth2_model import OAUTH2__APP_KEY
from ..oauth2_model import OAUTH2__APP_SECRET
from ..oauth2_model import Developer_OAuth2Server_BearerToken
from ..oauth2_model import Developer_OAuth2Client_BearerToken
from ..oauth2_utils import new_oauth2Provider
from ..oauth2_utils import new_oauth2ProviderLimited
from .. import oauth2_model
from .. import oauth2_utils

# pypi
from oauthlib.oauth2.rfc6749.errors import OAuth2Error
from oauthlib.oauth2.rfc6749.tokens import OAuth2Token
import pyramid_formencode_classic as formhandling
from formencode import Schema as form_Schema
from formencode.validators import UnicodeString as form_UnicodeString
from formencode.validators import OneOf as form_OneOf
from requests_oauthlib import OAuth2Session
import oauthlib

# ==============================================================================


# if True, will print some route/csrf data
# printing is easier than logging for debugging
# `export PYRAMID_OAUTHLIB_LOWLEVEL__DEBUG_ROUTE=1`
# `export PYRAMID_OAUTHLIB_LOWLEVEL__DEBUG_USERID=1`
# `export PYRAMID_OAUTHLIB_LOWLEVEL__LOG_ROUTE=1`
DEBUG_ROUTE = bool(int(os.getenv("PYRAMID_OAUTHLIB_LOWLEVEL__DEBUG_ROUTE", 0)))
DEBUG_USERID = bool(int(os.getenv("PYRAMID_OAUTHLIB_LOWLEVEL__DEBUG_USERID", 0)))
LOG_ROUTE = bool(int(os.getenv("PYRAMID_OAUTHLIB_LOWLEVEL__LOG_ROUTE", 0)))


# ==============================================================================


class Form_Oauth2Authorize(form_Schema):
    allow_extra_fields = True
    filter_extra_fields = True
    scope = form_UnicodeString(not_empty=True)
    client_id = form_UnicodeString(not_empty=True)
    redirect_uri = form_UnicodeString(not_empty=True)
    response_type = form_UnicodeString(not_empty=True)
    state = form_UnicodeString(not_empty=True)
    submit = form_OneOf(("authorize", "deny"))


class Handler(object):
    def __init__(self, request):
        self.request = request


class Shared(Handler):
    @view_config(route_name="whoami", renderer="string")
    def whoami(self):
        "This is used for writing tests"
        if DEBUG_ROUTE:
            print("whoami", get_csrf_token(self.request))
        if LOG_ROUTE:
            log.debug("whoami %s", get_csrf_token(self.request))
        if DEBUG_USERID:
            print("whoami", self.request.active_useraccount_id)
        return "%s" % (self.request.active_useraccount_id or "")


class Authority_User_AcccountViews(Handler):
    @view_config(route_name="authority:account:login-form", renderer="string")
    def account_login_form(self):
        if DEBUG_ROUTE:
            print("authority:account:login-form", get_csrf_token(self.request))
        if LOG_ROUTE:
            log.debug("authority:account:login-form %s", get_csrf_token(self.request))
        if self.request.active_useraccount_id:
            return HTTPSeeOther("/authority/account/home")
        return "authority|login-form"

    @view_config(route_name="authority:account:login-submit", renderer="string")
    def account_login_submit(self):
        if DEBUG_ROUTE:
            print("authority:account:login-submit", get_csrf_token(self.request))
        if LOG_ROUTE:
            log.debug("authority:account:login-submit %s", get_csrf_token(self.request))
        self.request.session["active_useraccount_id"] = USERID_ACTIVE__AUTHORITY
        return HTTPSeeOther("/authority/account/home")

    @view_config(route_name="authority:account:home", renderer="string")
    def account_home(self):
        if DEBUG_ROUTE:
            print("authority:account:home", get_csrf_token(self.request))
        if LOG_ROUTE:
            log.debug("authority:account:home %s", get_csrf_token(self.request))
        if not self.request.active_useraccount_id:
            return HTTPSeeOther("/authority/account/login-form")
        return "authority|home|user=%s" % self.request.active_useraccount_id

    @view_config(route_name="authority:account:logout", renderer="string")
    def account_logout(self):
        if DEBUG_ROUTE:
            print("authority:account:logout", get_csrf_token(self.request))
        if LOG_ROUTE:
            log.debug("authority:account:logout %s", get_csrf_token(self.request))
        if self.request.active_useraccount_id:
            self.request.session.invalidate()
        return HTTPSeeOther("/authority/account/login-form")


class Authority_Oauth2_FlowShared_API_Public(Handler):
    @view_config(route_name="authority:oauth2:protected_resource", renderer="string")
    def protected_resource(self):
        """the resource is protected behind an oauth2 token validation."""
        if DEBUG_ROUTE:
            print("authority:oauth2:protected_resource", get_csrf_token(self.request))
        if LOG_ROUTE:
            log.debug(
                "authority:oauth2:protected_resource %s", get_csrf_token(self.request)
            )

        oauth2Provider = new_oauth2Provider(self.request)
        scopes = ["platform.actor"]
        valid, req = oauth2Provider.verify_request(scopes)
        if not valid:
            raise HTTPForbidden()

        # dbTokens = self.request.dbSession.query(Developer_OAuth2Server_BearerToken).all()
        # pdb.set_trace()
        return "protected_resource"

    # - - - - - - - - - - - -

    @view_config(route_name="authority:oauth2:revoke_token", renderer="string")
    def oauth2_revoke_token(self):
        if DEBUG_ROUTE:
            print("authority:oauth2:revoke_token", get_csrf_token(self.request))
        if LOG_ROUTE:
            log.debug("authority:oauth2:revoke_token %s", get_csrf_token(self.request))
        try:
            oauth2Provider = new_oauth2Provider(self.request)
            rval = oauth2Provider.endpoint__revoke_token()
            return rval
        except HTTPException:
            raise
        except Exception as exc:
            # raise custom errors in production
            raise exc


class Authority_Oauth2_FlowA_API_Public(Handler):
    """And you'll need to allow logged in users to authenticate"""

    @view_config(route_name="authority:oauth2:flow_a:authorization", renderer="string")
    def authorization(self):
        if DEBUG_ROUTE:
            print("authority:oauth2:flow_a:authorization", get_csrf_token(self.request))
        if LOG_ROUTE:
            log.debug(
                "authority:oauth2:flow_a:authorization %s", get_csrf_token(self.request)
            )

        # the authorization MUST require a loggedin user
        if not self.request.active_useraccount_id:
            return HTTPSeeOther("/authority/account/login-form")

        try:
            # expecting in request.params.get
            #   * response_type=code
            #   * client_id=OAUTH2APPKEYOAUTH2APPKEYOAUTH2APPKEYOAUTH2APPKEY
            #   * redirect_uri=https%3A%2F%2Fexample.com%2Fapplication%2Fauthorized-callback
            #   * state=state=P5R1ihb7lvhDos4jHXzTGHK7sgVQv3

            # no matter what we do, we need to grab this data
            oauth2Provider = new_oauth2Provider(self.request)

            if self.request.method == "GET":

                # this is decorated by `catch_errors_and_unavailability` and will raise an `OAuth2Error`
                validity_dict = (
                    oauth2Provider.endpoint__validate_authorization_request()
                )
                self.request.workspace.oAuth2_ValidityDict = validity_dict

                return self._authorization__print()

            elif self.request.method == "POST":

                try:
                    (result, formStash) = formhandling.form_validate(
                        self.request,
                        schema=Form_Oauth2Authorize,
                        csrf_token=get_csrf_token(self.request),
                    )
                    if not result:
                        raise formhandling.FormInvalid()

                    if formStash.results["submit"] == "deny":
                        # process deny
                        raise HTTPSeeOther("/account/home")

                    # accept!
                    res = oauth2Provider.endpoint__confirm_authorization_request()
                    return res

                except (OAuth2Error, formhandling.FormInvalid) as exc:
                    if isinstance(exc, OAuth2Error):
                        self.request.workspace.oAuth2_Error = exc
                    return formhandling.form_reprint(
                        self.request, self._authorization__print
                    )

        except HTTPException:
            raise
        except Exception as exc:
            # raise custom errors in production
            raise exc

    def _authorization__print(self):
        """print the form"""
        return render_to_response(
            "pyramid_oauthlib_lowlevel:tests/oauth2_app/templates/authorize-form.mako",
            {},
            self.request,
        )

    # - - - - - - - - - - - -

    @view_config(route_name="authority:oauth2:flow_a:token", renderer="string")
    def token(self):
        """
        this is called in two contexts:
        1- a loggedin user is getting an access token for their client key/secret combo
        2- a client app is exchanging an authorization code for an access token
        """
        if DEBUG_ROUTE:
            print("authority:oauth2:token", get_csrf_token(self.request))
        if LOG_ROUTE:
            log.debug("authority:oauth2:token %s", get_csrf_token(self.request))
        try:
            user_id = self.request.active_useraccount_id
            if user_id is not None:
                credentials = dict(user_id=user_id)
            else:
                credentials = None

            oauth2Provider = new_oauth2Provider(self.request)
            rval = oauth2Provider.endopoint__token(credentials=credentials)
            return rval

        except HTTPException:
            raise
        except Exception as exc:
            # raise custom errors in production
            raise exc


class Authority_Oauth2_FlowB_API_Public(Handler):
    """"""

    @view_config(route_name="authority:oauth2:flow_b:obtain_token", renderer="string")
    def obtain_token(self):
        """this default version calculates the client credentials as needed"""
        if DEBUG_ROUTE:
            print("authority:oauth2:flow_b:obtain_token", get_csrf_token(self.request))
        if LOG_ROUTE:
            log.debug(
                "authority:oauth2:flow_b:obtain_token %s", get_csrf_token(self.request)
            )
        try:
            oauth2Provider = new_oauth2Provider(self.request)
            rval = oauth2Provider.endopoint__token(credentials=None)
            return rval
        except HTTPException:
            raise
        except Exception as exc:
            # raise custom errors in production
            raise exc

    @view_config(
        route_name="authority:oauth2:flow_b:obtain_token_alt", renderer="string"
    )
    def obtain_token_alt(self):
        """
        this alt version pre-calculates the client_credentials.

        1. 'grant_type' in request.POST, grant_type=='client_credentials'
        2. HTTP Basic Authorization contains
            username: client_id
            password: client_secret
        """
        if DEBUG_ROUTE:
            print(
                "authority:oauth2:flow_b:obtain_token_alt", get_csrf_token(self.request)
            )
        if LOG_ROUTE:
            log.debug(
                "authority:oauth2:flow_b:obtain_token_alt %s",
                get_csrf_token(self.request),
            )
        try:
            # turn this into a username/password
            # HTTPBasicCredentials(username=u'OAUTH2APPKEYOAUTH2APPKEYOAUTH2APPKEYOAUTH2APPKEY', password=u'OAUTH2__APP_SECRET')
            credentials = extract_http_basic_credentials(self.request)
            credentials = (
                {"username": credentials.username, "password": credentials.password}
                if credentials
                else {}
            )

            # logging.basicConfig()
            # _loggingOld = logging.getLogger().getEffectiveLevel()
            # logging.getLogger().setLevel(logging.DEBUG)

            oauth2Provider = new_oauth2Provider(self.request)
            rval = oauth2Provider.endopoint__token(credentials=credentials)
            return rval
        except HTTPException:
            raise
        except Exception as exc:
            # raise custom errors in production
            raise exc


class Authority_Oauth2_Flowc_API_Public(Handler):
    """
    no client_credentials
    """

    @view_config(route_name="authority:oauth2:flow_c:token_limited", renderer="string")
    def obtain_token(self):
        """this endpoint does not accept client_credentials"""
        if DEBUG_ROUTE:
            print("authority:oauth2:flow_c:token_limited", get_csrf_token(self.request))
        if LOG_ROUTE:
            log.debug(
                "authority:oauth2:flow_c:token_limited %s", get_csrf_token(self.request)
            )
        try:
            oauth2Provider = new_oauth2ProviderLimited(self.request)
            rval = oauth2Provider.endopoint__token()
            return rval
        except HTTPException:
            raise
        except Exception as exc:
            # raise custom errors in production
            raise exc


class ExampleApp_User_AccountViews(Handler):
    """
    these are shared across flows
    """

    @view_config(route_name="application:account:home", renderer="string")
    def account_home(self):
        if DEBUG_ROUTE:
            print("application:account:home", get_csrf_token(self.request))
        if LOG_ROUTE:
            log.debug("application:account:home %s", get_csrf_token(self.request))
        if DEBUG_USERID:
            print("application:account:home", self.request.active_useraccount_id)
        if not self.request.active_useraccount_id:
            return HTTPSeeOther("/application/account/login-form")
        return "application|home|user=%s" % self.request.active_useraccount_id

    @view_config(route_name="application:account:login-form", renderer="string")
    def account_login_form(self):
        if DEBUG_ROUTE:
            print("application:account:login-form", get_csrf_token(self.request))
        if LOG_ROUTE:
            log.debug("application:account:login-form %s", get_csrf_token(self.request))
        if DEBUG_USERID:
            print("application:account:login-form", self.request.active_useraccount_id)
        if self.request.active_useraccount_id:
            return HTTPSeeOther("/application/account/home")
        return "application|login-form"

    @view_config(route_name="application:account:login-submit", renderer="string")
    def account_login_submit(self):
        if DEBUG_ROUTE:
            print("application:account:login-submit", get_csrf_token(self.request))
        if LOG_ROUTE:
            log.debug(
                "application:account:login-submit %s", get_csrf_token(self.request)
            )
        if DEBUG_USERID:
            print(
                "application:account:login-submit", self.request.active_useraccount_id
            )
        self.request.session["active_useraccount_id"] = USERID_ACTIVE__APPLICATION
        return HTTPSeeOther("/application/account/home")

    @view_config(route_name="application:account:logout", renderer="string")
    def account_logout(self):
        if DEBUG_ROUTE:
            print("application:account:logout", get_csrf_token(self.request))
        if LOG_ROUTE:
            log.debug("application:account:logout %s", get_csrf_token(self.request))
        if DEBUG_USERID:
            print("application:account:logout", self.request.active_useraccount_id)
        if self.request.active_useraccount_id:
            self.request.session.invalidate()
        return HTTPSeeOther("/application/account/login-form")

    @view_config(
        route_name="application:account:fetch-protected-resource", renderer="string"
    )
    def fetch_protected_resource(self):
        """
        A user must log into ExampleApp and have an authorized token for the Authority system.

        This route will load the token and use it to make an oAuth2 request against the Authority system.
        """
        if DEBUG_ROUTE:
            print(
                "application:account:fetch-protected-resource",
                get_csrf_token(self.request),
            )
        if LOG_ROUTE:
            log.debug(
                "application:account:fetch-protected-resource %s",
                get_csrf_token(self.request),
            )
        if not self.request.active_useraccount_id:
            return HTTPSeeOther("/application/account/login-form")

        # what is our token?
        clientToken = (
            self.request.dbSession.query(Developer_OAuth2Client_BearerToken)
            .filter(
                Developer_OAuth2Client_BearerToken.useraccount_id
                == self.request.active_useraccount_id,
                Developer_OAuth2Client_BearerToken.original_grant_type
                == "authorization_code",
                Developer_OAuth2Client_BearerToken.is_active == True,  # noqa
            )
            .first()
        )
        if not clientToken:
            raise ValueError("no token for this user!")

        token_dict = {"access_token": clientToken.access_token, "token_type": "Bearer"}
        sess = OAuth2Session(client_id=OAUTH2__APP_KEY, token=token_dict)
        resp = sess.request(
            "GET", oauth2_utils.OAUTH2__URL_AUTHORITY_PROTECTED_RESOURCE
        )
        if resp.status_code != 200:
            raise ValueError("invalid")
        return resp.text

    @view_config(route_name="application:account:refresh-token", renderer="string")
    def refresh_token(self):
        """
        refresh the User's token from the server
        """
        if DEBUG_ROUTE:
            print("application:account:refresh-token", get_csrf_token(self.request))
        if LOG_ROUTE:
            log.debug(
                "application:account:refresh-token %s", get_csrf_token(self.request)
            )
        if not self.request.active_useraccount_id:
            return HTTPSeeOther("/application/account/login-form")
        if self.request.active_useraccount_id != USERID_ACTIVE__APPLICATION:
            raise ValueError("not the expected user!")

        # logging.basicConfig()
        # logging.getLogger().setLevel(logging.DEBUG)

        # what is our token?
        clientToken = (
            self.request.dbSession.query(Developer_OAuth2Client_BearerToken)
            .filter(
                Developer_OAuth2Client_BearerToken.useraccount_id
                == USERID_ACTIVE__APPLICATION,
                Developer_OAuth2Client_BearerToken.original_grant_type
                == "authorization_code",
                Developer_OAuth2Client_BearerToken.is_active == True,  # noqa
            )
            .first()
        )
        if not clientToken:
            raise ValueError("no token for this user!")

        # grab this data to send upstream
        token_dict = {
            "access_token": clientToken.access_token,
            "token_type": "Bearer",
            "refresh_token": clientToken.refresh_token,
        }

        # sending the client auth params is not required by spec, but is required by oauthlib2
        extra = {"client_id": OAUTH2__APP_KEY, "client_secret": OAUTH2__APP_SECRET}
        sess = OAuth2Session(client_id=OAUTH2__APP_KEY, token=token_dict)
        newToken_dict = sess.refresh_token(
            oauth2_utils.OAUTH2__URL_AUTHORITY_FLOWA_TOKEN, **extra
        )
        if not isinstance(newToken_dict, OAuth2Token):
            raise ValueError("did not load an `OAuth2Token``")

        newToken_db = Developer_OAuth2Client_BearerToken()
        newToken_db.useraccount_id = self.request.active_useraccount_id
        newToken_db.access_token = newToken_dict["access_token"]
        newToken_db.refresh_token = newToken_dict["refresh_token"]
        newToken_db.scope = " ".join(newToken_dict["scope"])
        newToken_db.timestamp_created = self.request.datetime
        newToken_db.timestamp_expires = (
            newToken_db.timestamp_created
            + datetime.timedelta(seconds=newToken_dict["expires_in"])
        )  # or use newToken_dict['expires_at]
        newToken_db.grant_type = "refresh_token"
        newToken_db.original_grant_type = "authorization_code"
        self.request.dbSession.add(newToken_db)
        self.request.dbSession.flush()

        # mark this as inactive since we have a new one
        clientToken.is_active = False
        self.request.dbSession.flush()

        # we don't recycle the refresh_token; we renew it
        assert clientToken.access_token != newToken_db.access_token
        assert clientToken.refresh_token != newToken_db.refresh_token

        # so let's just check to ensure we have the right number of active tokens (Client)
        _clientTokens = (
            self.request.dbSession.query(Developer_OAuth2Client_BearerToken)
            .filter(
                Developer_OAuth2Client_BearerToken.useraccount_id
                == USERID_ACTIVE__APPLICATION,
                Developer_OAuth2Client_BearerToken.original_grant_type
                == "authorization_code",
                Developer_OAuth2Client_BearerToken.is_active == True,  # noqa
            )
            .all()
        )
        assert len(_clientTokens) == 1

        # so let's just check to ensure we have the right number of active tokens (Server)
        _serverTokens = (
            self.request.dbSession.query(Developer_OAuth2Server_BearerToken)
            .filter(
                Developer_OAuth2Server_BearerToken.useraccount_id
                == USERID_ACTIVE__AUTHORITY,
                Developer_OAuth2Server_BearerToken.original_grant_type
                == "authorization_code",
                Developer_OAuth2Server_BearerToken.is_active == True,  # noqa
            )
            .all()
        )
        assert len(_serverTokens) == 1

        # we could return here, but let's try another method to ensure our tests
        # work correctly on the other method of token rotation...
        # return 'refreshed_token'

        # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
        # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

        # monkeypatch this to try an alternate method
        oauth2_utils.CustomValidator.rotate_refresh_token = (
            oauth2_utils.CustomValidator._rotate_refresh_token__False
        )

        # grab this data to send upstream
        token_dict = {
            "access_token": newToken_db.access_token,
            "token_type": "Bearer",
            "refresh_token": newToken_db.refresh_token,
        }

        # sending the client auth params is not required by spec, but is required by oauthlib2
        extra = {"client_id": OAUTH2__APP_KEY, "client_secret": OAUTH2__APP_SECRET}
        sess = OAuth2Session(client_id=OAUTH2__APP_KEY, token=token_dict)
        newToken_dict2 = sess.refresh_token(
            oauth2_utils.OAUTH2__URL_AUTHORITY_FLOWA_TOKEN, **extra
        )
        if not isinstance(newToken_dict, OAuth2Token):
            raise ValueError("did not load an `OAuth2Token``")

        newToken_db2 = Developer_OAuth2Client_BearerToken()
        newToken_db2.useraccount_id = self.request.active_useraccount_id
        newToken_db2.access_token = newToken_dict2["access_token"]
        newToken_db2.refresh_token = newToken_dict2["refresh_token"]
        newToken_db2.scope = " ".join(newToken_dict2["scope"])
        newToken_db2.grant_type = "refresh_token"
        newToken_db2.original_grant_type = "authorization_code"
        newToken_db2.timestamp_created = self.request.datetime
        newToken_db2.timestamp_expires = (
            newToken_db.timestamp_created
            + datetime.timedelta(seconds=newToken_dict2["expires_in"])
        )  # or use newToken_dict['expires_at]
        self.request.dbSession.add(newToken_db2)
        self.request.dbSession.flush()

        # mark this as inactive since we have a new one
        newToken_db2.is_active = False
        self.request.dbSession.flush()

        # we don't recycle the refresh_token; we renew it
        assert newToken_db.access_token != newToken_db2.access_token
        assert newToken_db.refresh_token == newToken_db2.refresh_token

        # so let's just check to ensure we have the right number of active tokens (Client)
        _clientTokens = (
            self.request.dbSession.query(Developer_OAuth2Client_BearerToken)
            .filter(
                Developer_OAuth2Client_BearerToken.useraccount_id
                == self.request.active_useraccount_id,
                Developer_OAuth2Client_BearerToken.original_grant_type
                == "authorization_code",
                Developer_OAuth2Client_BearerToken.is_active == True,  # noqa
            )
            .all()
        )
        assert len(_clientTokens) == 1

        # so let's just check to ensure we have the right number of active tokens (Server)
        _serverTokens = (
            self.request.dbSession.query(Developer_OAuth2Server_BearerToken)
            .filter(
                Developer_OAuth2Server_BearerToken.useraccount_id
                == USERID_ACTIVE__AUTHORITY,
                Developer_OAuth2Server_BearerToken.original_grant_type
                == "authorization_code",
                Developer_OAuth2Server_BearerToken.is_active == True,  # noqa
            )
            .all()
        )
        assert len(_serverTokens) == 1

        # reset the monkeypatch
        oauth2_utils.CustomValidator.rotate_refresh_token = (
            oauth2_utils.CustomValidator._rotate_refresh_token__True
        )

        return "refreshed_token"

    @view_config(route_name="application:account:revoke-token", renderer="string")
    def revoke_token(self):
        """
        revoke the User's token on the server
        """
        if DEBUG_ROUTE:
            print("application:account:revoke-token", get_csrf_token(self.request))
        if LOG_ROUTE:
            log.debug(
                "application:account:revoke-token %s", get_csrf_token(self.request)
            )
        if not self.request.active_useraccount_id:
            return HTTPSeeOther("/application/account/login-form")
        if self.request.active_useraccount_id != USERID_ACTIVE__APPLICATION:
            raise ValueError("not the expected user!")

        # what is our token?
        clientToken = (
            self.request.dbSession.query(Developer_OAuth2Client_BearerToken)
            .filter(
                Developer_OAuth2Client_BearerToken.useraccount_id
                == USERID_ACTIVE__APPLICATION,
                Developer_OAuth2Client_BearerToken.original_grant_type
                == "authorization_code",
                Developer_OAuth2Client_BearerToken.is_active == True,  # noqa
            )
            .first()
        )
        if not clientToken:
            raise ValueError("no token for this user!")

        apiClient = oauth2_utils.CustomApiClientB(
            app_key=oauth2_model.OAUTH2__APP_KEY,
            app_secret=oauth2_model.OAUTH2__APP_SECRET,
            oauth_version=2,
        )
        token_result = apiClient.revoke_access_token(token=clientToken.access_token)
        assert token_result is True

        clientToken.timestamp_revoked = self.request.datetime
        clientToken.is_active = False
        self.request.dbSession.flush()

        # just make sure it's marked as inactive on the server...
        _serverToken = (
            self.request.dbSession.query(Developer_OAuth2Server_BearerToken)
            .filter(
                Developer_OAuth2Server_BearerToken.useraccount_id
                == USERID_ACTIVE__AUTHORITY,
                Developer_OAuth2Server_BearerToken.original_grant_type
                == "authorization_code",
                Developer_OAuth2Server_BearerToken.is_active == False,  # noqa
                Developer_OAuth2Server_BearerToken.access_token
                == clientToken.access_token,
            )
            .first()
        )
        assert _serverToken is not None

        return "revoked_token"


class ExampleApp_FlowRegister(Handler):
    @view_config(route_name="application:flow-register", renderer="string")
    def register(self):
        if DEBUG_ROUTE:
            print("application:flow-register", get_csrf_token(self.request))
        if LOG_ROUTE:
            log.debug("application:flow-register %s", get_csrf_token(self.request))
        if DEBUG_USERID:
            print("application:flow-register", self.request.active_useraccount_id)
        if self.request.active_useraccount_id:
            return HTTPSeeOther("/application/account/home")
        return HTTPSeeOther("/application/flow-register/oauth2/start")

    @view_config(route_name="application:flow-register:oauth2:start", renderer="string")
    def oauth2_start(self):
        if DEBUG_ROUTE:
            print(
                "application:flow-register:oauth2:start", get_csrf_token(self.request)
            )
        if LOG_ROUTE:
            log.debug(
                "application:flow-register:oauth2:start %s",
                get_csrf_token(self.request),
            )
        if DEBUG_USERID:
            print(
                "application:account:oauth2:start", self.request.active_useraccount_id
            )

        if self.request.active_useraccount_id:
            return HTTPSeeOther("/application/account/home")

        authClient = OAuth2Session(
            OAUTH2__APP_KEY,
            redirect_uri=oauth2_utils.OAUTH2__URL_APP_FLOW_REGISTER_CALLBACK,
        )

        # Redirect user to the App for authorization
        authorization_url, state = authClient.authorization_url(
            oauth2_utils.OAUTH2__URL_AUTHORITY_FLOWA_AUTHORIZATION
        )

        return HTTPSeeOther(authorization_url)

    @view_config(
        route_name="application:flow-register:oauth2:authorized-callback",
        renderer="string",
    )
    def authorized_callback(self):
        if DEBUG_ROUTE:
            print(
                "application:flow-register:oauth2:authorized-callback",
                get_csrf_token(self.request),
            )
        if LOG_ROUTE:
            log.debug(
                "application:flow-register:oauth2:authorized-callback %s",
                get_csrf_token(self.request),
            )

        # we don't have a UID here because we haven't had an account created yet!
        if self.request.active_useraccount_id:
            return HTTPSeeOther("/application/account/home")

        _state = self.request.params.get("state")
        _code = self.request.params.get("code")

        # logging.basicConfig()
        # logging.getLogger().setLevel(logging.DEBUG)

        # we need to include the `redirect_uri` in the token fetch.
        try:
            sess = OAuth2Session(
                client_id=OAUTH2__APP_KEY,
                state=_state,
                redirect_uri=oauth2_utils.OAUTH2__URL_APP_FLOW_REGISTER_CALLBACK,
            )
            resp = sess.fetch_token(
                oauth2_utils.OAUTH2__URL_AUTHORITY_FLOWA_TOKEN,
                client_id=OAUTH2__APP_KEY,
                client_secret=OAUTH2__APP_SECRET,
                authorization_response=self.request.current_route_url(),
            )
            if not isinstance(resp, OAuth2Token):
                raise ValueError("did not load an `OAuth2Token``")

            # wow ok, we have successfully authorized, so...
            # log them in as a new user!
            # do this first, because the `Developer_oAuth1Server_TokenClient` requires a
            self.request.session["active_useraccount_id"] = USERID_ACTIVE__APPLICATION

            clientToken = Developer_OAuth2Client_BearerToken()
            clientToken.useraccount_id = self.request.active_useraccount_id
            clientToken.access_token = resp["access_token"]
            clientToken.refresh_token = resp["refresh_token"]
            clientToken.scope = " ".join(resp["scope"])
            clientToken.grant_type = "authorization_code"
            clientToken.original_grant_type = "authorization_code"
            clientToken.timestamp_created = self.request.datetime
            clientToken.timestamp_expires = (
                clientToken.timestamp_created
                + datetime.timedelta(seconds=resp["expires_in"])
            )
            self.request.dbSession.add(clientToken)
            self.request.dbSession.flush()

            return HTTPSeeOther(
                location="/application/flow-register/authorized-callback-success"
            )

        except:
            raise

    @view_config(
        route_name="application:flow-register:oauth2:authorized-callback-success",
        renderer="string",
    )
    def authorized_callback_success(self):
        if DEBUG_ROUTE:
            print(
                "application:flow-register:oauth2:authorized-callback-success",
                get_csrf_token(self.request),
            )
        if LOG_ROUTE:
            log.debug(
                "application:flow-register:oauth2:authorized-callback-success %s",
                get_csrf_token(self.request),
            )
        if not self.request.active_useraccount_id:
            return HTTPSeeOther("/application/account/login-form")
        return (
            "example_app|authorized-callback-success|user=%s"
            % self.request.active_useraccount_id
        )
