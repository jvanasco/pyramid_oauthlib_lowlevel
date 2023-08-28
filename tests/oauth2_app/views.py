"""
fake app for tests
"""

# stdlib
import datetime
import logging
import os

# pyramid
from formencode import Schema as form_Schema
from formencode.validators import OneOf as form_OneOf
from formencode.validators import UnicodeString as form_UnicodeString
from oauthlib.oauth2.rfc6749.errors import OAuth2Error
from oauthlib.oauth2.rfc6749.tokens import OAuth2Token
from pyramid.authentication import extract_http_basic_credentials
from pyramid.csrf import get_csrf_token
from pyramid.httpexceptions import HTTPException
from pyramid.httpexceptions import HTTPForbidden
from pyramid.httpexceptions import HTTPSeeOther
from pyramid.renderers import render_to_response
from pyramid.view import view_config
import pyramid_formencode_classic as formhandling
from requests_oauthlib import OAuth2Session

# local
from .. import oauth2_model
from .. import oauth2_utils
from ..oauth2_model import Developer_OAuth2Client_BearerToken
from ..oauth2_model import Developer_OAuth2Server_BearerToken
from ..oauth2_model import OAUTH2__APP_KEY
from ..oauth2_model import OAUTH2__APP_SECRET
from ..oauth2_model import USERID_ACTIVE__APPLICATION
from ..oauth2_model import USERID_ACTIVE__AUTHORITY
from ..oauth2_utils import new_oauth2Provider
from ..oauth2_utils import new_oauth2ProviderLimited

# ==============================================================================

log = logging.getLogger(__name__)

# ==============================================================================


# if True, will print some route/csrf data
# printing is easier than logging for debugging
# `export PYRAMID_OAUTHLIB_LOWLEVEL__DEBUG_ROUTE=1`
# `export PYRAMID_OAUTHLIB_LOWLEVEL__DEBUG_USERID=1`
# `export PYRAMID_OAUTHLIB_LOWLEVEL__DEBUG_LOGIC=1`
# `export PYRAMID_OAUTHLIB_LOWLEVEL__LOG_ROUTE=1`
DEBUG_ROUTE = bool(int(os.getenv("PYRAMID_OAUTHLIB_LOWLEVEL__DEBUG_ROUTE", 0)))
DEBUG_USERID = bool(int(os.getenv("PYRAMID_OAUTHLIB_LOWLEVEL__DEBUG_USERID", 0)))
DEBUG_LOGIC = bool(int(os.getenv("PYRAMID_OAUTHLIB_LOWLEVEL__DEBUG_LOGIC", 0)))
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
        """pylons style request handling"""
        # set the request attribute
        self.request = request
        # log debug information if needed
        if DEBUG_ROUTE or LOG_ROUTE or DEBUG_USERID:
            print(") === Pyramid Request ===")
            _route = request.matched_route.name
            if DEBUG_ROUTE or LOG_ROUTE:
                _msg = "  )  Pyramid: %s CSRF[%s]" % (_route, get_csrf_token(request))
                if DEBUG_ROUTE:
                    print(_msg)
                if LOG_ROUTE:
                    log.debug(_msg)
            if DEBUG_USERID:
                _msg = "  )  Pyramid: %s active_useraccount_id[%s]" % (
                    _route,
                    request.active_useraccount_id,
                )


class Shared(Handler):
    @view_config(route_name="whoami", renderer="string")
    def whoami(self):
        "This is used for writing tests"
        return "%s" % (self.request.active_useraccount_id or "")


class Authority_User_AcccountViews(Handler):
    @view_config(route_name="authority:account:login-form", renderer="string")
    def account_login_form(self):
        if self.request.active_useraccount_id:
            return HTTPSeeOther("/authority/account/home")
        return "authority|login-form"

    @view_config(route_name="authority:account:login-submit", renderer="string")
    def account_login_submit(self):
        self.request.session["active_useraccount_id"] = USERID_ACTIVE__AUTHORITY
        return HTTPSeeOther("/authority/account/home")

    @view_config(route_name="authority:account:home", renderer="string")
    def account_home(self):
        if not self.request.active_useraccount_id:
            return HTTPSeeOther("/authority/account/login-form")
        return "authority|home|user=%s" % self.request.active_useraccount_id

    @view_config(route_name="authority:account:logout", renderer="string")
    def account_logout(self):
        if self.request.active_useraccount_id:
            self.request.session.invalidate()
        return HTTPSeeOther("/authority/account/login-form")


class Authority_Oauth2_FlowShared_API_Public(Handler):
    @view_config(route_name="authority:oauth2:protected_resource", renderer="string")
    def protected_resource(self):
        """the resource is protected behind an oauth2 token validation."""
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
        if DEBUG_LOGIC:
            print(")  request.params:", self.request.params)
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
            "templates/authorize-form.mako",
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
        if DEBUG_LOGIC:
            print(") ExampleApp_User_AccountViews.account_home")
        if not self.request.active_useraccount_id:
            return HTTPSeeOther("/application/account/login-form")
        return "application|home|user=%s" % self.request.active_useraccount_id

    @view_config(route_name="application:account:login-form", renderer="string")
    def account_login_form(self):
        if DEBUG_LOGIC:
            print(") ExampleApp_User_AccountViews.account_login_form")
        if self.request.active_useraccount_id:
            return HTTPSeeOther("/application/account/home")
        return "application|login-form"

    @view_config(route_name="application:account:login-submit", renderer="string")
    def account_login_submit(self):
        if DEBUG_LOGIC:
            print(") ExampleApp_User_AccountViews.account_login_submit")
        self.request.session["active_useraccount_id"] = USERID_ACTIVE__APPLICATION
        return HTTPSeeOther("/application/account/home")

    @view_config(route_name="application:account:logout", renderer="string")
    def account_logout(self):
        if DEBUG_LOGIC:
            print(") ExampleApp_User_AccountViews.account_logout")
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
        if DEBUG_LOGIC:
            print(") ExampleApp_User_AccountViews.fetch_protected_resource")
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
                Developer_OAuth2Client_BearerToken.is_active.is_(True),
            )
            .first()
        )
        if not clientToken:
            raise ValueError("no token for this user!")

        token_dict = {"access_token": clientToken.access_token, "token_type": "Bearer"}
        sess = OAuth2Session(client_id=OAUTH2__APP_KEY, token=token_dict)
        resp = sess.request(
            "GET", oauth2_model.OAUTH2__URL_AUTHORITY_PROTECTED_RESOURCE
        )
        if resp.status_code != 200:
            raise ValueError("invalid")
        return resp.text

    @view_config(
        route_name="application:account:refresh-token-recycle", renderer="string"
    )
    def refresh_token_recycle(self):
        """
        refresh the User's token from the server
        """
        if DEBUG_LOGIC:
            print(") ExampleApp_User_AccountViews.refresh_token_recycle")
        if not self.request.active_useraccount_id:
            return HTTPSeeOther("/application/account/login-form")
        if self.request.active_useraccount_id != USERID_ACTIVE__APPLICATION:
            raise ValueError("not the expected user!")

        assert (
            oauth2_utils.CustomValidator.rotate_refresh_token
            == oauth2_utils.CustomValidator._rotate_refresh_token__True
        )
        # monkeypatch us into recycle mode
        oauth2_utils.CustomValidator.rotate_refresh_token = (
            oauth2_utils.CustomValidator._rotate_refresh_token__False
        )
        assert (
            oauth2_utils.CustomValidator.rotate_refresh_token
            == oauth2_utils.CustomValidator._rotate_refresh_token__False
        )

        # what is our token?
        # load from the `Developer_OAuth2Client_` table
        clientToken = (
            self.request.dbSession.query(Developer_OAuth2Client_BearerToken)
            .filter(
                Developer_OAuth2Client_BearerToken.useraccount_id
                == USERID_ACTIVE__APPLICATION,
                Developer_OAuth2Client_BearerToken.original_grant_type
                == "authorization_code",
                Developer_OAuth2Client_BearerToken.is_active.is_(True),
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

        if DEBUG_LOGIC:
            print(") ------")
            print("  )  refresh_token_recycle")
            print("  )  token - original:", token_dict)
            print("  )  token - new     :", newToken_dict)

        # save to the `Developer_OAuth2Client_` table
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

        # mark the original as inactive since we have a new one
        clientToken.is_active = False
        self.request.dbSession.flush()

        # we recycled the refresh_token!
        assert clientToken.access_token != newToken_db.access_token
        assert clientToken.refresh_token == newToken_db.refresh_token

        # check to ensure we have the right number of active tokens **Client**
        _clientTokens = (
            self.request.dbSession.query(Developer_OAuth2Client_BearerToken)
            .filter(
                Developer_OAuth2Client_BearerToken.useraccount_id
                == USERID_ACTIVE__APPLICATION,
                Developer_OAuth2Client_BearerToken.original_grant_type
                == "authorization_code",
                Developer_OAuth2Client_BearerToken.is_active.is_(True),
            )
            .all()
        )
        assert len(_clientTokens) == 1

        # check to ensure we have the right number of active tokens **Server**
        _serverTokens = (
            self.request.dbSession.query(Developer_OAuth2Server_BearerToken)
            .filter(
                Developer_OAuth2Server_BearerToken.useraccount_id
                == USERID_ACTIVE__AUTHORITY,
                Developer_OAuth2Server_BearerToken.original_grant_type
                == "authorization_code",
                Developer_OAuth2Server_BearerToken.is_active.is_(True),
            )
            .all()
        )
        assert len(_serverTokens) == 1

        # monkeypatch us back
        oauth2_utils.CustomValidator.rotate_refresh_token = (
            oauth2_utils.CustomValidator._rotate_refresh_token__True
        )
        assert (
            oauth2_utils.CustomValidator.rotate_refresh_token
            == oauth2_utils.CustomValidator._rotate_refresh_token__True
        )

        return "refreshed_token"

    @view_config(route_name="application:account:refresh-token", renderer="string")
    def refresh_token_rotate(self):
        """
        refresh the User's token from the server
        """
        if DEBUG_LOGIC:
            print(") ExampleApp_User_AccountViews.refresh_token_rotate")
        if not self.request.active_useraccount_id:
            return HTTPSeeOther("/application/account/login-form")
        if self.request.active_useraccount_id != USERID_ACTIVE__APPLICATION:
            raise ValueError("not the expected user!")

        assert (
            oauth2_utils.CustomValidator.rotate_refresh_token
            == oauth2_utils.CustomValidator._rotate_refresh_token__True
        )

        # what is our token?
        # load from the `Developer_OAuth2Client_` table
        clientToken = (
            self.request.dbSession.query(Developer_OAuth2Client_BearerToken)
            .filter(
                Developer_OAuth2Client_BearerToken.useraccount_id
                == USERID_ACTIVE__APPLICATION,
                Developer_OAuth2Client_BearerToken.original_grant_type
                == "authorization_code",
                Developer_OAuth2Client_BearerToken.is_active.is_(True),
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

        if DEBUG_LOGIC:
            print(") ------")
            print("  )  refresh_token_rotate")
            print("  )  token - original:", token_dict)
            print("  )  token - new     :", newToken_dict)

        # save to the `Developer_OAuth2Client_` table
        newToken_db = Developer_OAuth2Client_BearerToken()
        newToken_db.useraccount_id = self.request.active_useraccount_id
        newToken_db.access_token = newToken_dict["access_token"]
        newToken_db.refresh_token = newToken_dict["refresh_token"]
        newToken_db.scope = " ".join(newToken_dict["scope"])
        newToken_db.grant_type = "refresh_token"
        newToken_db.original_grant_type = "authorization_code"
        newToken_db.timestamp_created = self.request.datetime
        newToken_db.timestamp_expires = (
            newToken_db.timestamp_created
            + datetime.timedelta(seconds=newToken_dict["expires_in"])
        )  # or use newToken_dict['expires_at]
        self.request.dbSession.add(newToken_db)
        self.request.dbSession.flush()

        # mark the original as inactive since we have a new one
        clientToken.is_active = False
        self.request.dbSession.flush()

        # we don't recycle the refresh_token; we replaced it
        assert clientToken.access_token != newToken_db.access_token
        assert clientToken.refresh_token != newToken_db.refresh_token

        # check to ensure we have the right number of active tokens **Client**
        _clientTokens = (
            self.request.dbSession.query(Developer_OAuth2Client_BearerToken)
            .filter(
                Developer_OAuth2Client_BearerToken.useraccount_id
                == USERID_ACTIVE__APPLICATION,
                Developer_OAuth2Client_BearerToken.original_grant_type
                == "authorization_code",
                Developer_OAuth2Client_BearerToken.is_active.is_(True),
            )
            .all()
        )
        assert len(_clientTokens) == 1

        # check to ensure we have the right number of active tokens **Server**
        _serverTokens = (
            self.request.dbSession.query(Developer_OAuth2Server_BearerToken)
            .filter(
                Developer_OAuth2Server_BearerToken.useraccount_id
                == USERID_ACTIVE__AUTHORITY,
                Developer_OAuth2Server_BearerToken.original_grant_type
                == "authorization_code",
                Developer_OAuth2Server_BearerToken.is_active.is_(True),
            )
            .all()
        )
        assert len(_serverTokens) == 1
        return "refreshed_token"

    @view_config(route_name="application:account:revoke-token", renderer="string")
    def revoke_token(self):
        """
        revoke the User's token on the server
        """
        if DEBUG_LOGIC:
            print(") ExampleApp_User_AccountViews.revoke_token")
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
                Developer_OAuth2Client_BearerToken.is_active.is_(True),
            )
            .first()
        )

        if not clientToken:
            raise ValueError("no token for this user!")

        if DEBUG_LOGIC:
            print(")  Developer_OAuth2Client_BearerToken")
            print("  )  .grant_type", clientToken.grant_type)
            print("  )  .access_token", clientToken.access_token)
            print("  )  .refresh_token", clientToken.refresh_token)
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
                Developer_OAuth2Server_BearerToken.is_active.is_(False),
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
        if self.request.active_useraccount_id:
            return HTTPSeeOther("/application/account/home")
        return HTTPSeeOther("/application/flow-register/oauth2/start")

    @view_config(route_name="application:flow-register:oauth2:start", renderer="string")
    def oauth2_start(self):
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
        # we don't have a UID here because we haven't had an account created yet!
        if self.request.active_useraccount_id:
            return HTTPSeeOther("/application/account/home")

        _state = self.request.params.get("state")
        # _code = self.request.params.get("code")

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

        except Exception:
            raise

    @view_config(
        route_name="application:flow-register:oauth2:authorized-callback-success",
        renderer="string",
    )
    def authorized_callback_success(self):
        if not self.request.active_useraccount_id:
            return HTTPSeeOther("/application/account/login-form")
        return (
            "example_app|authorized-callback-success|user=%s"
            % self.request.active_useraccount_id
        )
