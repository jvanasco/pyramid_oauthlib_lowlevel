from __future__ import print_function
import logging

log = logging.getLogger(__name__)

"""
fake app for tests
"""
# stdlib
import os
import pdb

# pyramid
from pyramid.renderers import render_to_response
from pyramid.view import view_config
from pyramid.csrf import get_csrf_token
from pyramid.httpexceptions import HTTPException
from pyramid.httpexceptions import HTTPSeeOther

# pypi
import pyramid_formencode_classic as formhandling
from formencode import Schema as form_Schema
from formencode.validators import UnicodeString as form_UnicodeString
from formencode.validators import OneOf as form_OneOf

# local
from ..oauth1_utils import new_oauth1Provider
from ..oauth1_utils import CustomApiClient
from ..oauth1_utils import get_ApiExampleAppData
from ..oauth1_model import Developer_oAuth1Server_TokenRequest
from ..oauth1_model import Developer_oAuth1Server_TokenAccess
from ..oauth1_model import Developer_oAuth1Client_TokenAccess
from ..oauth1_model import USERID_ACTIVE__APPLICATION
from ..oauth1_model import USERID_ACTIVE__AUTHORITY

# local package
from oauthlib.oauth1.rfc5849.errors import OAuth1Error
from pyramid_oauthlib_lowlevel.client.api_client import ApiError
from pyramid_oauthlib_lowlevel.client.api_client import ApiAuthError


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


class Form_OAuthToken(form_Schema):
    allow_extra_fields = True
    filter_extra_fields = True
    oauth_token = form_UnicodeString(not_empty=True)
    submit = form_OneOf(("authorize", "deny"))


# ==============================================================================


class Handler(object):
    def __init__(self, request):
        self.request = request


class Authority_User_AcccountViews(Handler):
    @view_config(route_name="authority:account:login-form", renderer="string")
    def account_login_form(self):
        if DEBUG_ROUTE:
            print("authority:account:login-form", get_csrf_token(self.request))
        if LOG_ROUTE:
            log.debug("authority:account:login-form %s", get_csrf_token(self.request))
        if DEBUG_USERID:
            print("authority:account:login-form", self.request.active_useraccount_id)
        if self.request.active_useraccount_id:
            return HTTPSeeOther("/authority/account/home")
        return "authority|login-form"

    @view_config(route_name="authority:account:login-submit", renderer="string")
    def account_login_submit(self):
        if DEBUG_ROUTE:
            print("authority:account:login-submit", get_csrf_token(self.request))
        if LOG_ROUTE:
            log.debug("authority:account:login-submit %s", get_csrf_token(self.request))
        if DEBUG_USERID:
            print("authority:account:login-submit", self.request.active_useraccount_id)
        self.request.session["active_useraccount_id"] = USERID_ACTIVE__AUTHORITY
        return HTTPSeeOther("/authority/account/home")

    @view_config(route_name="authority:account:home", renderer="string")
    def account_home(self):
        if DEBUG_ROUTE:
            print("authority:account:home", get_csrf_token(self.request))
        if LOG_ROUTE:
            log.debug("authority:account:home %s", get_csrf_token(self.request))
        if DEBUG_USERID:
            print("authority:account:home", self.request.active_useraccount_id)
        if not self.request.active_useraccount_id:
            return HTTPSeeOther("/authority/account/login-form")
        return "authority|home|user=%s" % self.request.active_useraccount_id

    @view_config(route_name="authority:account:logout", renderer="string")
    def account_logout(self):
        if DEBUG_ROUTE:
            print("authority:account:logout", get_csrf_token(self.request))
        if LOG_ROUTE:
            log.debug("authority:account:logout %s", get_csrf_token(self.request))
        if DEBUG_USERID:
            print("authority:account:logout", self.request.active_useraccount_id)
        if self.request.active_useraccount_id:
            self.request.session.invalidate()
        return HTTPSeeOther("/authority/account/login-form")


class Authority_Oauth1_FlowShared_API_Public(Handler):
    """And you'll need to allow logged in users to authenticate"""

    @view_config(route_name="authority:oauth1:request_token", renderer="string")
    def request_token(self):
        if DEBUG_ROUTE:
            print("authority:oauth1:request_token", get_csrf_token(self.request))
        if LOG_ROUTE:
            log.debug("authority:oauth1:request_token %s", get_csrf_token(self.request))
        if DEBUG_USERID:
            print("authority:oauth1:request_token", self.request.active_useraccount_id)
        try:
            provider = new_oauth1Provider(self.request)
            return provider.endpoint__request_token()
        except HTTPException:
            raise
        except Exception as exc:
            # raise custom errors in production
            raise

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    @view_config(route_name="authority:oauth1:access_token", renderer="string")
    def access_token(self):
        if DEBUG_ROUTE:
            print("authority:oauth1:access_token", get_csrf_token(self.request))
        if LOG_ROUTE:
            log.debug("authority:oauth1:access_token %s", get_csrf_token(self.request))
        if DEBUG_USERID:
            print("authority:oauth1:access_token", self.request.active_useraccount_id)
        try:
            provider = new_oauth1Provider(self.request)
            return provider.endpoint__access_token()
        except HTTPException:
            raise
        except Exception as exc:
            # raise custom errors in production
            raise exc

    @view_config(route_name="authority:oauth1:authorize")
    def authorize(self):
        if DEBUG_ROUTE:
            print("authority:oauth1:authorize", get_csrf_token(self.request))
        if LOG_ROUTE:
            log.debug("authority:oauth1:authorize %s", get_csrf_token(self.request))
        if DEBUG_USERID:
            print("authority:oauth1:authorize", self.request.active_useraccount_id)
        if not self.request.active_useraccount_id:
            return HTTPSeeOther("/authority/account/login-form")
        try:
            # no matter what we do, we need to grab this data
            oauth1Provider = new_oauth1Provider(self.request)

            # this is decorated by `catch_errors_and_unavailability` and will raise an `OAuth1Error`
            oauth1_data = oauth1Provider.extract__endpoint_authorize_data()

            # grab the token to show the user or process
            oauth1_TokenRequest = (
                self.request.dbSession.query(Developer_oAuth1Server_TokenRequest)
                .filter(
                    Developer_oAuth1Server_TokenRequest.oauth_token
                    == oauth1_data["credentials"]["resource_owner_key"],
                    Developer_oAuth1Server_TokenRequest.is_active == True,  # noqa
                )
                .first()
            )
            if not oauth1_TokenRequest:
                raise ValueError("invalid token")

            self.request.workspace.oAuth1Provider = oauth1Provider
            self.request.workspace.oAuth1_data = oauth1_data
            self.request.workspace.oAuth1_TokenRequest = oauth1_TokenRequest

            if self.request.method == "POST":
                # this can raise an `OAuth1Error`, but it should be caught
                return self._authorize_process()
            return self._authorize_print()

        except OAuth1Error as exc:
            self.request.workspace.oAuth1_Error = exc
            return render_to_response(
                "pyramid_oauthlib_lowlevel:tests/oauth1_app/templates/authorize-error.mako",
                {},
                self.request,
            )

    def _authorize_print(self):
        """print the form"""
        return render_to_response(
            "pyramid_oauthlib_lowlevel:tests/oauth1_app/templates/authorize-form.mako",
            {},
            self.request,
        )

    def _authorize_process(self):
        """process the form"""
        try:
            (result, formStash) = formhandling.form_validate(
                self.request,
                schema=Form_OAuthToken,
                csrf_token=get_csrf_token(self.request),
            )
            if not result:
                raise formhandling.FormInvalid()

            if formStash.results["submit"] == "deny":
                # process deny
                raise HTTPSeeOther("/account/home")

            # accept!
            # this is decorated by `catch_errors_and_unavailability` and will raise an `OAuth1Error`
            return self.request.workspace.oAuth1Provider.endpoint__authorize__authorize(
                self.request.workspace.oAuth1_data
            )

        except (OAuth1Error, formhandling.FormInvalid) as exc:
            if isinstance(exc, OAuth1Error):
                self.request.workspace.oAuth1_Error = exc
            return formhandling.form_reprint(self.request, self._authorize_print)


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
        return HTTPSeeOther("/application/flow-register/oauth1/start")

    @view_config(route_name="application:flow-register:oauth1:start", renderer="string")
    def oauth1_start(self):
        if DEBUG_ROUTE:
            print(
                "application:flow-register:oauth1:start", get_csrf_token(self.request)
            )
        if LOG_ROUTE:
            log.debug(
                "application:flow-register:oauth1:start %s",
                get_csrf_token(self.request),
            )
        if DEBUG_USERID:
            print(
                "application:account:oauth1:start", self.request.active_useraccount_id
            )

        if self.request.active_useraccount_id:
            return HTTPSeeOther("/application/account/home")

        # setup the session storage
        if "3rdparty-app_oauth" not in self.request.session:
            self.request.session["3rdparty-app_oauth"] = {}

        # Store whether this OAuth attempt is to authenticate or authorize, so we
        # can provide the right try again link in case any of our calls to the
        # Twitter API fail.
        self.request.session["3rdparty-app_oauth"]["mode"] = "authorize"

        # If there was a valid ``next`` param in the query string, store it in the
        # session so we can redirect to it later on.
        self.request.session["3rdparty-app_oauth"]["next"] = self.request.params.get(
            "next"
        )

        app_data = get_ApiExampleAppData()
        apiClient = CustomApiClient(
            app_key=app_data["client_key"],
            app_secret=app_data["client_secret"],
            client_args={"verify": False},
        )
        try:
            auth_props = apiClient.get_authentication_tokens(
                callback_url=app_data["callback_uri"]
            )
            self.request.session["3rdparty-app_oauth"]["auth_url"] = auth_props[
                "auth_url"
            ]
            self.request.session["3rdparty-app_oauth"]["oauth_token"] = auth_props[
                "oauth_token"
            ]
            self.request.session["3rdparty-app_oauth"][
                "oauth_token_secret"
            ] = auth_props["oauth_token_secret"]
            redirect_url = auth_props["auth_url"]
            return HTTPSeeOther(location=redirect_url)

        except ApiAuthError as exc:
            raise ValueError("There are issues connecting with the Example Server API.")

        except ApiError as exc:
            error_dict = {"error": 1, "error_message": exc.msg}
            raise ValueError(exc.msg)

    @view_config(
        route_name="application:flow-register:oauth1:authorized-callback",
        renderer="string",
    )
    def registration_authorized_callback(self):
        if DEBUG_ROUTE:
            print(
                "application:flow-register:oauth1:authorized-callback",
                get_csrf_token(self.request),
            )
        if LOG_ROUTE:
            log.debug(
                "application:flow-register:oauth1:authorized-callback %s",
                get_csrf_token(self.request),
            )

        if DEBUG_USERID:
            print(
                "application:account:register:oauth1:authorized-callback",
                self.request.active_useraccount_id,
            )

        # we don't have a UID here because we haven't had an account created yet!
        if self.request.active_useraccount_id:
            return HTTPSeeOther("/application/account/home")

        public_token = self.request.params.get("oauth_token")
        public_verifier = self.request.params.get("oauth_verifier")

        oauth_sessiondata = self.request.session["3rdparty-app_oauth"]
        if not oauth_sessiondata:
            raise ApiError("we could not link your authorization session correctly.")
        _oauth_token = oauth_sessiondata.get("oauth_token")
        _oauth_token_secret = oauth_sessiondata.get("oauth_token_secret")
        if (_oauth_token is None) or (_oauth_token_secret is None):
            raise ApiError(
                "we could not link your authorization session data correctly."
            )

        app_data = get_ApiExampleAppData()
        apiClient = CustomApiClient(
            app_key=app_data["client_key"],
            app_secret=app_data["client_secret"],
            oauth_token=_oauth_token,
            oauth_token_secret=_oauth_token_secret,
            client_args={"verify": False},
        )
        authorized = apiClient.get_authorized_tokens(public_verifier)

        # wow ok, we have successfully authorized, so...
        # log them in as a new user!
        # do this first, because the `Developer_oAuth1Server_TokenClient` requires a
        self.request.session["active_useraccount_id"] = USERID_ACTIVE__APPLICATION

        newGrant = Developer_oAuth1Client_TokenAccess()
        newGrant.developer_application_id = app_data["id"]
        newGrant.useraccount_id = self.request.active_useraccount_id
        newGrant.timestamp_created = self.request.datetime
        newGrant.oauth_token = authorized["oauth_token"]
        newGrant.oauth_token_secret = authorized["oauth_token_secret"]
        newGrant._realms = (
            authorized["oauth_authorized_realms"]
            if "oauth_authorized_realms" in authorized
            else ""
        )
        newGrant.oauth_version = "1"
        self.request.dbSession.add(newGrant)

        return HTTPSeeOther(
            location="/application/flow-register/authorized-callback-success"
        )

    @view_config(
        route_name="application:flow-register:oauth1:authorized-callback-success",
        renderer="string",
    )
    def registration_authorized_callback_success(self):
        if DEBUG_ROUTE:
            print(
                "application:flow-register:oauth1:authorized-callback-success",
                get_csrf_token(self.request),
            )
        if LOG_ROUTE:
            log.debug(
                "application:flow-register:oauth1:authorized-callback-success|user=%s",
                get_csrf_token(self.request),
            )
        if DEBUG_USERID:
            print(
                "application:account:register:oauth1:authorized-callback-success",
                self.request.active_useraccount_id,
            )
        if not self.request.active_useraccount_id:
            return HTTPSeeOther("/application/account/login-form")

        # so let's just check to ensure we have the right number of active tokens (Client)
        _clientTokens = (
            self.request.dbSession.query(Developer_oAuth1Client_TokenAccess)
            .filter(
                Developer_oAuth1Client_TokenAccess.useraccount_id
                == USERID_ACTIVE__APPLICATION,
                Developer_oAuth1Client_TokenAccess.is_active == True,  # noqa
            )
            .all()
        )
        assert len(_clientTokens) == 1

        # so let's just check to ensure we have the right number of active tokens (Server)
        _serverTokens = (
            self.request.dbSession.query(Developer_oAuth1Server_TokenAccess)
            .filter(
                Developer_oAuth1Server_TokenAccess.useraccount_id
                == USERID_ACTIVE__AUTHORITY,
                Developer_oAuth1Server_TokenAccess.is_active == True,  # noqa
            )
            .all()
        )
        assert len(_serverTokens) == 1

        # and make sure the client/server tokens are the same
        assert (
            _serverTokens[0].oauth_token_secret == _clientTokens[0].oauth_token_secret
        )
        assert _serverTokens[0].oauth_token == _clientTokens[0].oauth_token
        assert _serverTokens[0]._realms == _clientTokens[0]._realms

        # yep, we good
        return (
            "application|register|authorized-callback-success|user=%s"
            % self.request.active_useraccount_id
        )
