from __future__ import print_function

# stdlib
from functools import partial
import json
import pdb
import re
import unittest

# pypi
import requests
import responses
import sqlalchemy
from twython.compat import parse_qsl

# pyramid
from pyramid import testing
from webtest import TestApp
import webtest.app

# local
from ._utils import FakeRequest
from ._utils import parse_request_simple
from ._utils import IsolatedTestapp
from . import oauth1_model
from . import oauth1_utils
from .oauth1_model import OAUTH1__URL_AUTHORITY_AUTHENTICATE
from .oauth1_model import OAUTH1__URL_APP_FLOW_REGISTER_CALLBACK
from .oauth1_model import OAUTH1__URL_APP_FLOW_REGISTER_CALLBACK_SUCCESS
from pyramid_oauthlib_lowlevel.utils import string_headers


# ==============================================================================


OAUTH_EXAMPLE_AUTH = 'OAuth oauth_nonce="24115362306624508491533856374", oauth_timestamp="1533856374", oauth_version="1.0", oauth_signature_method="HMAC-SHA1", oauth_consumer_key="537b5071f94ae5e8304da5a56802a6793bdf770721c80993", oauth_callback="https%3A%2F%2Fexample.com%2Fapi-example%2Fregister%2Fauthorized-callback", oauth_signature="2Ya1BhQD6K3RQQdU3i3U%2B7I93B8%3D"'


re_csrf = re.compile(
    '<input id="csrf_" type="hidden" name="csrf_" value="([^"]*)" data-formencode-ignore=\'1\' />'
)
re_token = re.compile('<input type="hidden" name="oauth_token" value="([^"]*)"/>')


def sa_init_sessionmaker():
    saEngine = sqlalchemy.create_engine("sqlite://", echo=False)
    saSessionmaker = sqlalchemy.orm.sessionmaker(bind=saEngine)
    saSession = saSessionmaker()
    oauth1_model.initialize(saEngine, saSession)
    return (saEngine, saSession)


def new_req_session():
    saEngine = sqlalchemy.create_engine("sqlite://", echo=False)
    saSessionmaker = sqlalchemy.orm.sessionmaker(bind=saEngine)
    saSession = saSessionmaker()
    oauth1_model.initialize(saEngine, saSession)
    req = FakeRequest()
    req.dbSession = saSession
    return req


def new_req_session_bad():
    """
    same as `new_req_session` but without the backend datastore.
    this will cause internal failures which should be caught
    """
    saEngine = sqlalchemy.create_engine("sqlite://", echo=False)
    saSessionmaker = sqlalchemy.orm.sessionmaker(bind=saEngine)
    saSession = saSessionmaker()
    # oauth1_model.initialize(saEngine, saSession)
    req = FakeRequest()
    req.dbSession = saSession
    return req


class PyramidTestApp(unittest.TestCase):
    def setUp(self):
        from .oauth1_app import main

        app = main({})
        # create two (cookie) environments for the same app
        self.testapp_app = TestApp(app)
        self.testapp_authority = TestApp(app)

    def test_invalids(self):
        test_env = {
            "testapp_authority": self.testapp_authority,
            "extra_environ_authority": {
                "wsgi.url_scheme": "https",
                "HTTP_HOST": "authority.example.com",
            },
        }

        res = self.testapp_authority.get(
            "/authority/oauth1/request_token",
            extra_environ=test_env["extra_environ_authority"],
            status=400,
        )
        # assert res.text == 'error=oauth1_error&error_description=Exception+caught+while+processing+request'  # useful for debugging a broken backend
        assert (
            res.text
            == "error=invalid_request&error_description=Missing+mandatory+OAuth+parameters."
        )

        res = self.testapp_authority.get(
            "/authority/oauth1/access_token",
            extra_environ=test_env["extra_environ_authority"],
            status=400,
        )
        # assert res.text == 'error=oauth1_error&error_description=Exception+caught+while+processing+request'  # useful for debugging a broken backend
        assert (
            res.text
            == "error=invalid_request&error_description=Missing+mandatory+OAuth+parameters."
        )

        # /authority/oauth1/authorize requires a login status..
        res = self.testapp_authority.get(
            "/authority/account/login-submit",
            extra_environ=test_env["extra_environ_authority"],
            status=303,
        )
        assert (
            res.text
            == """303 See Other\n\nThe resource has been moved to /authority/account/home; you should be redirected automatically.\n\n"""
        )
        res = self.testapp_authority.get(
            "/authority/oauth1/authorize",
            extra_environ=test_env["extra_environ_authority"],
            status=200,
        )
        assert (
            res.text
            == """<html>
<head></head>
<body>
    <div class="alert alert-danger">
        <b>Error</b>
        (oauth1_error) Error extracting oAuth1 params
    </div>
</body>
</html>
"""
        )

    def test_valid_flow__registration(self):
        """
        This flow tests a user of Authority registering a new account on Application

        IMPORTANT!
        make sure all calls to `testapp.get` and `testapp.post` contain
            extra_environ=test_env['extra_environ_*']  # * is the correct environment
        if we don't include that, then cookies are mixed between `localhost` and `example.com` which will prevent them from being sent correctly.

        This test wraps the Pyramid App into two TestApp environments - one for the 'application' and another for the oauth 'authority', each runing on a different domain as influenced by the `extra_environ_*` dicts. If we don't include that, then cookies are mixed between `localhost` and `example.com` which will prevent them from being sent correctly.

        The general Flow:

        Application         | Authority
        --------------------+-----------------------
                             User logs into Authority
        User visits Application to register
        Application makes a background request to Authority for a token
                             Authority returns a token to Application
        Application redirects user to Authority for confirmation
                             User confirms they want to authorize the application
                             Authority generates the oAuth token and redirects the User back to the Application's callback page
        User visits the callback page, the token is saved, the user is redirected to the callback-sucess page to display success
        User vists the callback-success page.
        --------------------+-----------------------
        """

        test_env = {
            "testapp_authority": self.testapp_authority,
            "testapp_app": self.testapp_app,
            "extra_environ_app": {
                "wsgi.url_scheme": "https",
                "HTTP_HOST": "app.example.com",
            },
            "extra_environ_authority": {
                "wsgi.url_scheme": "https",
                "HTTP_HOST": "authority.example.com",
            },
            "requests_session_app": requests.Session(),
            "requests_session_authority": requests.Session(),
        }

        def callback__request_token(req, test_env=test_env):
            """/authority/oauth1/request_token is visited by the Server

            py3 needs the 'unicode' wrapper to decode the bystring
            """
            assert "Authorization" in req.headers
            assert req.headers["Authorization"].decode("utf-8").startswith("OAuth ")
            assert "User-Agent" in req.headers
            assert req.headers["User-Agent"].decode("utf-8") == "CustomApiClient v0"
            assert req.url == oauth1_utils.CustomApiClient.OAUTH1_SERVER_REQUEST_TOKEN

            # request as SERVER, no cookies
            with IsolatedTestapp(test_env["testapp_authority"]) as testapp:
                res = testapp.get(
                    "/authority/oauth1/request_token",
                    headers=req.headers,
                    extra_environ=test_env["extra_environ_authority"],
                    status=200,
                )

            # status is '200 OK'
            # return in a format tailored for `requests`
            return (int(res.status.split(" ")[0]), res.headers, res.body)

        def callback__authenticate_get(req, test_env=test_env):
            """/authority/oauth1/authorize is visited by the USER"""
            assert req.url.startswith(OAUTH1__URL_AUTHORITY_AUTHENTICATE)
            qs = req.url.split("?")[1]
            qs = dict(parse_qsl(qs))

            testapp = test_env["testapp_authority"]
            res = testapp.get(
                "/authority/oauth1/authorize?oauth_token=%s" % qs["oauth_token"],
                headers=req.headers,
                extra_environ=test_env["extra_environ_authority"],
                status=200,
            )
            test_env["requests_session_authority"].cookies.update(
                testapp.cookies
            )  # update the session with the cookies from the response

            # status is '200 OK'
            # return in a format tailored for `requests`
            return (int(res.status.split(" ")[0]), res.headers, res.body)

        def callback__authenticate_post(req, test_env=test_env):
            """/authority/oauth1/authorize is visited by the USER"""
            assert req.url.startswith(OAUTH1__URL_AUTHORITY_AUTHENTICATE)
            payload = dict(parse_qsl(req.body))

            testapp = test_env["testapp_authority"]
            res = testapp.post(
                "/authority/oauth1/authorize",
                payload,
                headers=req.headers,
                extra_environ=test_env["extra_environ_authority"],
                status=302,
            )
            test_env["requests_session_authority"].cookies.update(
                testapp.cookies
            )  # update the session with the cookies from the response

            # status is '200 OK'
            # return in a format tailored for `requests`
            return (int(res.status.split(" ")[0]), res.headers, res.body)

        def callback__callback(req, test_env=test_env):
            """/application/flow-register/authorized-callback is visited by the USER"""
            _path, _qs = req.url.split("?")

            testapp = test_env["testapp_app"]
            res = testapp.get(
                "/application/flow-register/authorized-callback?%s" % _qs,
                headers=req.headers,
                extra_environ=test_env["extra_environ_app"],
                status=303,
            )
            test_env["requests_session_app"].cookies.update(
                testapp.cookies
            )  # update the session with the cookies from the response

            # status is '303 See Other'
            # return in a format tailored for `requests`
            return (int(res.status.split(" ")[0]), res.headers, res.body)

        def callback__access_token(req, test_env=test_env):
            """/authority/oauth1/access_token is visited by the Server"""
            assert "Authorization" in req.headers
            assert req.headers["Authorization"].decode("utf-8").startswith("OAuth ")
            assert "User-Agent" in req.headers
            assert req.headers["User-Agent"].decode("utf-8") == "CustomApiClient v0"
            assert req.url == oauth1_utils.CustomApiClient.OAUTH1_SERVER_ACCESS_TOKEN

            # request as SERVER, no cookies
            with IsolatedTestapp(test_env["testapp_authority"]) as testapp:
                _headers = string_headers(
                    req.headers
                )  # these can end up being unicode in tests
                res = testapp.get(
                    "/authority/oauth1/access_token",
                    headers=_headers,
                    extra_environ=test_env["extra_environ_authority"],
                    status=200,
                )

            # status is '200 OK'
            # return in a format tailored for `requests`
            return (int(res.status.split(" ")[0]), res.headers, res.body)

        def callback__callback_success(req, test_env=test_env):
            """/application/flow-register/authorized-callback-success is visited by the USER"""
            (_path, _qs) = parse_request_simple(req)

            testapp = test_env["testapp_application"]
            _headers = string_headers(
                req.headers
            )  # these can end up being unicode in tests
            res = testapp.get(
                "/application/flow-register/authorized-callback-success?%s" % _qs,
                headers=_headers,
                extra_environ=test_env["extra_environ_app"],
                status=200,
            )
            test_env["requests_session_application"].cookies.update(
                testapp.cookies
            )  # update the session with the cookies from the response

            # status is '200 OK'
            # return in a format tailored for `requests`
            return (int(res.status.split(" ")[0]), res.headers, res.body)

        with responses.RequestsMock() as rsps:

            rsps.add_callback(
                responses.GET,
                oauth1_utils.CustomApiClient.OAUTH1_SERVER_REQUEST_TOKEN,  # /authority/oauth1/request_token
                callback=callback__request_token,
            )
            rsps.add_callback(
                responses.GET,
                oauth1_utils.CustomApiClient.OAUTH1_SERVER_ACCESS_TOKEN,  # /authority/oauth1/access_token
                callback=callback__access_token,
            )

            # the following were originally handled via `requests.get` but migrated to direct webtest queries
            #
            # rsps.add_callback(
            #     responses.GET, OAUTH1__URL_AUTHORITY_AUTHENTICATE,  # /authority/oauth1/authorize
            #     callback=callback__authenticate_get,
            # )
            # rsps.add_callback(
            #     responses.POST, OAUTH1__URL_AUTHORITY_AUTHENTICATE,  # /authority/oauth1/authorize
            #     callback=callback__authenticate_post,
            # )
            # rsps.add_callback(
            #     responses.GET, oauth1_model.OAUTH1__URL_APP_FLOW_REGISTER_CALLBACK,  # https://example.com/application/flow-register/authorized-callback
            #     callback=callback__callback,
            # )
            # rsps.add_callback(
            #     responses.GET, oauth1_model.OAUTH1__URL_APP_FLOW_REGISTER_CALLBACK_SUCCESS,  # https://example.com/application/flow-register/authorized-callback-success
            #     callback=callback__callback_success,
            # )

            #
            # actual test flow...
            #

            # first we need to log into the oAuth1 Authority
            # the authority is the account which will be the oAuth identity provider (e.g. Twitter)

            # User visit
            res = self.testapp_authority.get(
                "/authority/account/login-form",
                extra_environ=test_env["extra_environ_authority"],
                status=200,
            )
            assert res.text == "authority|login-form"
            test_env["requests_session_authority"].cookies.update(
                self.testapp_authority.cookies
            )  # update the session with the cookies from the response

            # User visit
            res = self.testapp_authority.get(
                "/authority/account/login-submit",
                extra_environ=test_env["extra_environ_authority"],
                status=303,
            )
            test_env["requests_session_authority"].cookies.update(
                self.testapp_authority.cookies
            )  # update the session with the cookies from the response
            assert (
                res.text
                == """303 See Other\n\nThe resource has been moved to /authority/account/home; you should be redirected automatically.\n\n"""
            )

            # User visit
            res = self.testapp_authority.get(
                "/authority/account/home",
                extra_environ=test_env["extra_environ_authority"],
                status=200,
            )
            test_env["requests_session_authority"].cookies.update(
                self.testapp_authority.cookies
            )  # update the session with the cookies from the response
            assert (
                res.text
                == "authority|home|user=%s" % oauth1_model.USERID_ACTIVE__AUTHORITY
            )

            #
            # now we want to visit the application
            #

            # User visit's the application
            #
            res = self.testapp_app.get(
                "/application/flow-register",
                extra_environ=test_env["extra_environ_app"],
                status=303,
            )
            test_env["requests_session_app"].cookies.update(
                self.testapp_app.cookies
            )  # update the session with the cookies from the response
            assert (
                res.text
                == """303 See Other\n\nThe resource has been moved to /application/flow-register/oauth1/start; you should be redirected automatically.\n\n"""
            )

            # User visit
            # however, it makes a behind the scenes visit to
            # * /authority/oauth1/request_token
            res = self.testapp_app.get(
                "/application/flow-register/oauth1/start",
                extra_environ=test_env["extra_environ_app"],
                status=303,
            )
            test_env["requests_session_app"].cookies.update(
                self.testapp_app.cookies
            )  # update the session with the cookies from the response
            assert "Location" in res.headers
            url_auth = res.headers["Location"]
            assert res.headers["Location"].startswith(
                OAUTH1__URL_AUTHORITY_AUTHENTICATE
            )

            # resAuthInbound = test_env['requests_session_authority'].get(url_auth)
            # then the user is redirected to the authority to approve
            qs = url_auth.split("?")[1]
            url_auth_local = "/authority/oauth1/authorize?%s" % qs
            resAuthInbound = self.testapp_authority.get(
                url_auth_local, extra_environ=test_env["extra_environ_authority"]
            )
            assert (
                '<form action="/authority/oauth1/authorize" method="POST" id="app-action-authorize">'
                in resAuthInbound.text
            )
            csrfs = re_csrf.findall(resAuthInbound.text)
            assert len(csrfs) == 2  # submit, deny
            tokens = re_token.findall(resAuthInbound.text)
            assert len(tokens) == 2  # submit, deny

            payload = {
                "csrf_": csrfs[0],
                "oauth_token": tokens[0],
                "submit": "authorize",
            }
            # payload = {'csrf_': csrfs[0], 'oauth_token': tokens[0], 'submit': 'authorize', }

            # visited by USER: Authorize the application on the Authority
            resAuthApprove = self.testapp_authority.post(
                "/authority/oauth1/authorize",
                payload,
                extra_environ=test_env["extra_environ_authority"],
                status=302,
            )
            test_env["requests_session_authority"].cookies.update(
                self.testapp_authority.cookies
            )  # update the session with the cookies from the response

            # visited by USER: redirected to the callback page on the APPLICATION
            assert "Location" in resAuthApprove.headers
            url_callback = resAuthApprove.headers["Location"]
            assert url_callback.startswith(OAUTH1__URL_APP_FLOW_REGISTER_CALLBACK)
            qs = url_callback.split("?")[1]
            url_callback_local = (
                "/application/flow-register/authorized-callback?%s" % qs
            )
            resAuthCallback = self.testapp_app.get(
                url_callback_local,
                extra_environ=test_env["extra_environ_app"],
                status=303,
            )

            # visited by USER: redirected to the callback-success page on the APPLICATION
            assert "Location" in resAuthCallback.headers
            url_callback_success = resAuthCallback.headers["Location"]
            assert url_callback_success.startswith(
                OAUTH1__URL_APP_FLOW_REGISTER_CALLBACK_SUCCESS
            )
            assert len(url_callback_success.split("?")) == 1
            url_callback_success_local = (
                "/application/flow-register/authorized-callback-success"
            )
            resAuthCallbackSuccess = self.testapp_app.get(
                url_callback_success_local,
                extra_environ=test_env["extra_environ_app"],
                status=200,
            )
            assert (
                resAuthCallbackSuccess.text
                == "application|register|authorized-callback-success|user=%s"
                % oauth1_model.USERID_ACTIVE__APPLICATION
            )

            # ensure logout, just to be safe
            res = self.testapp_authority.get(
                "/authority/account/logout",
                extra_environ=test_env["extra_environ_authority"],
                status=303,
            )
            assert (
                res.text
                == """303 See Other\n\nThe resource has been moved to /authority/account/login-form; you should be redirected automatically.\n\n"""
            )

            res = self.testapp_authority.get(
                "/authority/account/home",
                extra_environ=test_env["extra_environ_authority"],
                status=303,
            )
            assert (
                res.text
                == """303 See Other\n\nThe resource has been moved to /authority/account/login-form; you should be redirected automatically.\n\n"""
            )


class TestOauth1Faked(unittest.TestCase):
    def test_request_token(self):

        req = new_req_session()
        req.current_route_url(
            uri=oauth1_utils.CustomApiClient.OAUTH1_SERVER_REQUEST_TOKEN
        )
        provider = oauth1_utils.new_oauth1Provider(req)
        result = provider.endpoint__request_token(dbSessionCommit=req.dbSession)
        assert result.status_code == 400
        assert (
            result.text
            == "error=invalid_request&error_description=Missing+mandatory+OAuth+parameters."
        )

        req.headers = {"Authorization": OAUTH_EXAMPLE_AUTH}
        provider = oauth1_utils.new_oauth1Provider(req)
        result = provider.endpoint__request_token(dbSessionCommit=req.dbSession)
        assert result.status_code == 400
        assert (
            result.text
            == "error=invalid_request&error_description=Timestamp+given+is+invalid%2C+differ+from+allowed+by+over+600+seconds."
        )

        req.headers = {"Authorization": OAUTH_EXAMPLE_AUTH}
        provider = oauth1_utils.new_oauth1Provider(req)
        result = provider.endpoint__request_token(dbSessionCommit=req.dbSession)
        assert result.status_code == 400
        assert (
            result.text
            == "error=invalid_request&error_description=Timestamp+given+is+invalid%2C+differ+from+allowed+by+over+600+seconds."
        )

        req.headers = {
            "Authorization": OAUTH_EXAMPLE_AUTH.replace(
                "1533856374", oauth1_utils.oauth_time_now()
            )
        }
        provider = oauth1_utils.new_oauth1Provider(req)
        result = provider.endpoint__request_token(dbSessionCommit=req.dbSession)
        assert result.status_code == 400
        assert result.text == "error=invalid_client&error_description=Invalid+Client"

    def test_request_token_backend_failure(self):
        """
        same as `test_request_token`, except with a broken database
        this should generate a 500 exception
        """

        req = new_req_session_bad()

        req.current_route_url(
            uri=oauth1_utils.CustomApiClient.OAUTH1_SERVER_REQUEST_TOKEN
        )
        provider = oauth1_utils.new_oauth1Provider(req)
        result = provider.endpoint__request_token(dbSessionCommit=req.dbSession)
        assert result.status_code == 400
        assert (
            result.text
            == "error=invalid_request&error_description=Missing+mandatory+OAuth+parameters."
        )

        req.headers = {"Authorization": OAUTH_EXAMPLE_AUTH}
        provider = oauth1_utils.new_oauth1Provider(req)
        result = provider.endpoint__request_token(dbSessionCommit=req.dbSession)
        assert result.status_code == 400
        assert (
            result.text
            == "error=invalid_request&error_description=Timestamp+given+is+invalid%2C+differ+from+allowed+by+over+600+seconds."
        )

        req.headers = {"Authorization": OAUTH_EXAMPLE_AUTH}
        provider = oauth1_utils.new_oauth1Provider(req)
        result = provider.endpoint__request_token(dbSessionCommit=req.dbSession)
        assert result.status_code == 400
        assert (
            result.text
            == "error=invalid_request&error_description=Timestamp+given+is+invalid%2C+differ+from+allowed+by+over+600+seconds."
        )

        req.headers = {
            "Authorization": OAUTH_EXAMPLE_AUTH.replace(
                "1533856374", oauth1_utils.oauth_time_now()
            )
        }
        provider = oauth1_utils.new_oauth1Provider(req)
        result = provider.endpoint__request_token(dbSessionCommit=req.dbSession)
        assert result.status_code == 500
        assert (
            result.text
            == u"error=internal_system_failure&error_description=Internal+System+Failure"
        )
