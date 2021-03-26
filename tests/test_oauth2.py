from __future__ import print_function

import logging

log = logging.getLogger(__name__)

# stdlib
import pdb
import re
import unittest

# pypi
from requests_oauthlib import OAuth2Session
from twython.compat import parse_qsl
from webtest import TestApp
import requests
import requests_oauthlib
import responses

# local
from . import oauth2_app
from . import oauth2_model
from . import oauth2_utils
from ._utils import FakeRequest
from ._utils import IsolatedTestapp
from ._utils import parse_request_simple
from pyramid_oauthlib_lowlevel.client.api_client import ApiError, ApiAuthError
from pyramid_oauthlib_lowlevel.utils import string_headers


# ==============================================================================

# these regex are used for handling form submission
re_csrf = re.compile(
    '<input id="csrf_" type="hidden" name="csrf_" value="([^"]*)" data-formencode-ignore=\'1\' />'
)
re_scope = re.compile('<input type="hidden" name="scope" value="([^"]*)"/>')
re_client_id = re.compile('<input type="hidden" name="client_id" value="([^"]*)"/>')
re_redirect_uri = re.compile(
    '<input type="hidden" name="redirect_uri" value="([^"]*)"/>'
)
re_response_type = re.compile(
    '<input type="hidden" name="response_type" value="([^"]*)"/>'
)
re_state = re.compile('<input type="hidden" name="state" value="([^"]*)"/>')


class PyramidTestApp(unittest.TestCase):
    def setUp(self):
        from .oauth2_app import main

        app = main({})
        self.testapp_app = TestApp(app)
        self.testapp_authority = TestApp(app)

    def test_valid_flow__registration(self):
        """
        This flow tests a user of Authority registering a new account on Application

        IMPORTANT!
        make sure all calls to `testapp.get` and `testapp.post` contain
            extra_environ=test_env['extra_environ_*']  # * is the correct environment
        if we don't include that, then cookies are mixed between `localhost` and `example.com` which will prevent them from being sent correctly.

        This test wraps the Pyramid App into two TestApp environments - one for the 'application' and another for the oauth 'authority', each runing on a different domain as influenced by the `extra_environ_*` dicts.  If we don't include that, then cookies are mixed between `localhost` and `example.com` which will prevent them from being sent correctly.

        The general Flow:

        Application         | Authority
        --------------------+-----------------------
                             User logs into Authority
        User visits Application to register
        Application redirects user to Authority for authorization with a unique token
                             User confirms they want to authorize the application
                             Authority generates the oAuth token and redirects the User back to the Application's callback page
        User visits the callback page, the token is saved, the user is redirected to the callback-sucess page to display success
        User vists the callback-success page.
        --------------------+-----------------------
        """

        test_env = {
            "testapp_app": self.testapp_app,
            "testapp_authority": self.testapp_authority,
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

        # Credentials you get from registering a new application
        client_id = oauth2_model.OAUTH2__APP_KEY
        client_secret = oauth2_model.OAUTH2__APP_SECRET

        def callback__authorization_base_url(req):
            """/authority/oauth2/flow-a/authorization is visited by the USER_BROWSER"""
            assert req.url.startswith(
                oauth2_utils.OAUTH2__URL_AUTHORITY_FLOWA_AUTHORIZATION
            )
            (_path, _qs) = parse_request_simple(req)

            testapp_authority = test_env["testapp_authority"]
            res = testapp_authority.get(
                "/authority/oauth2/flow-a/authorization?%s" % _qs,
                headers=req.headers,
                extra_environ=test_env["extra_environ_authority"],
                status=200,
            )
            test_env["requests_session_authority"].cookies.update(
                testapp_authority.cookies
            )  # update the session with the cookies from the response

            # status is '200 OK'
            # return in a format tailored for `requests`
            return (int(res.status.split(" ")[0]), res.headers, res.body)

        def callback__authorization_base_url_post(req):
            """POST /authority/oauth2/flow-a/authorization is visited by the USER_BROWSER after doing the GET"""
            assert req.url.startswith(
                oauth2_utils.OAUTH2__URL_AUTHORITY_FLOWA_AUTHORIZATION
            )
            payload = dict(parse_qsl(req.body))

            testapp_authority = test_env["testapp_authority"]
            res = testapp_authority.post(
                "/authority/oauth2/flow-a/authorization",
                payload,
                headers=req.headers,
                extra_environ=test_env["extra_environ_authority"],
                status=302,
            )
            test_env["requests_session_authority"].cookies.update(
                testapp_authority.cookies
            )  # update the session with the cookies from the response

            # assume this is a valid request
            # ResponseHeaders([('Location', 'https://app.example.com/application/flow-register/authorized-callback?state=XufmnJbYMKORxkgj1jtfIbojm1YFwm&code=bLE6gTXo7nxvdNlvWzXsIdOh53Xe1f')])

            assert "Location" in res.headers
            _uri_redirect = res.headers["Location"]
            assert _uri_redirect.startswith(
                oauth2_model.OAUTH2__URL_APP_FLOW_REGISTER_CALLBACK
            )

            _base, _qs = _uri_redirect.split("?")
            _qs = dict(parse_qsl(_qs))
            assert _qs.get("state")
            assert _qs.get("code")

            # status is '200 OK'
            # return in a format tailored for `requests`
            return (int(res.status.split(" ")[0]), res.headers, res.body)

        # def callback__token_url(req):
        #    """/authority/oauth2/flow-a/token is visited by a CLIENT ; is this GET or POST?"""
        #    # request as CLIENT, no cookies
        #    with IsolatedTestapp(test_env['testapp_authority']) as testapp_authority:
        #        res = testapp_authority.get('/authority/oauth2/flow-a/token', headers=req.headers, extra_environ=test_env['extra_environ_authority'], status=200)
        #    # status is '200 OK'
        #    # return in a format tailored for `requests`
        #    return (int(res.status.split(' ')[0]), res.headers, res.body)

        def callback__token_url_post(req):
            """POST /authority/oauth2/flow-a/token is made by the client (IN THE SERVER) to get a token for the code"""
            assert req.url.startswith(oauth2_utils.OAUTH2__URL_AUTHORITY_FLOWA_TOKEN)
            payload = dict(parse_qsl(req.body))

            _headers = string_headers(
                req.headers
            )  # these can end up being unicode in tests
            testapp_authority = test_env["testapp_authority"]
            res = testapp_authority.post(
                "/authority/oauth2/flow-a/token",
                payload,
                headers=_headers,
                extra_environ=test_env["extra_environ_authority"],
                status=200,
            )
            test_env["requests_session_authority"].cookies.update(
                testapp_authority.cookies
            )  # update the session with the cookies from the response

            return (int(res.status.split(" ")[0]), res.headers, res.body)

        def callback__app_callback(req):
            """/application/flow-register/authorized-callback is visited by the USER_BROWSER"""
            (_path, _qs) = parse_request_simple(req)

            # ConnectionError: Connection refused: GET https://app.example.com/application/flow-register/authorized-callback?state=ZNZvad0w74CbyJFq0HJO8zDm26bJme&code=5wU5CPjP5W6KzwSKCiRemeXnW7B5kb

            test_env["testapp_app"].get("/whoami")

            testapp_app = test_env["testapp_app"]
            res = testapp_app.get(
                "/application/flow-register/authorized-callback?%s" % _qs,
                headers=req.headers,
                extra_environ=test_env["extra_environ_app"],
                status=303,
            )
            test_env["requests_session_app"].cookies.update(
                testapp_app.cookies
            )  # update the session with the cookies from the response

            # status is '303 SEE Other'
            # return in a format tailored for `requests`
            return (int(res.status.split(" ")[0]), res.headers, res.body)

        def callback__app_callback_success(req, test_env=test_env):
            """/application/flow-register/authorized-callback-success is visited by the USER"""
            (_path, _qs) = parse_request_simple(req)

            testapp_app = test_env["testapp_app"]
            res = testapp_app.get(
                "/application/flow-register/authorized-callback-success?%s" % _qs,
                headers=req.headers,
                extra_environ=test_env["extra_environ_app"],
                status=200,
            )
            test_env["requests_session_app"].cookies.update(
                testapp_app.cookies
            )  # update the session with the cookies from the response

            # status is '200 OK'
            # return in a format tailored for `requests`
            return (int(res.status.split(" ")[0]), res.headers, res.body)

        def callback__app_fetch_protected_resource(req, test_env=test_env):
            """/application/account/fetch-protected-resource is visited by the USER"""
            (_path, _qs) = parse_request_simple(req)

            testapp_app = test_env["testapp_app"]
            res = testapp_app.get(
                "/application/account/fetch-protected-resource",
                headers=req.headers,
                extra_environ=test_env["extra_environ_app"],
                status=200,
            )
            test_env["requests_session_app"].cookies.update(
                testapp_app.cookies
            )  # update the session with the cookies from the response

            # status is '200 OK'
            # return in a format tailored for `requests`
            return (int(res.status.split(" ")[0]), res.headers, res.body)

        def callback__authority_protected_resource(req, test_env=test_env):
            """/authority/oauth2/protected_resource is visited by the USER"""
            (_path, _qs) = parse_request_simple(req)

            testapp_authority = test_env["testapp_authority"]
            _headers = string_headers(
                req.headers
            )  # these can end up being unicode in tests
            res = testapp_authority.get(
                "/authority/oauth2/protected_resource",
                headers=_headers,
                extra_environ=test_env["extra_environ_authority"],
                status=200,
            )

            # status is '200 OK'
            # return in a format tailored for `requests`
            return (int(res.status.split(" ")[0]), res.headers, res.body)

        def callback__app_refresh_token(req, test_env=test_env):
            """/application/account/refresh-token is visited by the USER"""
            (_path, _qs) = parse_request_simple(req)

            testapp_app = test_env["testapp_app"]
            res = testapp_app.get(
                "/application/account/refresh-token",
                headers=req.headers,
                extra_environ=test_env["extra_environ_app"],
                status=200,
            )
            test_env["requests_session_app"].cookies.update(
                testapp_app.cookies
            )  # update the session with the cookies from the response

            # status is '200 OK'
            # return in a format tailored for `requests`
            return (int(res.status.split(" ")[0]), res.headers, res.body)

        def callback__app_revoke_token(req, test_env=test_env):
            """/application/account/revoke-token is visited by the USER"""
            (_path, _qs) = parse_request_simple(req)

            testapp_app = test_env["testapp_app"]
            res = testapp_app.get(
                "/application/account/revoke-token",
                headers=req.headers,
                extra_environ=test_env["extra_environ_app"],
                status=200,
            )
            test_env["requests_session_app"].cookies.update(
                testapp_app.cookies
            )  # update the session with the cookies from the response

            # status is '200 OK'
            # return in a format tailored for `requests`
            return (int(res.status.split(" ")[0]), res.headers, res.body)

        def callback__url_revoke_token_post(req):
            assert req.url == oauth2_utils.OAUTH2__URL_AUTHORITY_REVOKE_TOKEN
            payload = dict(parse_qsl(req.body))

            testapp_authority = test_env["testapp_authority"]
            res = testapp_authority.post(
                "/authority/oauth2/revoke_token",
                payload,
                headers=req.headers,
                extra_environ=test_env["extra_environ_authority"],
                status=200,
            )
            test_env["requests_session_authority"].cookies.update(
                testapp_authority.cookies
            )  # update the session with the cookies from the response

            # status is '200 OK'
            # return in a format tailored for `requests`
            return (int(res.status.split(" ")[0]), res.headers, res.body)

        with responses.RequestsMock() as rsps:
            #
            # the following were migrated from mocked requests to webtest
            #
            # rsps.add_callback(
            #    responses.GET, oauth2_utils.OAUTH2__URL_AUTHORITY_FLOWA_AUTHORIZATION,  # https://authority.example.com/authority/oauth2/flow-a/authorization
            #    callback=callback__authorization_base_url,
            # )
            # rsps.add_callback(
            #    responses.POST, oauth2_utils.OAUTH2__URL_AUTHORITY_FLOWA_AUTHORIZATION,  # POST https://authority.example.com/authority/oauth2/flow-a/authorization
            #    callback=callback__authorization_base_url_post,
            # )
            # rsps.add_callback(
            #    responses.GET, oauth2_model.OAUTH2__URL_APP_FLOW_REGISTER_CALLBACK,  # https://app.example.com/application/flow-register/authorized-callback
            #    callback=callback__app_callback,
            # )
            # rsps.add_callback(
            #    responses.GET, oauth2_model.OAUTH2__URL_APP_FLOW_REGISTER_CALLBACK_SUCCESS,  # https://app.example.com/application/flow-register/authorized-callback-success
            #    callback=callback__app_callback_success,
            # )
            rsps.add_callback(
                responses.POST,
                oauth2_model.OAUTH2__URL_AUTHORITY_FLOWA_TOKEN,  # https://authority.example.com/authority/oauth2/flow-a/token
                callback=callback__token_url_post,
            )
            rsps.add_callback(
                responses.GET,
                oauth2_model.OAUTH2__URL_APP_FETCH_PROTECTED_RESOURCE,  # https://app.example.com/application/account/fetch-protected-resource
                callback=callback__app_fetch_protected_resource,
            )
            rsps.add_callback(
                responses.GET,
                oauth2_model.OAUTH2__URL_AUTHORITY_PROTECTED_RESOURCE,  # https://authority.example.com/authority/oauth2/protected_resource
                callback=callback__authority_protected_resource,
            )
            rsps.add_callback(
                responses.POST,
                oauth2_utils.OAUTH2__URL_AUTHORITY_REVOKE_TOKEN,  # 'https://authority.example.com/authority/oauth2/revoke_token',
                callback=callback__url_revoke_token_post,
            )
            rsps.add_callback(
                responses.GET,
                oauth2_model.OAUTH2__URL_APP_REFRESH_TOKEN,  # https://app.example.com/application/account/refresh-token
                callback=callback__app_refresh_token,
            )
            rsps.add_callback(
                responses.GET,
                oauth2_model.OAUTH2__URL_APP_REVOKE_TOKEN,  # https://app.example.com/application/account/revoke-token
                callback=callback__app_revoke_token,
            )

            #
            # actual test flow...
            #

            # first we need to log into the oAuth2 Authority
            # the authority is the account which will be the oAuth identity provider (e.g. Facebook)

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
            assert res.text == (
                "authority|home|user=%s" % oauth2_model.USERID_ACTIVE__AUTHORITY
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
                == """303 See Other\n\nThe resource has been moved to /application/flow-register/oauth2/start; you should be redirected automatically.\n\n"""
            )

            # User is redirected to the oauth2/start page
            res = self.testapp_app.get(
                "/application/flow-register/oauth2/start",
                extra_environ=test_env["extra_environ_app"],
                status=303,
            )
            test_env["requests_session_app"].cookies.update(
                self.testapp_app.cookies
            )  # update the session with the cookies from the response
            assert "Location" in res.headers
            url_authform = res.headers["Location"]
            assert res.headers["Location"].startswith(
                oauth2_utils.OAUTH2__URL_AUTHORITY_FLOWA_AUTHORIZATION
            )

            # Redirect user to the App for authorization
            qs = url_authform.split("?")[1]
            url_authform_local = "/authority/oauth2/flow-a/authorization?%s" % qs
            resAuthInbound = self.testapp_authority.get(
                url_authform_local, extra_environ=test_env["extra_environ_authority"]
            )

            assert (
                '<form action="/authority/oauth2/flow-a/authorization" method="POST" id="app-action-authorize">'
                in resAuthInbound.text
            )

            _csrf = re_csrf.findall(resAuthInbound.text)
            _scope = re_scope.findall(resAuthInbound.text)
            _client_id = re_client_id.findall(resAuthInbound.text)
            _redirect_uri = re_redirect_uri.findall(resAuthInbound.text)
            _response_type = re_response_type.findall(resAuthInbound.text)
            _state = re_state.findall(resAuthInbound.text)

            assert len(_csrf) == 1  # authorize
            assert len(_scope) == 1  # authorize
            assert len(_client_id) == 1  # authorize
            assert len(_redirect_uri) == 1  # authorize
            assert len(_response_type) == 1  # authorize
            assert len(_state) == 1  # authorize

            payload = {
                "csrf_": _csrf[0],
                "scope": _scope[0],
                "client_id": _client_id[0],
                "redirect_uri": _redirect_uri[0],
                "response_type": _response_type[0],
                "state": _state[0],
                "submit": "authorize",
            }

            # payload = {'csrf_': _csrf[0],'scope': _scope[0],'client_id': _client_id[0],'redirect_uri': _redirect_uri[0],'response_type': _response_type[0],'state': _state[0],'submit': 'authorize',}

            # USER submits the form and is sent to the app callback
            resAuthSubmit = self.testapp_authority.post(
                "/authority/oauth2/flow-a/authorization",
                payload,
                extra_environ=test_env["extra_environ_authority"],
                status=302,
            )
            test_env["requests_session_authority"].cookies.update(
                self.testapp_authority.cookies
            )  # update the session with the cookies from the response
            assert "Location" in resAuthSubmit.headers
            url_callback = resAuthSubmit.headers["Location"]
            assert url_callback.startswith(
                oauth2_model.OAUTH2__URL_APP_FLOW_REGISTER_CALLBACK
            )

            # user visits the app callback, is redirected to callback-success
            qs = url_callback.split("?")[1]
            url_callback_local = (
                "/application/flow-register/authorized-callback?%s" % qs
            )
            resAppCallback = self.testapp_app.get(
                url_callback_local,
                payload,
                extra_environ=test_env["extra_environ_app"],
                status=303,
            )
            test_env["requests_session_app"].cookies.update(
                self.testapp_app.cookies
            )  # update the session with the cookies from the response
            assert "Location" in resAppCallback.headers
            url_callback_success = resAppCallback.headers["Location"]
            assert url_callback_success.startswith(
                oauth2_model.OAUTH2__URL_APP_FLOW_REGISTER_CALLBACK_SUCCESS
            )

            url_callback_success_local = (
                "/application/flow-register/authorized-callback-success"
            )
            resAppCallbackSuccess = self.testapp_app.get(
                url_callback_success_local,
                payload,
                extra_environ=test_env["extra_environ_app"],
                status=200,
            )
            test_env["requests_session_app"].cookies.update(
                self.testapp_app.cookies
            )  # update the session with the cookies from the response
            assert (
                resAppCallbackSuccess.text
                == "example_app|authorized-callback-success|user=%s"
                % oauth2_model.USERID_ACTIVE__APPLICATION
            )

            # OK so let's try and view a protected resource?
            # '/OAUTH2__URL_APP_FETCH_PROTECTED_RESOURCE' is a url that will use the application's client token to request a protected resource on the authority.
            resProtectedAttempt = test_env["requests_session_app"].get(
                oauth2_model.OAUTH2__URL_APP_FETCH_PROTECTED_RESOURCE
            )
            assert resProtectedAttempt.status_code == 200
            assert resProtectedAttempt.text == "protected_resource"

            # okay try a refresh
            # the oauth client is on the server, not our commandline.
            # so we visit this page, where it will refresh the token
            resProtectedAttempt = test_env["requests_session_app"].get(
                oauth2_model.OAUTH2__URL_APP_REFRESH_TOKEN
            )
            assert resProtectedAttempt.status_code == 200
            assert resProtectedAttempt.text == "refreshed_token"

            # okay try a revoke
            # the oauth client is on the server, not our commandline.
            # so we visit this page, where it will revoke the token
            resProtectedAttempt = test_env["requests_session_app"].get(
                oauth2_model.OAUTH2__URL_APP_REVOKE_TOKEN
            )
            assert resProtectedAttempt.status_code == 200
            assert resProtectedAttempt.text == "revoked_token"

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

    def test_valid_flow__client_credentials_grant(self):
        """
        This flow mimics the Twitter/Twython oAuth2 login API
        """
        test_env = {
            "testapp_app": self.testapp_app,
            "testapp_authority": self.testapp_authority,
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

        apiClient = oauth2_utils.CustomApiClientB(
            app_key=oauth2_model.OAUTH2__APP_KEY,
            app_secret=oauth2_model.OAUTH2__APP_SECRET,
            oauth_version=2,
        )

        def callback__url_obtain_token__post(req):
            assert req.url == apiClient._url_obtain_token
            payload = dict(parse_qsl(req.body))

            testapp_authority = test_env["testapp_authority"]
            res = testapp_authority.post(
                "/authority/oauth2/flow-b/obtain_token",
                payload,
                headers=req.headers,
                extra_environ=test_env["extra_environ_authority"],
                status=200,
            )
            test_env["requests_session_authority"].cookies.update(
                testapp_authority.cookies
            )  # update the session with the cookies from the response

            # status is '200 OK'
            # return in a format tailored for `requests`
            return (int(res.status.split(" ")[0]), res.headers, res.body)

        def callback__url_obtain_token_alt__post(req):
            assert req.url == apiClient._url_obtain_token_alt
            payload = dict(parse_qsl(req.body))

            testapp_authority = test_env["testapp_authority"]
            res = testapp_authority.post(
                "/authority/oauth2/flow-b/obtain_token_alt",
                payload,
                headers=req.headers,
                extra_environ=test_env["extra_environ_authority"],
                status=200,
            )
            test_env["requests_session_authority"].cookies.update(
                testapp_authority.cookies
            )  # update the session with the cookies from the response

            # status is '200 OK'
            # return in a format tailored for `requests`
            return (int(res.status.split(" ")[0]), res.headers, res.body)

        def callback__url_token_limited__post(req):
            assert req.url == apiClient._url_token_limited
            payload = dict(parse_qsl(req.body))

            testapp_authority = test_env["testapp_authority"]
            res = testapp_authority.post(
                "/authority/oauth2/flow-c/token_limited",
                payload,
                headers=req.headers,
                extra_environ=test_env["extra_environ_authority"],
                status=400,
            )
            test_env["requests_session_authority"].cookies.update(
                testapp_authority.cookies
            )  # update the session with the cookies from the response

            # status is '200 OK'
            # return in a format tailored for `requests`
            return (int(res.status.split(" ")[0]), res.headers, res.body)

        def callback__url_revoke_token_post(req):
            assert req.url == oauth2_utils.OAUTH2__URL_AUTHORITY_REVOKE_TOKEN
            payload = dict(parse_qsl(req.body))

            testapp_authority = test_env["testapp_authority"]
            res = testapp_authority.post(
                "/authority/oauth2/revoke_token",
                payload,
                headers=req.headers,
                extra_environ=test_env["extra_environ_authority"],
                status=200,
            )
            test_env["requests_session_authority"].cookies.update(
                testapp_authority.cookies
            )  # update the session with the cookies from the response

            # status is '200 OK'
            # return in a format tailored for `requests`
            return (int(res.status.split(" ")[0]), res.headers, res.body)

        with responses.RequestsMock() as rsps:

            rsps.add_callback(
                responses.POST,
                apiClient._url_obtain_token,  # https://authority.example.com/authority/oauth2/flow-b/obtain_token
                callback=callback__url_obtain_token__post,
            )

            rsps.add_callback(
                responses.POST,
                apiClient._url_obtain_token_alt,  # https://authority.example.com/authority/oauth2/flow-b/obtain_token_alt
                callback=callback__url_obtain_token_alt__post,
            )

            rsps.add_callback(
                responses.POST,
                apiClient._url_token_limited,  # https://authority.example.com/authority/oauth2/flow-c/token_limited
                callback=callback__url_token_limited__post,
            )

            rsps.add_callback(
                responses.POST,
                oauth2_utils.OAUTH2__URL_AUTHORITY_REVOKE_TOKEN,  # 'https://authority.example.com/authority/oauth2/revoke_token',
                callback=callback__url_revoke_token_post,
            )

            # first get the normal route
            token_result = apiClient.obtain_access_token()
            assert isinstance(token_result, dict)
            assert token_result.get("access_token")

            # ensure there is no refresh_token
            assert token_result.get("refresh_token", None) is None

            # switch these
            apiClient._url_obtain_token = apiClient._url_obtain_token_alt

            # now get the alt route
            token_result = apiClient.obtain_access_token()
            assert isinstance(token_result, dict)
            assert token_result.get("access_token")

            # ensure there is no refresh_token
            assert token_result.get("refresh_token", None) is None

            # User visit
            res = self.testapp_authority.get(
                "/authority/oauth2/flow-b/obtain_token", status=400
            )
            assert "Only `HTTPS` connections are accepted" in res.text
            res = self.testapp_authority.get(
                "/authority/oauth2/flow-b/obtain_token",
                extra_environ=test_env["extra_environ_authority"],
                status=400,
            )
            assert "Only `POST` is accepted." in res.text

            # can we revoke the token?
            token_result = apiClient.revoke_access_token(
                token=token_result.get("access_token")
            )
            assert token_result is True

            # now try the limited endpoint!
            try:
                apiClient._url_obtain_token = apiClient._url_token_limited
                token_result = apiClient.obtain_access_token()
                raise ValueError("we shold not get here")
            except ApiError as exc:
                assert exc.msg == "Unable to obtain OAuth 2 access token."
                assert (
                    exc.original_response.text == '{"error": "unsupported_grant_type"}'
                )
            # if we're here, the right error was logged
