import logging

log = logging.getLogger(__name__)

# stdlib
from functools import wraps
import pdb


# pypi, upstream
from oauthlib import oauth2
from oauthlib.oauth2 import Server
from oauthlib.oauth2.rfc6749.endpoints.base import BaseEndpoint
from oauthlib.oauth2.rfc6749.endpoints.base import catch_errors_and_unavailability
from oauthlib.common import add_params_to_uri

# pypi
from pyramid.httpexceptions import HTTPUnauthorized
from pyramid.httpexceptions import HTTPFound
from pyramid.httpexceptions import HTTPSeeOther
from pyramid.httpexceptions import HTTPBadRequest

# local
from .. import utils
from .errors import MiscellaneousOAuth2Error
from .validator import OAuth2RequestValidator
from ..utils import create_response
from ..utils import extract_params


# ==============================================================================


class OAuth2Provider(object):

    # these fields modeled after oauthlib.oauth2.rfc6749.endpoints.base.BaseEndpoint
    _available = True
    _catch_errors = True

    # stash for OAuth1RequestValidator
    _validator_api_hooks = None
    _validator_class = None
    _validator = None

    pyramid_request = None
    server = None  # Server instance

    # misc
    error_uri = "/error"
    confirm_authorization_request__post_only = False

    def __init__(
        self,
        pyramid_request,
        validator_api_hooks=None,
        validator_class=None,
        server_class=Server,
        error_uri=None,
    ):
        """
        Builds a new Provider instance.

        :param pyramid_request: pyramid `request` object.
        :param validator_api_hooks: A subclass of `base_OAuth1RequestValidator_Hooks`
        :param validator_class: A subclass of `OAuth1RequestValidator` or `None`
                                (defaults to OAuth1RequestValidator)
        :param server_class: An endpoint class compatible with an endpoint server
                             from `oauthlib.oauth2.pre_configured`, such as
                             the default of `oauthlib.oauth2.pre_configured.Server`
                             which is also known as `oauthlib.oauth2.Server`.
        """
        self.pyramid_request = pyramid_request
        self._validator_api_hooks = validator_api_hooks
        self._validator_class = validator_class or OAuth2RequestValidator
        if error_uri:
            self.error_uri = error_uri

        self._validator = validator = self._validator_class(
            pyramid_request, validator_api_hooks=self._validator_api_hooks
        )
        self.server = server_class(
            validator,
            token_expires_in=validator.token_expires_in,
            token_generator=validator.token_generator,
            refresh_token_generator=validator.refresh_token_generator,
        )

    def _protected_https_only(self):
        if self.pyramid_request.scheme != "https":
            raise HTTPBadRequest("Only `HTTPS` connections are accepted.")

    def _protected_post_only(self):
        if self.pyramid_request.method != "POST":
            raise HTTPBadRequest("Only `POST` is accepted.")

    def endpoint__validate_authorization_request(self):
        """
        This function will sort the parameters and headers out, and pre validate everything.

        The response will be DICT with the following structure:

            :param scopes: a list of scopes in the request
            :param state: the state toen
            :redirect_uri: uri in the request
            :response_type: response_type in the request
            :client_id: client_id in the request
            :request: an ``oauthlib.Request`` object. it will have a

        Example:
            {'scopes': [u'platform.actor'],
             'state': 'SRO9WFZPJ7jvh0yljF6Ffpup6gZ80y',
             'redirect_uri': 'https://example.com/example-app/authorized-callback',
             'response_type': 'code',
             'client_id': 'OAUTH2APPKEYOAUTH2APPKEYOAUTH2APPKEYOAUTH2APPKEY',
             'request': <oauthlib.Request>,
             }

        If the user approves, they should visit `endpoint__confirm_authorization_request`

        """
        uri, http_method, body, headers = extract_params(self.pyramid_request)

        validity = {}
        if http_method in ("GET", "HEAD"):
            redirect_uri = self.pyramid_request.params.get(
                "redirect_uri", self.error_uri
            )
            log.debug(
                "endpoint__validate_authorization_request GET:HEAD| Found redirect_uri %s.",
                redirect_uri,
            )
            try:
                ret = self.server.validate_authorization_request(
                    uri, http_method, body, headers
                )
                scopes, credentials = ret
                validity["scopes"] = scopes
                validity.update(credentials)

            except oauth2.FatalClientError as exc:
                log.debug(
                    "endpoint__validate_authorization_request GET:HEAD | Fatal client error %r",
                    exc,
                    exc_info=True,
                )
                raise HTTPFound(exc.in_uri(self.error_uri))

            except oauth2.OAuth2Error as exc:
                log.debug(
                    "endpoint__validate_authorization_request GET:HEAD | OAuth2Error: %r",
                    exc,
                    exc_info=True,
                )
                raise HTTPFound(exc.in_uri(redirect_uri))

            except Exception as exc:
                log.critical(
                    "endpoint__validate_authorization_request GET:HEAD | %s", exc
                )
                raise HTTPFound(add_params_to_uri(self.error_uri, {"error": str(exc)}))

            return validity
        else:
            raise HTTPFound(
                add_params_to_uri(self.error_uri, {"error": "request must be GET"})
            )

    def endpoint__confirm_authorization_request(self):
        """
        When consumer confirm the authorization after ``endpoint__validate_authorization_request``

        These are being pulled from the `pyramid_request.params` multidict

        TODO: should these be POST only? The RFC states `endpoint__validate_authorization_request` must be GET, but is silent to this submission
              this can be toggled via `confirm_authorization_request__post_only`
        """
        params_source = self.pyramid_request.params
        if self.confirm_authorization_request__post_only:
            params_source = self.pyramid_request.POST

        scope = params_source.get("scope") or ""
        scopes = scope.split()
        credentials = dict(
            client_id=params_source.get("client_id"),
            redirect_uri=params_source.get("redirect_uri", None),
            response_type=params_source.get("response_type", None),
            state=params_source.get("state", None),
        )
        log.debug("Fetched credentials from request %r.", credentials)
        redirect_uri = credentials.get("redirect_uri")
        log.debug("Found redirect_uri %s.", redirect_uri)

        uri, http_method, body, headers = extract_params(self.pyramid_request)
        try:
            ret = self.server.create_authorization_response(
                uri, http_method, body, headers, scopes, credentials
            )
            log.debug("Authorization successful.")
            return create_response(*ret)

        except oauth2.FatalClientError as exc:
            log.debug("Fatal client error %r", exc, exc_info=True)
            # return redirect(exc.in_uri(self.error_uri))
            return HTTPSeeOther(exc.in_uri(self.error_uri))

        except oauth2.OAuth2Error as exc:
            log.debug("OAuth2Error: %r", exc, exc_info=True)
            # return redirect(exc.in_uri(redirect_uri or self.error_uri))
            return HTTPSeeOther(exc.in_uri(redirect_uri or self.error_uri))

        except Exception as exc:
            log.critical(exc)
            # return redirect(add_params_to_uri(
            #    self.error_uri, {'error': str(exc)}
            # ))
            return HTTPSeeOther(add_params_to_uri(self.error_uri, {"error": str(exc)}))

    def endopoint__token(self, credentials=None):
        """
        handle the token endpoint
        """
        self._protected_https_only()
        self._protected_post_only()

        uri, http_method, body, headers = extract_params(self.pyramid_request)
        try:
            ret = self.server.create_token_response(
                uri, http_method, body, headers, credentials
            )
            log.debug("Authorization successful.")
            return create_response(*ret)
        except Exception as exc:
            print("Exception", exc)
            log.critical(exc)
            return HTTPSeeOther(add_params_to_uri(self.error_uri, {"error": str(exc)}))

    def endpoint__revoke_token(self):
        """
        handle the token endpoint
        """
        self._protected_https_only()
        self._protected_post_only()

        uri, http_method, body, headers = extract_params(self.pyramid_request)
        try:
            ret = self.server.create_revocation_response(
                uri, http_method, body, headers
            )
            log.debug("Revocation successful.")
            return create_response(*ret)
        except Exception as exc:
            print("Exception", exc)
            log.critical(exc)
            return HTTPSeeOther(add_params_to_uri(self.error_uri, {"error": str(exc)}))

    def verify_request(self, scopes):
        """
        used to validate
        """
        uri, http_method, body, headers = extract_params(self.pyramid_request)
        return self.server.verify_request(uri, http_method, body, headers, scopes)
