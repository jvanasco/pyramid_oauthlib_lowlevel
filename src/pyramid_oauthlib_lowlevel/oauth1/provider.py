import logging

log = logging.getLogger(__name__)

# pypi, upstream
from oauthlib.oauth1 import WebApplicationServer as Server
from oauthlib.common import to_unicode, add_params_to_uri, urlencode
from oauthlib.oauth1.rfc5849 import errors

# pypi
from pyramid.httpexceptions import HTTPUnauthorized

# local
from .. import utils
from .utils import catch_endpoint_failure
from .errors import MiscellaneousOAuth1Error
from .validator import OAuth1RequestValidator


# ==============================================================================


class OAuth1Provider(object):
    # these fields modeled after oauthlib.oauth2.rfc6749.endpoints.base.BaseEndpoint
    _available = True
    _catch_errors = True

    # stash for OAuth1RequestValidator
    _validator_api_hooks = None
    _validator_class = None
    _validator = None

    pyramid_request = None
    server = None  # Server instance

    def __init__(self, pyramid_request, validator_api_hooks=None, validator_class=None):
        """Builds a new Provider

        :param pyramid_request: pyramid `request` object.
        :param validator_api_hooks: A subclass of `base_OAuth1RequestValidator_Hooks`
        :param validator_class: A subclass of `OAuth1RequestValidator` or None (defaults to OAuth1RequestValidator)
        """
        self.pyramid_request = pyramid_request
        self._validator_api_hooks = validator_api_hooks
        self._validator_class = validator_class or OAuth1RequestValidator

        self._validator = self._validator_class(
            pyramid_request, validator_api_hooks=self._validator_api_hooks
        )
        self.server = Server(self._validator)

    @property
    def available(self):
        # from: oauthlib.oauth2.rfc6749.endpoints.base.BaseEndpoint
        return self._available

    @available.setter
    def available(self, available):
        # from: oauthlib.oauth2.rfc6749.endpoints.base.BaseEndpoint
        self._available = available

    @property
    def catch_errors(self):
        # from: oauthlib.oauth2.rfc6749.endpoints.base.BaseEndpoint
        return self._catch_errors

    @catch_errors.setter
    def catch_errors(self, catch_errors):
        # from: oauthlib.oauth2.rfc6749.endpoints.base.BaseEndpoint
        self._catch_errors = catch_errors

    def extract_params(self):
        """proxy function to utils.extract_params"""
        return utils.extract_params(self.pyramid_request)

    @catch_endpoint_failure
    def endpoint__request_token(self, dbSessionCommit=None):
        """
        actual endpoint logic

        kwargs:
            dbSessionCommit: if provided, will call `commit()` on this dbSession
        """
        uri, http_method, body, headers = utils.extract_params(self.pyramid_request)
        # resp_headers, token, 200
        oauth_response = self.server.create_request_token_response(
            uri, http_method, body, headers, credentials=None
        )
        if dbSessionCommit:
            dbSessionCommit.commit()
        return utils.oauth1_to_pyramid_Response(oauth_response)

    @catch_endpoint_failure
    def endpoint__access_token(self, dbSessionCommit=None, update_access_token=None):
        """
        actual endpoint logic

        kwargs:
            dbSessionCommit: if provided, will call `commit()` on this dbSession
            update_access_token: currently not implemented yet

        TODO: update_access_token
        """
        uri, http_method, body, headers = utils.extract_params(self.pyramid_request)
        credentials = None
        # resp_headers, token, 200
        # oauth_response = self.server.create_access_token_response(uri, http_method, body, headers, credentials, update_access_token=update_access_token)
        oauth_response = self.server.create_access_token_response(
            uri, http_method, body, headers, credentials
        )
        if dbSessionCommit:
            dbSessionCommit.commit()
        return utils.oauth1_to_pyramid_Response(oauth_response)

    def extract__endpoint_authorize_data(self):
        """Returns a dict"""
        try:
            uri, http_method, body, headers = utils.extract_params(self.pyramid_request)
            realms, credentials = self.server.get_realms_and_credentials(
                uri, http_method=http_method, body=body, headers=headers
            )
        except Exception as exc:
            error = MiscellaneousOAuth1Error(
                description="Error extracting oAuth1 params", wrapped_exception=exc
            )
            raise error
        oauth1_data = {
            "uri": uri,
            "http_method": http_method,
            "body": body,
            "headers": headers,
            "realms": realms,
            "credentials": credentials,
        }
        return oauth1_data

    @catch_endpoint_failure
    def endpoint__authorize__authorize(self, oauth1_data=None, dbSessionCommit=None):
        """
        authorize the app
        kwargs:
            `oauth1_data` is object from `extract__endpoint_authorize_data`
            dbSessionCommit: if provided, will call `commit()` on this dbSession
        """
        uri = oauth1_data["uri"]
        http_method = oauth1_data["http_method"]
        body = oauth1_data["body"]
        headers = oauth1_data["headers"]
        realms = oauth1_data["realms"]
        credentials = oauth1_data["credentials"]

        # resp_headers/redirect, None, 302
        oauth_response = self.server.create_authorization_response(
            uri, http_method, body, headers, realms, credentials
        )
        if dbSessionCommit:
            dbSessionCommit.commit()
        return utils.oauth1_to_pyramid_Response(oauth_response)

    def logic__is_authorized(self, realms):
        """
        This checks for a valid oAuth payload for the given `realms`.
        The return value is a tuple of :
            (valid, oauth_request_object)

        A common usage might be:

            oauth1Provider = new_oauth1Provider(request)
            _is_authorized, req = oauth1Provider.logic__is_authorized(['platform.actor', ])
            if not _is_authorized:
                raise pyramid.exceptions.HTTPUnauthorized(body=""" '{"error": "Not Authorized (oAuth Failed)}' """, content_type='application/json')
            request.api_client_info.register__oAuth_developerApp_accessToken(req.client, req.access_token)
            return _is_authorized
        """
        uri, http_method, body, headers = utils.extract_params(self.pyramid_request)
        valid, req = self.server.validate_protected_resource_request(
            uri, http_method, body, headers, realms
        )
        return valid, req
