from __future__ import print_function

import logging

log = logging.getLogger(__name__)

# stdlib
import functools
import json
import os

# pypi, upstream
from oauthlib.oauth1.rfc5849.errors import OAuth1Error
from oauthlib.common import urlencode

# local
from .errors import MiscellaneousOAuth1Error
from .errors import TemporarilyUnavailableError
from ..errors import BackendError
from ..utils import create_response


# ==============================================================================


# this is made available for ease of debugging unittests
# `export PYRAMID_OAUTHLIB_LOWLEVEL__PRINT_ERRORS=1`
PRINT_ERRORS = bool(int(os.getenv("PYRAMID_OAUTHLIB_LOWLEVEL__PRINT_ERRORS", 0)))


# ==============================================================================


def oauth_error_json(error):
    """
    the upstream oauthlib `OAuth2Error` has a `json` property that encodes the error data
    this is missing on the `OAuth1Error` object
    """
    return json.dumps(dict(error.twotuples))


def oauth_error_uri(error):
    """
    the upstream oauthlib `OAuth2Error` has a `json` property that encodes the error data
    this is missing on the `OAuth1Error` object
    in this version, the error is urlencoded
    """
    return urlencode(error.twotuples)


def catch_endpoint_failure(f):
    """
    this ports the oauth2 error catching utility `catch_errors_and_unavailability` for oauth1

    400 - Bad request
    401 - Unauthorized
    403 - Forbidden
    500 - Internal Server Error
    503 - Service Unavailable
    """

    @functools.wraps(f)
    def wrapper(endpoint, *args, **kwargs):
        if not endpoint.available:
            _status_code = 503
            exc = TemporarilyUnavailableError(status_code=_status_code)
            log.info("Endpoint unavailable, ignoring request %s." % endpoint)
            return create_response({}, oauth_error_uri(exc), _status_code)

        if endpoint.catch_errors:
            try:
                return f(endpoint, *args, **kwargs)

            except OAuth1Error:
                raise

            except MiscellaneousOAuth1Error:
                raise

            except BackendError as exc:
                # if this is an internal failure
                _status_code = 500
                _message = "Internal System Failure"
                error = MiscellaneousOAuth1Error(
                    _message,  # description
                    wrapped_exception=exc,
                    status_code=_status_code,
                )
                error.error = exc.error  # copy over the error code
                log.warning(
                    "%s(%s) -> MiscellaneousOAuth1Error(%s)"
                    % (exc.__class__.__name__, exc, _message)
                )
                if PRINT_ERRORS:
                    print(
                        "%s(%s) -> MiscellaneousOAuth1Error(%s)"
                        % (exc.__class__.__name__, exc, _message)
                    )
                if exc.wrapped_exception:
                    log.warning("BackendError wraps: %s" % exc.wrapped_exception)
                    if PRINT_ERRORS:
                        print("BackendError wraps: %s" % exc.wrapped_exception)
                    if isinstance(exc.wrapped_exception, OAuth1Error):
                        # raise exc.wrapped_exception
                        error.error = exc.wrapped_exception.error  # copy over the error
                        _status_code = (
                            exc.wrapped_exception.status_code
                        )  # copy over the error
                return create_response({}, oauth_error_uri(error), _status_code)

            except Exception as exc:
                _status_code = 400
                _message = "Exception caught while processing request"
                error = MiscellaneousOAuth1Error(
                    _message,  # description
                    wrapped_exception=exc,
                    status_code=_status_code,
                )
                log.warning(
                    "%s(%s) -> MiscellaneousOAuth1Error(%s)"
                    % (exc.__class__.__name__, exc, _message)
                )
                if PRINT_ERRORS:
                    print(
                        "%s(%s) -> MiscellaneousOAuth1Error(%s)"
                        % (exc.__class__.__name__, exc, _message)
                    )
                return create_response({}, oauth_error_uri(error), _status_code)

        else:
            return f(endpoint, *args, **kwargs)

    return wrapper
