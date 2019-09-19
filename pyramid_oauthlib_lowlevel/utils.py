from __future__ import print_function

import logging

log = logging.getLogger(__name__)

# stdlib
from functools import wraps
import os

# pyramid
from pyramid.response import Response
from pyramid.compat import native_

# local
from .errors import BackendError

# ==============================================================================


# this is made available for ease of debugging unittests
# `export PYRAMID_OAUTHLIB_LOWLEVEL__PRINT_ERRORS=1`
PRINT_ERRORS = bool(int(os.getenv("PYRAMID_OAUTHLIB_LOWLEVEL__PRINT_ERRORS", 0)))


# ==============================================================================


def oauth1_to_pyramid_Response(ret):
    """
    originally this simply did:

        safe_headers = [(str(i[0]), str(i[1])) for i in ret[0].items()]
        return Response(body=ret[1], status=ret[2], headerlist=safe_headers)

    however, changes to webob necessitated pulling the content-type
    see https://github.com/Pylons/webob/issues/298
    """
    kwargs = {"body": ret[1], "status": ret[2]}
    safe_headers = []
    content_type = None
    charset = None
    for (k, v) in ret[0].items():
        k = str(k)
        v = str(v)
        if k.lower() == "content-type":
            content_type = v
        elif k.lower() == "charset":
            charset = v
        safe_headers.append((k, v))
    if safe_headers:
        kwargs["headerlist"] = safe_headers
    if content_type:
        kwargs["content_type"] = content_type
        if not charset:
            kwargs["charset"] = "UTF-8"
    return Response(**kwargs)


def string_headers(headers):
    return {
        native_(name, encoding="latin-1"): native_(value, encoding="latin-1")
        for name, value in headers.items()
    }


def create_response(headers, body, status):
    """
    originally from flask-oauthlib
    Extract request params.

    flask-oauthlib:
        response = Response(body or '')
        for (k, v) in headers.items():
            response.headers[str(k)] = v
        response.status_code = status

    pyramid_oauthlib:
        return Response(
            body=body,
            status=status,
            headers={native_(name, encoding='latin-1'): native_(value, encoding='latin-1')
                     for name, value
                     in headers.items()
                     }
        )
    the flask version works for oauth1 under pyramid, but not oauth2
    """
    response = Response(
        body=body,
        status=status,
        headers={
            native_(name, encoding="latin-1"): native_(value, encoding="latin-1")
            for name, value in headers.items()
        },
    )
    return response


def extract_params(pyramid_request):
    """
    originally from flask-oauthlib
    Extract pyramid_request params.
    """
    uri = pyramid_request.current_route_url()
    http_method = pyramid_request.method
    headers = dict(pyramid_request.headers)
    if "wsgi.input" in headers:
        del headers["wsgi.input"]
    if "wsgi.errors" in headers:
        del headers["wsgi.errors"]

    body = dict(pyramid_request.POST.items())
    return uri, http_method, body, headers


def catch_backend_failure(f):
    """
    this is used to catch generic backend failures and correctly log/handle them
    """

    @wraps(f)
    def wrapper(hook, *args, **kwargs):
        try:
            return f(hook, *args, **kwargs)

        except Exception as exc:
            if isinstance(exc, BackendError):
                error = exc
            else:
                error = BackendError(wrapped_exception=exc)
                log.debug(
                    "%s(%s) -> BackendError(%s) | %s"
                    % (exc.__class__.__name__, exc, error, hook)
                )
                if PRINT_ERRORS:
                    print(
                        "%s(%s) -> BackendError(%s) | %s"
                        % (exc.__class__.__name__, exc, error, hook)
                    )
            raise error

    return wrapper
