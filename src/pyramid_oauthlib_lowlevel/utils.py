# stdlib
from functools import wraps
import logging
import os
from typing import Any
from typing import Callable
from typing import Dict
from typing import Tuple
from typing import Union

# from typing import TYPE_CHECKING

# pypi
from pyramid.httpexceptions import HTTPSeeOther
from pyramid.request import Request
from pyramid.response import Response
from sqlalchemy.orm import scoped_session
from sqlalchemy.orm.session import Session

# local
from .errors import BackendError

# ==============================================================================

TYPES_RESPONSE = Union[Response, HTTPSeeOther]
TYPES_SESSION_OPTIONAL = Union[Session, scoped_session, None]

TYPE_EXTRACTED_PARAMS = Tuple[str, str, Dict, Dict]

# ==============================================================================

log = logging.getLogger(__name__)


# this is made available for ease of debugging unittests
# `export PYRAMID_OAUTHLIB_LOWLEVEL__PRINT_ERRORS=1`
PRINT_ERRORS = bool(int(os.getenv("PYRAMID_OAUTHLIB_LOWLEVEL__PRINT_ERRORS", 0)))


# ==============================================================================


def native_(s, encoding="latin-1", errors="strict"):
    return s


def oauth1_to_pyramid_Response(ret) -> Response:
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
    for k, v in ret[0].items():
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


def string_headers(headers: Dict) -> Dict:
    rval: Dict = {}
    for name, value in headers.items():
        if isinstance(name, bytes):
            name = name.decode("latin-1")
        if isinstance(value, bytes):
            value = value.decode("latin-1")
        rval[name] = value
    return rval


def bytes_headers(headers: Dict) -> Dict:
    rval: Dict = {}
    for name, value in headers.items():
        if isinstance(name, str):
            name = name.encode()
        if isinstance(value, str):
            value = value.encode()
        rval[name] = value
    return rval


def create_response(headers: Dict, body: str, status: int) -> Response:
    """
    Originally from flask-oauthlib
    Extract request params.

    flask-oauthlib::

        response = Response(body or '')
        for (k, v) in headers.items():
            response.headers[str(k)] = v
        response.status_code = status

    pyramid_oauthlib::

        return Response(
            body=body,
            status=status,
            headers={native_(name, encoding='latin-1'): native_(value, encoding='latin-1')
                     for name, value
                     in headers.items()
                     }
        )

    the flask version works for OAuth1 under Pyramid, but not OAuth2
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


def extract_params(pyramid_request: "Request") -> TYPE_EXTRACTED_PARAMS:
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


def catch_backend_failure(f: Callable) -> Callable:
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
