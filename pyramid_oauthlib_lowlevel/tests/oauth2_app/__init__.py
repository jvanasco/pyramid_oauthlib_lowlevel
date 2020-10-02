"""
fake app for tests
"""
import logging

log = logging.getLogger(__name__)

# stdlib
import datetime

# pyramid
from pyramid.config import Configurator
from pyramid.session import SignedCookieSessionFactory

# pypi
import sqlalchemy

# local
from .. import oauth2_model


# ==============================================================================


class AttribSafeContextObj(object):
    "from Pylons https://github.com/Pylons/pylons/blob/master/pylons/util.py"

    def __getattr__(self, name):
        try:
            return object.__getattribute__(self, name)
        except AttributeError:
            log.debug(
                "No attribute called %s found on c object, returning " "empty string",
                name,
            )
            return ""


my_session_factory = SignedCookieSessionFactory("itsaseekreet")


def main(global_config, **settings):
    """This function returns a Pyramid WSGI application."""

    if not settings:
        settings = {"sqlalchemy.url": "sqlite://", "mako.directories": "."}
    config = Configurator(settings=settings)
    config.set_session_factory(my_session_factory)

    # libraries for ease
    config.include("pyramid_formencode_classic")
    config.include("pyramid_mako")

    # authority - account
    config.add_route("authority:account:login-form", "/authority/account/login-form")
    config.add_route(
        "authority:account:login-submit", "/authority/account/login-submit"
    )
    config.add_route("authority:account:home", "/authority/account/home")
    config.add_route("authority:account:logout", "/authority/account/logout")

    # routes
    # these are shared across flows
    config.add_route("whoami", "/whoami")
    config.add_route(
        "authority:oauth2:protected_resource", "/authority/oauth2/protected_resource"
    )
    config.add_route("authority:oauth2:revoke_token", "/authority/oauth2/revoke_token")

    # the oauth2 facebook flow
    config.add_route(
        "authority:oauth2:flow_a:authorization",
        "/authority/oauth2/flow-a/authorization",
    )
    config.add_route("authority:oauth2:flow_a:token", "/authority/oauth2/flow-a/token")

    # this is the twitter flow
    config.add_route(
        "authority:oauth2:flow_b:obtain_token", "/authority/oauth2/flow-b/obtain_token"
    )
    config.add_route(
        "authority:oauth2:flow_b:obtain_token_alt",
        "/authority/oauth2/flow-b/obtain_token_alt",
    )

    # this endpoint does not support client_credentials
    config.add_route(
        "authority:oauth2:flow_c:token_limited",
        "/authority/oauth2/flow-c/token_limited",
    )

    # note supported yet
    # config.add_route("authority:oauth2:token_introspection", "/authority/oauth2/token-introspection")

    # application - account
    config.add_route(
        "application:account:login-form", "/application/account/login-form"
    )
    config.add_route(
        "application:account:login-submit", "/application/account/login-submit"
    )
    config.add_route("application:account:home", "/application/account/home")
    config.add_route("application:account:logout", "/application/account/logout")
    config.add_route(
        "application:account:fetch-protected-resource",
        "/application/account/fetch-protected-resource",
    )
    config.add_route(
        "application:account:refresh-token", "/application/account/refresh-token"
    )
    config.add_route(
        "application:account:revoke-token", "/application/account/revoke-token"
    )

    # application - flow
    config.add_route("application:flow-register", "/application/flow-register")
    config.add_route(
        "application:flow-register:oauth2:start",
        "/application/flow-register/oauth2/start",
    )
    config.add_route(
        "application:flow-register:oauth2:authorized-callback",
        "/application/flow-register/authorized-callback",
    )
    config.add_route(
        "application:flow-register:oauth2:authorized-callback-success",
        "/application/flow-register/authorized-callback-success",
    )

    # model & views
    config.include(".model")
    config.scan(".views")

    # request methods!
    config.add_request_method(
        lambda request: datetime.datetime.utcnow(), "datetime", reify=True
    )
    config.add_request_method(
        lambda request: request.session["active_useraccount_id"]
        if "active_useraccount_id" in request.session
        else None,
        "active_useraccount_id",
        reify=False,
        property=True,
    )  # don't reify because this may change during the request
    config.add_request_method(
        lambda request: AttribSafeContextObj(), "workspace", reify=True
    )

    return config.make_wsgi_app()


if __name__ == "__main__":
    app = main(None)
    # serve(app, host='0.0.0.0', port=6543)
