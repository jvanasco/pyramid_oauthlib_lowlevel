from typing import Dict
from typing import Optional
from typing import TYPE_CHECKING

# pypi
from sqlalchemy import Engine
from sqlalchemy import engine_from_config
from sqlalchemy.orm import configure_mappers
from sqlalchemy.orm import sessionmaker
import zope.sqlalchemy

# import or define all models here to ensure they are attached to the
# Base.metadata prior to any initialization routines

# local
from ... import oauth2_model

if TYPE_CHECKING:
    from pyramid.config import Configurator
    from pyramid.request import Request
    from sqlalchemy.orm import Session
    from transaction import TransactionManager

# ==============================================================================

# run configure_mappers after defining all of the models to ensure
# all relationships can be setup
configure_mappers()


def _get_engine(settings: Dict, prefix="sqlalchemy.") -> Engine:
    # leading underscore, because this can return different engines
    return engine_from_config(settings, prefix)


def get_session_factory(engine: "Engine") -> sessionmaker:
    factory = sessionmaker()
    factory.configure(bind=engine)
    return factory


def get_tm_session(
    request: "Request",
    session_factory: sessionmaker,
    transaction_manager: Optional["TransactionManager"],
) -> "Session":
    """
    Get a ``sqlalchemy.orm.Session`` instance backed by a transaction.

    This function will hook the session to the transaction manager which
    will take care of committing any changes.

    - When using pyramid_tm it will automatically be committed or aborted
      depending on whether an exception is raised.

    - When using scripts you should wrap the session in a manager yourself.
      For example::

          import transaction

          engine = get_engine(settings)
          session_factory = get_session_factory(engine)
          with transaction.manager:
              dbsession = get_tm_session(request, session_factory, transaction.manager)
    """
    dbSession = session_factory()
    zope.sqlalchemy.register(
        dbSession, transaction_manager=transaction_manager, keep_session=True
    )

    if request is not None:

        def _cleanup(request):
            dbSession.close()

        request.add_finished_callback(_cleanup)

    return dbSession


def includeme(config: "Configurator"):
    """
    Initialize the model for a Pyramid app.

    Activate this setup using ``config.include('peter_sslers.models')``.

    """
    settings = config.get_settings()

    # use pyramid_tm to hook the transaction lifecycle to the request
    config.include("pyramid_tm")

    # call this once, so we create the same sqlalchemy engine
    _engine = _get_engine(settings)

    session_factory = get_session_factory(_engine)
    config.registry["dbSession_factory"] = session_factory

    # make request.dbSession available for use in Pyramid
    config.add_request_method(
        # r.tm is the transaction manager used by pyramid_tm
        lambda r: get_tm_session(r, session_factory, r.tm),
        "dbSession",
        reify=True,
    )

    # setup

    # build tables
    oauth2_model.initialize(_engine, session_factory())
