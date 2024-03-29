"""This is an alternate implementation.  proxies are used to make interfaces compliant"""

# stdlib
import datetime
from typing import List
from typing import Optional

# pypi
import sqlalchemy as sa
from sqlalchemy import Engine
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column
from sqlalchemy.orm import Session

# ==============================================================================

# we'll use these in a few places...
OAUTH1__APP_KEY = "OAUTH1APPKEYOAUTH1APPKEYOAUTH1APPKEYOAUTH1APPKEY"
OAUTH1__APP_SECRET = "OAUTH1__APP_SECRET"
OAUTH1__APP_ID = 99
OAUTH1__APP_NAME = "example-app"
OAUTH1__URL_APP_FLOW_REGISTER = "https://app.example.com/application/flow-register"
OAUTH1__URL_APP_FLOW_REGISTER_OAUTH_START = (
    "https://app.example.com/application/flow-register/oauth/start"
)
OAUTH1__URL_APP_FLOW_REGISTER_CALLBACK = (
    "https://app.example.com/application/flow-register/authorized-callback"
)
OAUTH1__URL_APP_FLOW_REGISTER_CALLBACK_SUCCESS = (
    "https://app.example.com/application/flow-register/authorized-callback-success"
)
OAUTH1__URL_AUTHORITY_AUTHENTICATE = (
    "https://authority.example.com/authority/oauth1/authorize"
)
OAUTH1__URL_AUTHORITY_ACCESS_TOKEN = (
    "https://authority.example.com/authority/oauth1/access_token"
)
OAUTH1__URL_AUTHORITY_REQUEST_TOKEN = (
    "https://authority.example.com/authority/oauth1/request_token"
)


USERID_ACTIVE__APPLICATION = 47
USERID_ACTIVE__AUTHORITY = 42


# ==============================================================================


# mymetadata = MetaData()
# Base = declarative_base(metadata=mymetadata)
# Base: DeclarativeMeta = declarative_base()
class Base(DeclarativeBase):
    pass


# ==============================================================================


class Useraccount(Base):
    __tablename__ = "useraccount"
    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True)


class DeveloperApplication(Base):
    """
    This implements the `Client` inerface

    flask-oauthlib states:

    # required
        client_key: A random string
        client_secret: A random string
        redirect_uris: A list of redirect uris
        default_redirect_uri: One of the redirect uris
        default_realms: Default realms/scopes of the client
    # optional
        validate_realms: A function to validate realms

    """

    __tablename__ = "developer_application"
    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True)
    is_active: Mapped[Optional[bool]] = mapped_column(
        sa.Boolean, nullable=True, default=True
    )
    useraccount_id__owner: Mapped[int] = mapped_column(
        sa.Integer, sa.ForeignKey("useraccount.id"), nullable=True
    )
    timestamp_created: Mapped[datetime.datetime] = mapped_column(
        sa.DateTime, nullable=False
    )
    app_name_unique: Mapped[str] = mapped_column(sa.Unicode(32), nullable=False)
    app_description: Mapped[str] = mapped_column(sa.Unicode(200), nullable=False)
    app_website: Mapped[str] = mapped_column(sa.Unicode(200), nullable=False)
    app_scope: Mapped[Optional[str]] = mapped_column(sa.Unicode(200), nullable=True)
    callback_url: Mapped[Optional[str]] = mapped_column(sa.Unicode(200), nullable=True)

    app_keyset_active = sa.orm.relationship(
        "DeveloperApplication_Keyset",
        primaryjoin="and_(DeveloperApplication.id==DeveloperApplication_Keyset.developer_application_id, DeveloperApplication_Keyset.is_active==True)",
        uselist=False,
        viewonly=True,
    )
    app_keys_all = sa.orm.relationship(
        "DeveloperApplication_Keyset",
        primaryjoin="DeveloperApplication.id==DeveloperApplication_Keyset.developer_application_id",
        order_by="DeveloperApplication_Keyset.id.desc()",
        viewonly=True,
    )

    @property
    def client_key(self) -> str:
        """compatibility with `OAuth1Server_Client`"""
        return self.app_keyset_active.consumer_key

    @property
    def client_secret(self) -> str:
        """compatibility with `OAuth1Server_Client`"""
        return self.app_keyset_active.consumer_secret

    @property
    def redirect_uris(self) -> List[Optional[str]]:
        """compatibility with `OAuth1Server_Client`"""
        return [self.callback_url]

    @property
    def default_redirect_uri(self) -> Optional[str]:
        """compatibility with `OAuth1Server_Client`"""
        return self.callback_url

    @property
    def default_realms(self) -> List[str]:
        """compatibility with `OAuth1Server_Client`
        oauthlib wants to READONLY an array of realms, the db wants a string,"""
        if self.app_scope:
            return self.app_scope.split(" ")
        return ["platform.actor"]

    # def validate_realms(self, ??): a function to validate realms


class DeveloperApplication_Keyset(Base):
    __tablename__ = "developer_application_keyset"
    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True)
    developer_application_id: Mapped[int] = mapped_column(
        sa.Integer, sa.ForeignKey("developer_application.id"), nullable=False
    )
    is_active: Mapped[Optional[bool]] = mapped_column(
        sa.Boolean, nullable=True, default=True
    )
    timestamp_created: Mapped[datetime.datetime] = mapped_column(
        sa.DateTime, nullable=False
    )
    timestamp_deactivated: Mapped[Optional[datetime.datetime]] = mapped_column(
        sa.DateTime, nullable=True
    )
    consumer_key: Mapped[str] = mapped_column(sa.Unicode(64), nullable=False)
    consumer_secret: Mapped[str] = mapped_column(sa.Unicode(64), nullable=False)

    developer_application = sa.orm.relationship(
        "DeveloperApplication",
        primaryjoin="DeveloperApplication.id==DeveloperApplication_Keyset.developer_application_id",
        uselist=False,
    )


class Developer_oAuth1Server_TokenRequest(Base):
    """
    flask-oauthlib states:
        Request token is designed for exchanging access token. Verifier token is designed to verify the current user.
        It is always suggested that you combine request token and verifier together.

        The request token should contain:

            client: Client associated with this token
            token: Access token
            secret: Access token secret
            realms: Realms with this access token
            redirect_uri: A URI for redirecting

        The verifier should contain:

            verifier: A random string for verifier
            user: The current user
    """

    __tablename__ = "developer__oauth1_server__token_request"
    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True)
    developer_application_id: Mapped[int] = mapped_column(
        sa.Integer, sa.ForeignKey("developer_application.id"), nullable=False
    )
    useraccount_id: Mapped[int] = mapped_column(
        sa.Integer, sa.ForeignKey("useraccount.id"), nullable=True
    )
    timestamp_created: Mapped[datetime.datetime] = mapped_column(
        sa.DateTime, nullable=False
    )
    timestamp_expires: Mapped[Optional[datetime.datetime]] = mapped_column(
        sa.DateTime, nullable=True
    )
    _realms: Mapped[str] = mapped_column(sa.Unicode(255), nullable=False)
    oauth_token: Mapped[str] = mapped_column(sa.Unicode(1000), nullable=False)
    oauth_token_secret: Mapped[str] = mapped_column(sa.Unicode(1000), nullable=False)
    oauth_verifier: Mapped[Optional[str]] = mapped_column(
        sa.Unicode(1000), nullable=True
    )
    oauth_version: Mapped[str] = mapped_column(
        sa.Unicode(5), nullable=False, default="1"
    )
    redirect_uri: Mapped[str] = mapped_column(sa.Unicode(255), nullable=False)
    oauth_callback_confirmed: Mapped[str] = mapped_column(
        sa.Unicode(1000), nullable=False
    )
    is_rejected: Mapped[Optional[bool]] = mapped_column(
        sa.Boolean, nullable=True, default=None
    )
    is_active: Mapped[Optional[bool]] = mapped_column(
        sa.Boolean, nullable=True, default=True
    )

    client = sa.orm.relationship(
        "DeveloperApplication",
        primaryjoin="Developer_oAuth1Server_TokenRequest.developer_application_id==DeveloperApplication.id",
        viewonly=True,
    )

    # only on verifier
    user = sa.orm.relationship(
        "Useraccount",
        primaryjoin="Developer_oAuth1Server_TokenRequest.useraccount_id==Useraccount.id",
        viewonly=True,
    )

    @property
    def realms(self) -> List[str]:
        """oauthlib wants to READONLY an array of realms, the db wants a string"""
        return self._realms.split(" ")

    @property
    def client_key(self) -> str:
        """oauthlib wants a `client_key` available on the token"""
        return self.client.app_keyset_active.consumer_key

    @property
    def token(self) -> str:
        """oauthlib wants a `token`, but we want to store 'oauth_token`"""
        return self.oauth_token

    @property
    def secret(self) -> str:
        """oauthlib wants a `secret`, but we want to store 'oauth_token_secret`"""
        return self.oauth_token_secret

    @property
    def verifier(self) -> Optional[str]:
        """oauthlib wants a `verifier`, but we want to store 'oauth_verifier`"""
        return self.oauth_verifier


class Developer_oAuth1Server_Nonce(Base):
    """
    flask-oauthlib states:
        Timestamp and nonce is a token for preventing repeating requests, it can store these information:

            client_key: The client/consure key
            timestamp: The oauth_timestamp parameter
            nonce: The oauth_nonce parameter
            request_token: Request token string, if any
            access_token: Access token string, if any

        The timelife of a timestamp and nonce is 60 senconds, put it in a cache please.
    """

    __tablename__ = "developer__oauth1_server__nonce"
    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True)
    timestamp_created: Mapped[datetime.datetime] = mapped_column(
        sa.Integer, nullable=False
    )
    nonce: Mapped[str] = mapped_column(sa.Unicode(40), nullable=False)
    developer_application_id: Mapped[int] = mapped_column(
        sa.Integer, sa.ForeignKey("developer_application.id"), nullable=False
    )
    request_token: Mapped[Optional[str]] = mapped_column(sa.Unicode(64), nullable=True)
    access_token: Mapped[Optional[str]] = mapped_column(sa.Unicode(64), nullable=True)

    client = sa.orm.relationship(
        "DeveloperApplication",
        primaryjoin="Developer_oAuth1Server_Nonce.developer_application_id==DeveloperApplication.id",
        viewonly=True,
    )

    @property
    def timestamp(self) -> datetime.datetime:
        """oauthlib wants `timestamp`"""
        return self.timestamp_created

    @property
    def client_key(self) -> str:
        """
        oauthlib wants a `client_key` available on the token
        this could be mapped via a sqlalchemy AssociationProxy
        """
        return self.client.app_keyset_active.consumer_key


class Developer_oAuth1Server_TokenAccess(Base):
    """
    Flask oauthlib states:
        An access token is the final token that could be use by the client. Client will send access token everytime when it need to access resource.

        A access token requires at least these information:

            client: Client associated with this token
            user: User associated with this token
            token: Access token
            secret: Access token secret
            realms: Realms with this access token
    """

    __tablename__ = "developer__oauth1_server__token_access"
    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True)
    oauth_token: Mapped[str] = mapped_column(sa.Unicode(1000), nullable=False)
    oauth_token_secret: Mapped[str] = mapped_column(sa.Unicode(1000), nullable=False)
    _realms: Mapped[str] = mapped_column(sa.Unicode(255), nullable=False)
    timestamp_created: Mapped[datetime.datetime] = mapped_column(
        sa.DateTime, nullable=False
    )
    token_type: Mapped[str] = mapped_column(
        sa.Unicode(32), nullable=False, default="bearer"
    )
    developer_application_id: Mapped[int] = mapped_column(
        sa.Integer, sa.ForeignKey("developer_application.id"), nullable=False
    )
    useraccount_id: Mapped[int] = mapped_column(
        sa.Integer, sa.ForeignKey("useraccount.id"), nullable=False
    )
    oauth_version: Mapped[str] = mapped_column(
        sa.Unicode(5), nullable=False, default="1"
    )
    timestamp_expired: Mapped[Optional[int]] = mapped_column(sa.Integer, nullable=True)
    is_active: Mapped[Optional[bool]] = mapped_column(
        sa.Boolean, nullable=True, default=True
    )

    client = sa.orm.relationship(
        "DeveloperApplication",
        primaryjoin="Developer_oAuth1Server_TokenAccess.developer_application_id==DeveloperApplication.id",
        viewonly=True,
    )

    user = sa.orm.relationship(
        "Useraccount",
        primaryjoin="Developer_oAuth1Server_TokenAccess.useraccount_id==Useraccount.id",
        viewonly=True,
    )

    @property
    def token(self) -> str:
        """oauthlib wants a `token`, but we want to store 'oauth_token`"""
        return self.oauth_token

    @property
    def secret(self) -> str:
        """oauthlib wants a `secret`, but we want to store 'oauth_token_secret`"""
        return self.oauth_token_secret

    @property
    def realms(self) -> List[str]:
        """oauthlib wants a list"""
        return self._realms.split(" ")


class Developer_oAuth1Client_TokenAccess(Base):
    """
    The client (example application) needs to save the access token for communicating with the server
    """

    __tablename__ = "developer__oauth1_client__token_access"
    id: Mapped[int] = mapped_column(sa.Integer, primary_key=True)
    developer_application_id: Mapped[int] = mapped_column(
        sa.Integer, sa.ForeignKey("developer_application.id"), nullable=False
    )
    useraccount_id: Mapped[int] = mapped_column(
        sa.Integer, sa.ForeignKey("useraccount.id"), nullable=False
    )

    oauth_token: Mapped[str] = mapped_column(sa.Unicode(1000), nullable=False)
    oauth_token_secret: Mapped[str] = mapped_column(sa.Unicode(1000), nullable=False)
    _realms: Mapped[str] = mapped_column(sa.Unicode(255), nullable=False)
    timestamp_created: Mapped[datetime.datetime] = mapped_column(
        sa.DateTime, nullable=False
    )
    token_type: Mapped[str] = mapped_column(
        sa.Unicode(32), nullable=False, default="bearer"
    )
    oauth_version: Mapped[str] = mapped_column(
        sa.Unicode(5), nullable=False, default="1"
    )
    timestamp_expired: Mapped[Optional[int]] = mapped_column(sa.Integer, nullable=True)
    is_active: Mapped[Optional[bool]] = mapped_column(
        sa.Boolean, nullable=True, default=True
    )

    @property
    def realms(self) -> List[str]:
        """oauthlib wants to READONLY an array of realms, the db wants a string"""
        return self._realms.split(" ")


def initialize(engine: "Engine", session: "Session"):
    Base.metadata.create_all(engine)

    # insert users
    user1 = Useraccount(id=USERID_ACTIVE__APPLICATION)
    user2 = Useraccount(id=USERID_ACTIVE__AUTHORITY)
    session.add(user1)
    session.add(user2)
    session.flush()

    # insert our client
    app = DeveloperApplication()
    app.id = OAUTH1__APP_ID
    app.is_active = True
    app.app_name_unique = OAUTH1__APP_NAME
    app.timestamp_created = datetime.datetime.utcnow()
    app.app_description = "description"
    app.app_website = "https://example.com"
    app.app_scope = None
    app.callback_url = OAUTH1__URL_APP_FLOW_REGISTER_CALLBACK
    session.add(app)
    session.flush()

    keyset = DeveloperApplication_Keyset()
    keyset.developer_application_id = OAUTH1__APP_ID
    keyset.is_active = True
    keyset.timestamp_created = datetime.datetime.utcnow()
    keyset.consumer_key = OAUTH1__APP_KEY
    keyset.consumer_secret = OAUTH1__APP_SECRET
    session.add(keyset)

    app.app_keyset_active = keyset
    session.flush()
    session.commit()
