"""
This is an alternate implementation. Properties are used to make interfaces compliant.

About our data model
--------------------

The following will refer to the model elements as `Object(tablename)`

    oAuth2 `user`

        This is implemented by `Useraccount(useraccount)` and only requires an `id` field

    oAuth2 `client`

        This is implemented across two tables:
            * `DeveloperApplication(developer_application)`
            * `DeveloperApplication_Keyset(developer_application_keyset)`

        This is done to allow the application's public and/or secret credentials to be rotated.


    `DeveloperApplication` <->





"""

# pypi
import sqlalchemy as sa
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.schema import MetaData

# stdlib
import datetime


# we'll use these in a few places...
OAUTH2__APP_KEY = "OAUTH2APPKEYOAUTH2APPKEYOAUTH2APPKEYOAUTH2APPKEY"
OAUTH2__APP_SECRET = "OAUTH2__APP_SECRET"
OAUTH2__APP_ID = 99
OAUTH2__APP_NAME = "application"
OAUTH2__URL_AUTHORITY_FLOWA_AUTHORIZATION = (
    "https://authority.example.com/authority/oauth2/flow-a/authorization"
)
OAUTH2__URL_AUTHORITY_FLOWA_TOKEN = (
    "https://authority.example.com/authority/oauth2/flow-a/token"
)
OAUTH2__URL_AUTHORITY_FLOWB_TOKEN = (
    "https://authority.example.com/authority/oauth2/flow-b/obtain_token"
)
OAUTH2__URL_AUTHORITY_FLOWB_TOKEN_ALT = (
    "https://authority.example.com/authority/oauth2/flow-b/obtain_token_alt"
)
OAUTH2__URL_AUTHORITY_FLOWC_TOKEN_LIMITED = (
    "https://authority.example.com/authority/oauth2/flow-c/token_limited"
)
OAUTH2__URL_AUTHORITY_REVOKE_TOKEN = (
    "https://authority.example.com/authority/oauth2/revoke_token"
)
OAUTH2__URL_AUTHORITY_PROTECTED_RESOURCE = (
    "https://authority.example.com/authority/oauth2/protected_resource"
)

OAUTH2__URL_APP_FLOW_REGISTER_CALLBACK = (
    "https://app.example.com/application/flow-register/authorized-callback"
)
OAUTH2__URL_APP_FLOW_REGISTER_CALLBACK_SUCCESS = (
    "https://app.example.com/application/flow-register/authorized-callback-success"
)
OAUTH2__URL_APP_FETCH_PROTECTED_RESOURCE = (
    "https://app.example.com/application/account/fetch-protected-resource"
)
OAUTH2__URL_APP_REFRESH_TOKEN = (
    "https://app.example.com/application/account/refresh-token"
)
OAUTH2__URL_APP_REVOKE_TOKEN = (
    "https://app.example.com/application/account/revoke-token"
)

USERID_ACTIVE__APPLICATION = 47
USERID_ACTIVE__AUTHORITY = 42

# ==============================================================================


# mymetadata = MetaData()
# Base = declarative_base(metadata=mymetadata)
Base = declarative_base()


# ==============================================================================


class Useraccount(Base):
    __tablename__ = "useraccount"
    id = sa.Column(sa.Integer, primary_key=True)


class DeveloperApplication(Base):
    """
    This implements the `Client` interface, either directly or through proxies to correlated objects.
    """

    __tablename__ = "developer_application"
    id = sa.Column(sa.Integer, primary_key=True)
    is_active = sa.Column(sa.Boolean, nullable=True, default=True)
    useraccount_id__owner = sa.Column(
        sa.Integer, sa.ForeignKey("useraccount.id"), nullable=True
    )
    timestamp_created = sa.Column(sa.DateTime, nullable=False)
    app_name_unique = sa.Column(sa.Unicode(32), nullable=False)
    app_description = sa.Column(sa.Unicode(200), nullable=False)
    app_website = sa.Column(sa.Unicode(200), nullable=False)
    _default_scopes = sa.Column(
        sa.Unicode(200), nullable=True
    )  # The value of the scope parameter is expressed as a list of space- delimited, case-sensitive strings.
    is_confidential = sa.Column(
        sa.Boolean, nullable=True, default=False
    )  # Flask-oauthlib uses this to implement some RFC details see ``OAuth2RequestValidator.client_authentication_required```
    _redirect_uris = sa.Column(sa.Text, nullable=True)

    # this is used to find the current credentials
    app_keyset_active = sa.orm.relationship(
        "DeveloperApplication_Keyset",
        primaryjoin="and_(DeveloperApplication.id==DeveloperApplication_Keyset.developer_application_id, DeveloperApplication_Keyset.is_active==True)",
        uselist=False,
        viewonly=True,
    )

    # not required, this is just how we instrument all(expired) keys
    app_keys_all = sa.orm.relationship(
        "DeveloperApplication_Keyset",
        primaryjoin="DeveloperApplication.id==DeveloperApplication_Keyset.developer_application_id",
        order_by="DeveloperApplication_Keyset.id.desc()",
        viewonly=True,
    )

    # only required if you need to support client credential
    user = sa.orm.relationship(
        "Useraccount",
        primaryjoin="DeveloperApplication.useraccount_id__owner==Useraccount.id",
        uselist=False,
        viewonly=True,
    )

    @property
    def default_scopes(self):
        """
        store a STRING but must iterate a LIST on the interface
        """
        if self._default_scopes:
            return self._default_scopes.split(" ")
        return []

    # allowed_response_types = ('client', 'token')

    @property
    def redirect_uris(self):
        """
        store a STRING but must iterate a LIST on the interface
        """
        if self._redirect_uris:
            return self._redirect_uris.split(" ")
        return []

    @property
    def default_redirect_uri(self):
        """
        store a STRING LIST but must provide a single string of the first item on the interface.
        """
        return self.redirect_uris[0] if self.redirect_uris else None

    @property
    def client_type(self):
        """
        A string represents if this client is confidential or not.
        This is particular to the flask-oauthlib implementation which this library was ported from.
        """
        if self.is_confidential:
            return "confidential"
        return "public"

    @property
    def client_id(self):
        """
        This is the ``Client.client_id``, which is implemented via ``DeveloperApplication_Keyset.client_id``
        This is the "public" component of the consumer keyset.
        """
        return self.app_keyset_active.client_id

    @property
    def client_secret(self):
        """
        This is the ``Client.client_secret``, which is implemented via ``DeveloperApplication_Keyset.client_secret``
        This is the "private" component of the consumer keyset.
        """
        return self.app_keyset_active.client_secret


class DeveloperApplication_Keyset(Base):
    """
    The keyset (client_id + client_secret) is kept in it's own table.
    Why? This method allows for the secret to be rotated and accessed via the `is_active` flag
    """

    __tablename__ = "developer_application_keyset"
    id = sa.Column(sa.Integer, primary_key=True)
    developer_application_id = sa.Column(
        sa.Integer, sa.ForeignKey("developer_application.id"), nullable=False
    )
    is_active = sa.Column(sa.Boolean, nullable=True, default=True)
    timestamp_created = sa.Column(sa.DateTime, nullable=False)
    timestamp_deactivated = sa.Column(sa.DateTime, nullable=True)
    client_id = sa.Column(sa.Unicode(64), nullable=False)
    client_secret = sa.Column(sa.Unicode(64), nullable=False)

    developer_application = sa.orm.relationship(
        "DeveloperApplication",
        primaryjoin="DeveloperApplication.id==DeveloperApplication_Keyset.developer_application_id",
        uselist=False,
    )


class Developer_OAuth2Server_GrantToken(Base):
    """
    A "Grant Token" is the **TEMPORARY** token which is used in the authorization flow.
    It will be destroyed when the authorization is finished.
    ** THIS IS BEST implemented via a cache, unless bookkeeping is required. ***

        client_id: A random string of client_id
        code: A random string
        user: The authorization user
        scopes: A list of scope
        expires: A datetime.datetime in UTC
        redirect_uri: A URI string
    """

    __tablename__ = "developer__oauth2_server__grant_token"
    id = sa.Column(sa.Integer, primary_key=True)  # numeric
    useraccount_id = sa.Column(
        sa.Integer, sa.ForeignKey("useraccount.id"), nullable=False
    )
    developer_application_id = sa.Column(
        sa.Integer, sa.ForeignKey("developer_application.id"), nullable=False
    )
    code = sa.Column(sa.Unicode(255), nullable=False)
    redirect_uri = sa.Column(sa.String(255))
    timestamp_created = sa.Column(sa.DateTime, nullable=False)
    timestamp_expires = sa.Column(sa.DateTime, nullable=False)
    scope = sa.Column(sa.Unicode(1000), nullable=False)
    is_active = sa.Column(sa.Boolean, nullable=True, default=True)

    developer_application = sa.orm.relationship(
        "DeveloperApplication",
        primaryjoin="Developer_OAuth2Server_GrantToken.developer_application_id==DeveloperApplication.id",
        uselist=False,
    )

    user = sa.orm.relationship(
        "Useraccount",
        primaryjoin="Developer_OAuth2Server_GrantToken.useraccount_id==Useraccount.id",
        viewonly=True,
        uselist=False,
    )

    @property
    def client_id(self):
        """
        This is the ``Client.client_id``, which is implemented via ``DeveloperApplication_Keyset.client_id``
        """
        return self.developer_application.app_keyset_active.client_id

    @property
    def client(self):
        """
        This is the ``Client``, which is implemented via ``DeveloperApplication_Keyset``
        """
        return self.developer_application

    @property
    def scopes(self):
        """
        store a STRING but must iterate a LIST on the interface
        """
        return self.scope.split(" ") if self.scope else []

    @property
    def expires(self):
        """
        The interface expects `expires` but we prefer a `timestamp` prefix on datetime columns.
        """
        return self.timestamp_expires


class Developer_OAuth2Server_BearerToken(Base):
    """
    A "Bearer Token" is the token which is ultimately used by the client.
    There are other token types which can be supported, but "Bearer" is widely used

    Notes:

        refresh-token is not guaranteed

        client_credentials
            A refresh token SHOULD NOT be included.
            https://tools.ietf.org/html/rfc6749#section-4.4.3

        implicit grant
            Access Token Response
            The authorization server MUST NOT issue a refresh token.
            https://tools.ietf.org/html/rfc6749#section-4.2.2

    """

    __tablename__ = "developer__oauth2_server__bearer_token"
    __table_args__ = (
        sa.CheckConstraint("NOT(access_token IS NULL AND refresh_token IS NULL)"),
    )
    id = sa.Column(sa.Integer, primary_key=True)
    useraccount_id = sa.Column(
        sa.Integer, sa.ForeignKey("useraccount.id"), nullable=False
    )
    developer_application_id = sa.Column(
        sa.Integer, sa.ForeignKey("developer_application.id"), nullable=False
    )
    is_active = sa.Column(sa.Boolean, nullable=True, default=True)
    access_token = sa.Column(
        sa.Unicode(255), nullable=True, unique=True
    )  # `payload:access_token`
    refresh_token = sa.Column(
        sa.Unicode(255), nullable=True, unique=False
    )  # `payload:refresh_token`  # not unique because we might recycle these; will be NULL if this is a `client_credentials` grant | https://tools.ietf.org/html/rfc6749#section-4.4.3 states "A refresh token SHOULD NOT be included."
    token_type = sa.Column(
        sa.Unicode(32), nullable=False, default="Bearer"
    )  # `payload:token_type`, unnecessary
    timestamp_created = sa.Column(sa.DateTime, nullable=False)
    timestamp_expires = sa.Column(
        sa.DateTime, nullable=False
    )  # based on `payload:expires_in`
    timestamp_revoked = sa.Column(sa.DateTime, nullable=True)
    scope = sa.Column(
        sa.Unicode(1000), nullable=False
    )  # payload:scope  The value of the scope parameter is expressed as a list of space- delimited, case-sensitive strings.

    # this is some housekeeping for lineage tracking
    grant_type = sa.Column(
        sa.Unicode(32), nullable=True
    )  # could be for a `user` or for the `client`
    original_grant_type = sa.Column(
        sa.Unicode(32), nullable=True
    )  # could be for a `user` or for the `client`

    user = sa.orm.relationship(
        "Useraccount",
        primaryjoin="Developer_OAuth2Server_BearerToken.useraccount_id==Useraccount.id",
        viewonly=True,
        uselist=False,
    )

    developer_application = sa.orm.relationship(
        "DeveloperApplication",
        primaryjoin="Developer_OAuth2Server_BearerToken.developer_application_id==DeveloperApplication.id",
        uselist=False,
    )

    @property
    def client_id(self):
        """
        This is the ``Client.client_id``, which we implement via ``DeveloperApplication_Keyset.client_id``
        """
        return self.developer_application.app_keyset_active.client_id

    @property
    def scopes(self):
        return self.scope.split(" ") if self.scope else []

    @property
    def expires(self):
        """compliance with model"""
        return self.timestamp_expires


class Developer_OAuth2Client_BearerToken(Base):
    """
    A "Bearer Token" is the token which is ultimately used by the client.
    There are other token types which can be supported, but "Bearer" is widely used
    """

    __tablename__ = "developer__oauth2_client__bearer_token"

    # payload = {"token_type": "Bearer", "user_id": 47, "access_token": "B6Qw8Pxcglg3R9Suly9wPRHKEN5bA8", "scope": "platform.actor platform.fun", "expires_in": 3600, "refresh_token": "QkxJKvusVmjg2wZCjdzhfFR1QejphF"}'

    id = sa.Column(sa.Integer, primary_key=True)
    useraccount_id = sa.Column(
        sa.Integer, sa.ForeignKey("useraccount.id"), nullable=False
    )
    access_token = sa.Column(sa.Unicode(255), nullable=True, unique=True)
    refresh_token = sa.Column(
        sa.Unicode(255), nullable=True, unique=False
    )  # not unique because we may recycle these
    scope = sa.Column(sa.Unicode(1000), nullable=False)
    timestamp_created = sa.Column(sa.DateTime, nullable=False)
    timestamp_expires = sa.Column(
        sa.DateTime, nullable=False
    )  # based on `payload:expires_in
    timestamp_revoked = sa.Column(sa.DateTime, nullable=True)
    is_active = sa.Column(sa.Boolean, nullable=True, default=True)

    # this is some housekeeping for lineage tracking
    grant_type = sa.Column(
        sa.Unicode(32), nullable=True
    )  # could be for a `user` or for the `client`
    original_grant_type = sa.Column(
        sa.Unicode(32), nullable=True
    )  # could be for a `user` or for the `client`

    user = sa.orm.relationship(
        "Useraccount",
        primaryjoin="Developer_OAuth2Client_BearerToken.useraccount_id==Useraccount.id",
        viewonly=True,
        uselist=False,
    )

    @property
    def scopes(self):
        return self.scope.split(" ") if self.scope else []

    @property
    def expires(self):
        """compliance with model"""
        return self.timestamp_expires


def initialize(engine, session):
    Base.metadata.create_all(engine)

    user1 = Useraccount(id=USERID_ACTIVE__APPLICATION)
    user2 = Useraccount(id=USERID_ACTIVE__AUTHORITY)
    session.add(user1)
    session.add(user2)
    session.flush()

    # insert our client
    app = DeveloperApplication()
    app.id = OAUTH2__APP_ID
    app.useraccount_id__owner = USERID_ACTIVE__APPLICATION
    app.is_active = True
    app.app_name_unique = OAUTH2__APP_NAME
    app.timestamp_created = datetime.datetime.utcnow()
    app.app_description = "description"
    app.app_website = "https://example.com"
    app._default_scopes = "platform.actor platform.fun"
    app._redirect_uris = OAUTH2__URL_APP_FLOW_REGISTER_CALLBACK
    session.add(app)
    session.flush()

    keyset = DeveloperApplication_Keyset()
    keyset.developer_application_id = OAUTH2__APP_ID
    keyset.is_active = True
    keyset.timestamp_created = datetime.datetime.utcnow()
    keyset.client_id = OAUTH2__APP_KEY
    keyset.client_secret = OAUTH2__APP_SECRET
    session.add(keyset)

    app.keyset = keyset
    session.flush()
    session.commit()
