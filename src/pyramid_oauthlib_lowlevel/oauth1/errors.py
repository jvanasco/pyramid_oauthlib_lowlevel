# stdlib
import logging
from typing import Optional

# pypi
from oauthlib.common import Request as oAuth_Request
from oauthlib.oauth1.rfc5849.errors import OAuth1Error

log = logging.getLogger(__name__)


# ==============================================================================


class MiscellaneousOAuth1Error(OAuth1Error):
    """
    this extends the OAuth1Error class with a `wrapped_exception`
    """

    error: str = "oauth1_error"
    wrapped_exception: Optional[Exception] = None

    def __init__(
        self,
        description: Optional[str] = None,
        uri: Optional[str] = None,
        status_code: int = 400,
        request: Optional[oAuth_Request] = None,
        wrapped_exception: Optional[Exception] = None,
    ):
        super(MiscellaneousOAuth1Error, self).__init__(
            description=description, uri=uri, status_code=status_code, request=request
        )
        if wrapped_exception:
            self.wrapped_exception = wrapped_exception


class TemporarilyUnavailableError(MiscellaneousOAuth1Error):
    """
    from: oauthlib.oauth2.rfc6749.errors.TemporarilyUnavailableError
    """

    error = "temporarily_unavailable"
