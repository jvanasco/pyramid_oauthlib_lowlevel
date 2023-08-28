# stdlib
import logging
from typing import Optional

# pypi
from oauthlib.common import Request as oAuth_Request
from oauthlib.oauth2.rfc6749.errors import OAuth2Error

log = logging.getLogger(__name__)

# ==============================================================================


class MiscellaneousOAuth2Error(OAuth2Error):
    """
    this extends the OAuth2Error class with a `wrapped_exception`
    """

    error: str = "oauth2_error"
    wrapped_exception: Optional[Exception] = None

    def __init__(
        self,
        description: Optional[str] = None,
        uri: Optional[str] = None,
        state: Optional[str] = None,
        status_code: int = 400,
        request: Optional[oAuth_Request] = None,
        wrapped_exception: Optional[Exception] = None,
    ):
        super(MiscellaneousOAuth2Error, self).__init__(
            description=description,
            uri=uri,
            state=state,
            status_code=status_code,
            request=request,
        )
        if wrapped_exception:
            self.wrapped_exception = wrapped_exception
