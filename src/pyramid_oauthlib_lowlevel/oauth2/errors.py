import logging

log = logging.getLogger(__name__)

# stdlib
import json

# pypi, upstream
from oauthlib.oauth2.rfc6749.errors import OAuth2Error


# ==============================================================================


class MiscellaneousOAuth2Error(OAuth2Error):
    """
    this extends the OAuth2Error class with a `wrapped_exception`
    """

    error = "oauth2_error"
    wrapped_exception = None

    def __init__(
        self,
        description=None,
        uri=None,
        state=None,
        status_code=400,
        request=None,
        wrapped_exception=None,
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
