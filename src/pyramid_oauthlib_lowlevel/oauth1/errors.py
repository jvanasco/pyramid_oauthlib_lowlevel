import logging

log = logging.getLogger(__name__)

# stdlib
import json

# pypi
from oauthlib.oauth1.rfc5849.errors import OAuth1Error


# ==============================================================================


class MiscellaneousOAuth1Error(OAuth1Error):
    """
    this extends the OAuth1Error class with a `wrapped_exception`
    """

    error = "oauth1_error"
    wrapped_exception = None

    def __init__(
        self,
        description=None,
        uri=None,
        status_code=400,
        request=None,
        wrapped_exception=None,
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
