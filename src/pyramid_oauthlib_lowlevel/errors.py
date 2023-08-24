# stdlib
from typing import Optional

# ==============================================================================


class BackendError(Exception):
    """
    this is used to catch generic backend failures and correctly log/handle them

    this extends the Exception class with a `wrapped_exception`

    this must derive from the Base exception, otherwise it will not be caught correctly
    """

    error: str = "internal_system_failure"  # error code
    description: str = "Internal System Failure"  # human version
    wrapped_exception: Optional[Exception] = None

    def __init__(
        self,
        description: Optional[str] = None,
        wrapped_exception: Optional[Exception] = None,
    ):
        """
        description:    A human-readable ASCII [USASCII] text providing
                        additional information, used to assist the client
                        developer in understanding the error that occurred.
                        Values for the "error_description" parameter MUST NOT
                        include characters outside the set
                        x20-21 / x23-5B / x5D-7E.
        """
        self.description = description or self.description
        super(BackendError, self).__init__(self.description)
        if wrapped_exception:
            self.wrapped_exception = wrapped_exception
