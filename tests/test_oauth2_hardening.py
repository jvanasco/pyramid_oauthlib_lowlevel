import logging
from types import SimpleNamespace
from typing import List
from unittest.mock import Mock

from oauthlib.common import Request
from oauthlib.oauth2 import InvalidRequestError
import pytest

from pyramid_oauthlib_lowlevel.oauth2.provider import OAuth2Provider
from pyramid_oauthlib_lowlevel.oauth2.validator import OAuth2RequestValidator


@pytest.mark.parametrize(
    ("required", "allowed"),
    [
        ([], True),
        (["read", "write"], True),
        (["read", "admin"], False),
        (["admin"], False),
    ],
)
def test_bearer_token_requires_all_scopes(
    required: List[str], allowed: bool, caplog: pytest.LogCaptureFixture
) -> None:
    """Check scope enforcement and keep bearer values out of diagnostic logs."""
    hooks = Mock()
    hooks.token_getter.return_value = SimpleNamespace(
        expires=None, scopes=["read", "write"], user=object(), client=object()
    )
    validator = OAuth2RequestValidator(Mock(registry=Mock(settings={})), hooks)
    request = Request("https://example.invalid/resource")
    with caplog.at_level(logging.DEBUG):
        assert (
            validator.validate_bearer_token("synthetic-bearer-value", required, request)
            is allowed
        )
    assert "synthetic-bearer-value" not in caplog.text


@pytest.mark.parametrize(
    ("endpoint", "server_method"),
    [
        ("endopoint__token", "create_token_response"),
        ("endpoint__revoke_token", "create_revocation_response"),
    ],
)
def test_oauth2_endpoint_errors(
    endpoint: str, server_method: str, caplog: pytest.LogCaptureFixture
) -> None:
    """Keep unexpected exception details private and preserve OAuth errors."""
    request = Mock(scheme="https", method="POST", headers={}, POST={})
    request.current_route_url.return_value = "https://example.invalid/oauth"
    provider = OAuth2Provider(
        request, Mock(), OAuth2RequestValidator, server_class=Mock()
    )
    operation = getattr(provider.server, server_method)

    operation.side_effect = RuntimeError("synthetic-internal-detail")
    response = getattr(provider, endpoint)()
    assert response.status_int == 303
    assert response.location == "/error?error=server_error"
    assert "synthetic-internal-detail" not in caplog.text

    operation.side_effect = InvalidRequestError()
    response = getattr(provider, endpoint)()
    assert response.status_int == 400
    assert response.content_type == "application/json"
    assert response.json["error"] == "invalid_request"
