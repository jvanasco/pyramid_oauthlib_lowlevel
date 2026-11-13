import logging
from base64 import b64encode
from types import SimpleNamespace
from typing import List, Optional
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


@pytest.mark.parametrize(
    ("hint", "stored_type"),
    [
        (None, "refresh_token"),
        ("refresh_token", "access_token"),
        ("unknown", "access_token"),
    ],
)
def test_revocation_searches_supported_token_types(
    hint: Optional[str], stored_type: str
) -> None:
    """Resolve tokens despite missing or inaccurate type hints."""
    hooks = Mock()
    owner = SimpleNamespace(client_id="owner", user=object())
    hooks.token_getter.side_effect = lambda **lookup: (
        owner if lookup.get(f"{stored_type}_str") == "synthetic-token" else None
    )
    validator = OAuth2RequestValidator(Mock(registry=Mock(settings={})), hooks)
    request = Request("https://example.invalid/revoke")
    request.client = SimpleNamespace(client_id="owner")
    validator.revoke_token("synthetic-token", hint, request)
    hooks.token_revoke.assert_called_once_with(owner)


@pytest.mark.parametrize(
    ("confidential", "secret", "token_owner", "status", "revoked"),
    [
        (False, None, "client", 200, True),
        (True, "secret", "client", 200, True),
        (True, "incorrect", "client", 401, False),
        (True, None, "client", 401, False),
        (False, None, "other-client", 200, False),
        (False, None, None, 200, False),
    ],
)
def test_revocation_authenticates_client_and_checks_ownership(
    confidential: bool,
    secret: Optional[str],
    token_owner: Optional[str],
    status: int,
    revoked: bool,
) -> None:
    """Exercise authentication, ownership and repeat requests through OAuthlib."""
    hooks = Mock()
    hooks.client_getter.return_value = SimpleNamespace(
        client_id="client", client_secret="secret", is_confidential=confidential
    )
    token = SimpleNamespace(client_id=token_owner, user=object())
    hooks.token_getter.return_value = token if token_owner else None
    post = {"token": "synthetic-token"}
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    if secret is None:
        post["client_id"] = "client"
    else:
        credentials = b64encode(f"client:{secret}".encode()).decode()
        headers["Authorization"] = f"Basic {credentials}"
    request = Mock(scheme="https", method="POST", headers=headers, POST=post)
    request.current_route_url.return_value = "https://example.invalid/revoke"
    provider = OAuth2Provider(request, hooks, OAuth2RequestValidator)

    assert provider.endpoint__revoke_token().status_int == status
    if revoked:
        hooks.token_revoke.assert_called_once_with(token)
        hooks.token_getter.return_value = None
        assert provider.endpoint__revoke_token().status_int == 200
        hooks.token_revoke.assert_called_once_with(token)
    else:
        hooks.token_revoke.assert_not_called()
        if status == 401:
            hooks.token_getter.assert_not_called()
