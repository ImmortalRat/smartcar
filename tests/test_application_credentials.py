"""Test application_credentials."""

from unittest.mock import AsyncMock, MagicMock, patch

from homeassistant.components.application_credentials import ClientCredential
from homeassistant.core import HomeAssistant
import pytest

from custom_components.smartcar.application_credentials import (
    SmartcarAuthImplementation,
    async_get_authorization_server,
    async_get_description_placeholders,
)
from custom_components.smartcar.const import DOMAIN, OAUTH2_TOKEN


@pytest.mark.parametrize(
    ("additional_components", "external_url", "expected_redirect_uri"),
    [
        ([], "https://example.com", "https://example.com/auth/external/callback"),
        ([], None, "https://YOUR_DOMAIN:PORT/auth/external/callback"),
        (["my"], "https://example.com", "https://my.home-assistant.io/redirect/oauth"),
    ],
)
async def test_description_placeholders(
    hass: HomeAssistant,
    additional_components: list[str],
    external_url: str | None,
    expected_redirect_uri: str,
) -> None:
    """Test description placeholders."""
    hass.config.components.update(additional_components)
    hass.config.external_url = external_url
    placeholders = await async_get_description_placeholders(hass)
    assert placeholders == {
        "more_info_url": "https://github.com/wbyoung/smartcar?tab=readme-ov-file#configuration",
        "oauth_creds_url": "https://dashboard.smartcar.com/team/applications",
        "redirect_url": expected_redirect_uri,
    }


async def test_v3_token_request_is_form_encoded(hass: HomeAssistant) -> None:
    """The v3 client credentials request uses a form body, as Smartcar documents."""
    impl = SmartcarAuthImplementation(
        hass,
        DOMAIN,
        ClientCredential("client_abc", "secret"),
        await async_get_authorization_server(hass),
    )
    response = MagicMock(status=200)
    response.json = AsyncMock(
        return_value={
            "access_token": "token",
            "token_type": "Bearer",
            "expires_in": 3600,
        }
    )
    session = MagicMock()
    session.post = AsyncMock(return_value=response)

    with patch(
        "custom_components.smartcar.application_credentials.async_get_clientsession",
        return_value=session,
    ):
        token = await impl._token_request({})

    assert token["access_token"] == "token"  # noqa: S105
    assert token["refresh_token"] is None
    args, kwargs = session.post.call_args
    assert args == (OAUTH2_TOKEN,)
    assert "json" not in kwargs
    assert kwargs["data"] == {
        "client_id": "client_abc",
        "client_secret": "secret",
        "grant_type": "client_credentials",
    }
