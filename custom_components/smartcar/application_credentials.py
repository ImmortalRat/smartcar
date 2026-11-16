from dataclasses import dataclass
from http import HTTPStatus
import logging
from typing import cast

from homeassistant.components.application_credentials import (
    AuthImplementation,
    AuthorizationServer,
    ClientCredential,
)
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.config_entry_oauth2_flow import (
    AUTH_CALLBACK_PATH,
    MY_AUTH_CALLBACK_PATH,
    AbstractOAuth2Implementation,
)

from .const import OAUTH2_AUTHORIZE, OAUTH2_TOKEN, OAUTH2_TOKEN_LEGACY
from .util import api_version_for_client_id

_LOGGER = logging.getLogger(__name__)


class InvalidTokenResponseError(ValueError):
    """Error to indicate the token response had no bearer access token."""


@dataclass
class SmartcarAuthorizationServer(AuthorizationServer):
    """Represent Smartcar OAuth2 Authorization Server(s)."""

    token_url_v2: str


class SmartcarAuthImplementation(AuthImplementation):
    """Smartcar local OAuth2 implementation."""

    def __init__(
        self,
        hass: HomeAssistant,
        auth_domain: str,
        credential: ClientCredential,
        authorization_server: AuthorizationServer,
    ) -> None:
        """Initialize AuthImplementation."""
        super().__init__(
            hass,
            auth_domain,
            credential,
            authorization_server,
        )

        if api_version_for_client_id(credential.client_id) == "v2":
            self.token_url = authorization_server.token_url_v2

    async def _token_request(self, data: dict) -> dict:
        if api_version_for_client_id(self.client_id) == "v2":
            return cast("dict", await super()._token_request(data))

        # Smartcar documents this endpoint as taking a form-encoded body:
        # https://smartcar.com/docs/api-reference/authorization/request-access-token
        session = async_get_clientsession(self.hass)
        response = await session.post(
            self.token_url,
            data={
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "grant_type": "client_credentials",
            },
        )

        try:
            data = await response.json(content_type=None)
        except ValueError:
            data = None
        if not isinstance(data, dict):
            data = {}

        if response.status >= HTTPStatus.BAD_REQUEST or not (
            str(data.get("token_type", "")).lower() == "bearer"
            and data.get("access_token")
        ):
            # never log the token or the secret; only Smartcar's error fields
            _LOGGER.error(
                "Smartcar token request failed: HTTP %s, error=%s, description=%s",
                response.status,
                data.get("error") or data.get("code"),
                data.get("error_description")
                or data.get("description")
                or data.get("message"),
            )
            response.raise_for_status()
            raise InvalidTokenResponseError

        return {"refresh_token": None, **data}


async def async_get_auth_implementation(
    hass: HomeAssistant,
    auth_domain: str,
    credential: ClientCredential,
) -> AbstractOAuth2Implementation:
    return SmartcarAuthImplementation(
        hass,
        auth_domain,
        credential,
        authorization_server=await async_get_authorization_server(hass),
    )


async def async_get_authorization_server(  # noqa: RUF029
    hass: HomeAssistant,  # noqa: ARG001
) -> AuthorizationServer:
    """Return authorization server details."""
    return SmartcarAuthorizationServer(
        authorize_url=OAUTH2_AUTHORIZE,
        token_url=OAUTH2_TOKEN,
        token_url_v2=OAUTH2_TOKEN_LEGACY,
    )


async def async_get_description_placeholders(  # noqa: RUF029
    hass: HomeAssistant,
) -> dict[str, str]:
    """Return description placeholders for the credentials dialog."""
    if "my" in hass.config.components:
        redirect_url = MY_AUTH_CALLBACK_PATH
    else:
        ha_host = hass.config.external_url or "https://YOUR_DOMAIN:PORT"
        redirect_url = f"{ha_host}{AUTH_CALLBACK_PATH}"
    return {
        "more_info_url": "https://github.com/wbyoung/smartcar?tab=readme-ov-file#configuration",
        "oauth_creds_url": "https://dashboard.smartcar.com/team/applications",
        "redirect_url": redirect_url,
    }
