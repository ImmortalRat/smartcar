"""Test finishing setup for a vehicle connected with the Smartcar mobile SDK."""

from unittest.mock import AsyncMock, patch

from homeassistant import config_entries
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType
import pytest
from pytest_homeassistant_custom_component.common import (
    MockConfigEntry,
    load_json_object_fixture,
)
from pytest_homeassistant_custom_component.test_util.aiohttp import AiohttpClientMocker

from custom_components.smartcar.const import (
    CONF_APPLICATION_ID,
    CONFIGURABLE_SCOPES,
    DOMAIN,
    OAUTH2_TOKEN,
    OAUTH2_TOKEN_LEGACY,
    REQUIRED_SCOPES,
)

from . import MOCK_API_ENDPOINT, MOCK_API_ENDPOINT_LEGACY, setup_added_integration

VEHICLE_ID = "36ab27d0-fd9d-4455-823a-ce30af709ffc"
SELECTED_SCOPES = ["read_odometer"]


def _mock_v3_api(aioclient_mock: AiohttpClientMocker, connections: str) -> None:
    aioclient_mock.post(
        OAUTH2_TOKEN,
        json={
            "access_token": "server-access-token",
            "token_type": "bearer",
            "expires_in": 3600,
        },
    )
    aioclient_mock.get(
        f"{MOCK_API_ENDPOINT}/connections",
        json=load_json_object_fixture(f"api/{connections}.json", DOMAIN),
    )
    aioclient_mock.get(
        f"{MOCK_API_ENDPOINT}/vehicles/{VEHICLE_ID}/signals/vehicleidentification-vin",
        json=load_json_object_fixture("api/get_vin_signal.json", DOMAIN),
    )


def _mock_v2_api(aioclient_mock: AiohttpClientMocker) -> None:
    aioclient_mock.post(
        OAUTH2_TOKEN_LEGACY,
        json={
            "refresh_token": "server-refresh-token",
            "access_token": "server-access-token",
            "type": "Bearer",
            "expires_in": 60,
            "scope": " ".join(REQUIRED_SCOPES + SELECTED_SCOPES),
        },
    )
    aioclient_mock.get(
        f"{MOCK_API_ENDPOINT_LEGACY}/vehicles",
        json={"paging": {"count": 25, "offset": 0}, "vehicles": [VEHICLE_ID]},
    )
    aioclient_mock.get(
        f"{MOCK_API_ENDPOINT_LEGACY}/vehicles/{VEHICLE_ID}/vin",
        json={"vin": "5YJSA1CN5DFP00101"},
    )
    aioclient_mock.get(
        f"{MOCK_API_ENDPOINT_LEGACY}/vehicles/{VEHICLE_ID}",
        json={"id": VEHICLE_ID, "make": "TESLA", "model": "Model S", "year": "2014"},
    )


async def _start_app_link_flow(hass: HomeAssistant) -> dict:
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": config_entries.SOURCE_USER}
    )
    assert result["step_id"] == "webhooks"
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        {
            CONF_APPLICATION_ID: "my-app-id",
            "use_webhooks": False,
            "connected_via_app": True,
        },
    )
    assert result["step_id"] == "scopes"
    return await hass.config_entries.flow.async_configure(
        result["flow_id"],
        {k: k in SELECTED_SCOPES for k in CONFIGURABLE_SCOPES},
    )


@pytest.mark.parametrize("client_id_version", ["v3"])
@pytest.mark.usefixtures("current_request_with_host")
async def test_app_link_v3(
    hass: HomeAssistant,
    aioclient_mock: AiohttpClientMocker,
    mock_smartcar_auth: AsyncMock,
) -> None:
    """A v3 app skips the browser and lists the phone-created connection."""
    result = await _start_app_link_flow(hass)

    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "app_link"
    assert result["description_placeholders"]["redirect_uri"] == (
        "scmy-app-id://exchange"
    )
    assert result["data_schema"].schema == {}

    _mock_v3_api(aioclient_mock, "list_connections")

    with patch("custom_components.smartcar.async_setup_entry", return_value=True):
        result = await hass.config_entries.flow.async_configure(result["flow_id"], {})

    assert result["type"] is FlowResultType.CREATE_ENTRY
    data = result["data"]
    assert data["connected_via_app"] is True
    assert data["token"]["access_token"] == "server-access-token"
    assert "expires_at" in data["token"]
    # client credentials, never an authorization code
    token_call = aioclient_mock.mock_calls[0]
    assert str(token_call[1]) == OAUTH2_TOKEN
    assert token_call[2]["grant_type"] == "client_credentials"


@pytest.mark.parametrize("client_id_version", ["v3"])
@pytest.mark.usefixtures("current_request_with_host")
async def test_app_link_v3_no_vehicles_then_retry(
    hass: HomeAssistant,
    aioclient_mock: AiohttpClientMocker,
    mock_smartcar_auth: AsyncMock,
) -> None:
    """An empty connection list keeps the form open so the user can retry."""
    result = await _start_app_link_flow(hass)
    _mock_v3_api(aioclient_mock, "list_connections_empty")

    result = await hass.config_entries.flow.async_configure(result["flow_id"], {})
    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "app_link"
    assert result["errors"] == {"base": "app_no_vehicles"}

    aioclient_mock.clear_requests()
    _mock_v3_api(aioclient_mock, "list_connections")

    with patch("custom_components.smartcar.async_setup_entry", return_value=True):
        result = await hass.config_entries.flow.async_configure(result["flow_id"], {})
    assert result["type"] is FlowResultType.CREATE_ENTRY


@pytest.mark.parametrize("client_id_version", ["v3"])
@pytest.mark.usefixtures("current_request_with_host")
async def test_app_link_v3_token_rejected(
    hass: HomeAssistant,
    aioclient_mock: AiohttpClientMocker,
    mock_smartcar_auth: AsyncMock,
) -> None:
    """A bad client secret shows an error on the form."""
    result = await _start_app_link_flow(hass)
    aioclient_mock.post(OAUTH2_TOKEN, status=401, json={"error": "invalid_client"})

    result = await hass.config_entries.flow.async_configure(result["flow_id"], {})
    assert result["type"] is FlowResultType.FORM
    assert result["errors"] == {"base": "app_token_failed"}


@pytest.mark.parametrize("client_id_version", ["v2"])
@pytest.mark.usefixtures("current_request_with_host")
async def test_app_link_v2(
    hass: HomeAssistant,
    aioclient_mock: AiohttpClientMocker,
    mock_smartcar_auth: AsyncMock,
) -> None:
    """A v2 app exchanges the code the phone received."""
    result = await _start_app_link_flow(hass)

    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "app_link_v2"

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {"authorization_code": "  "}
    )
    assert result["errors"] == {"authorization_code": "no_authorization_code"}

    _mock_v2_api(aioclient_mock)
    with patch("custom_components.smartcar.async_setup_entry", return_value=True):
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"], {"authorization_code": "phone-code"}
        )

    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["data"]["token"]["refresh_token"] == "server-refresh-token"
    token_call = aioclient_mock.mock_calls[0]
    assert str(token_call[1]) == OAUTH2_TOKEN_LEGACY
    assert token_call[2]["grant_type"] == "authorization_code"
    assert token_call[2]["code"] == "phone-code"
    assert token_call[2]["redirect_uri"] == "scmock-id://exchange"


@pytest.mark.parametrize("client_id_version", ["v2"])
@pytest.mark.parametrize("vehicle_fixture", ["vw_id_4"])
@pytest.mark.usefixtures("current_request_with_host")
async def test_app_link_reauth(
    hass: HomeAssistant,
    mock_config_entry: MockConfigEntry,
    aioclient_mock: AiohttpClientMocker,
    mock_smartcar_auth: AsyncMock,
) -> None:
    """Reauthentication of an app-linked entry also skips the browser."""
    mock_config_entry.add_to_hass(hass)
    hass.config_entries.async_update_entry(
        mock_config_entry,
        data={**mock_config_entry.data, "connected_via_app": True},
    )
    with patch("custom_components.smartcar.async_do_first_refresh", return_value=True):
        await setup_added_integration(hass, mock_config_entry)

    result = await mock_config_entry.start_reauth_flow(hass)
    result = await hass.config_entries.flow.async_configure(result["flow_id"], {})
    assert result["step_id"] == "scopes"
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        {k: k in SELECTED_SCOPES for k in CONFIGURABLE_SCOPES},
    )
    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "app_link_v2"
