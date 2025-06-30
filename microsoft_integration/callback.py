import base64
import json

import frappe
import jwt
from frappe import _
from frappe.utils.oauth import login_oauth_user
from jwt import PyJWKClient

# This is the modern way to handle JWKS key fetching and verification.


@frappe.whitelist(allow_guest=True)
def azure_ad_b2c(*args, **kwargs):
    """
    Handles the OAuth2 callback from Azure AD.
    This function is now upgraded to use modern, secure JWT validation.
    """
    try:
        # 1. Decode the state parameter sent back by Azure
        state_str = kwargs.get("state")
        if not state_str:
            frappe.throw(_("State missing from OAuth2 callback."), title=_("Invalid Request"))

        state = json.loads(base64.b64decode(state_str).decode("utf-8"))
        if not state.get("token"):
            frappe.throw(_("CSRF Token missing from state."), title=_("Invalid Request"))

        # 2. Get the Social Login Key configuration from Frappe
        # The name "azure_ad_b2c" is derived from the "Provider Name" field in the doctype.
        # Frappe converts "Azure AD B2C" to "azure_ad_b2c".
        provider_name = frappe.get_conf().get("azure_provider_key", "azure_ad_b2c")
        provider = frappe.get_doc("Social Login Key", provider_name)

        # 3. Exchange the authorization code for an access token
        token_response = exchange_code_for_token(kwargs.get("code"), provider)
        id_token = token_response.get("id_token")

        if not id_token:
            frappe.throw(
                _("ID Token not found in response from provider. Response: {0}").format(
                    json.dumps(token_response)
                ),
                title=_("Login Failed"),
            )

        # 4. Decode and securely verify the ID Token
        decoded_id_token = get_decoded_and_verified_token(id_token, provider)

        # 5. Prepare user info and log the user in
        # Handle cases where email might be in 'preferred_username' or 'upn'
        if not decoded_id_token.get("email"):
            email = decoded_id_token.get("preferred_username") or decoded_id_token.get("upn")
            if email:
                decoded_id_token["email"] = email

        login_oauth_user(decoded_id_token, provider=provider.name, state=state)

    except jwt.exceptions.PyJWTError as e:
        frappe.log_error(f"JWT Validation Failed: {e}", "Azure AD Login")
        frappe.respond_as_web_page(
            _("Authentication Failed"),
            _("Could not validate the login token. Please contact your administrator."),
            http_status_code=401,
        )
    except Exception as e:
        frappe.log_error(frappe.get_traceback(), "Azure AD Login")
        frappe.respond_as_web_page(
            _("An Error Occurred"),
            _("Something went wrong during the login process. Please try again."),
            http_status_code=500,
        )


def exchange_code_for_token(code: str, provider: "frappe.Document") -> dict:
    """Exchanges the authorization code for an access token and ID token."""
    import requests

    scope = json.loads(provider.auth_url_data).get("scope")
    data = {
        "grant_type": "authorization_code",
        "client_id": provider.client_id,
        "scope": scope,
        "code": code,
        "redirect_uri": provider.redirect_url,
        "client_secret": provider.get_password("client_secret"),
    }
    
    token_url = provider.base_url + provider.access_token_url
    
    response = requests.post(url=token_url, data=data)
    response.raise_for_status()  # Will raise an exception for 4xx/5xx errors
    return response.json()


def get_decoded_and_verified_token(token: str, provider: "frappe.Document") -> dict:
    """
    Decodes the JWT ID token and verifies its signature.
    This version is fully dynamic and requires no extra configuration.
    It fetches the expected issuer from Microsoft's OIDC metadata endpoint.
    """
    import requests

    # 1. Construct the OIDC metadata URL from the provider's Base URL
    #    e.g., https://login.microsoftonline.com/{tenant}/ -> https://login.microsoftonline.com/{tenant}/v2.0/.well-known/openid-configuration
    #    The v2.0 endpoint is standard for modern auth.
    base_url = provider.base_url.rstrip("/")
    metadata_url = f"{base_url}/v2.0/.well-known/openid-configuration"

    try:
        # 2. Fetch the metadata and extract the expected issuer and jwks_uri
        metadata_response = requests.get(metadata_url, timeout=5)
        metadata_response.raise_for_status()
        oidc_metadata = metadata_response.json()
        
        expected_issuer = oidc_metadata.get("issuer")
        jwks_uri = oidc_metadata.get("jwks_uri")

        if not expected_issuer or not jwks_uri:
            raise ValueError("Issuer or JWKS URI not found in OIDC metadata.")

    except (requests.exceptions.RequestException, ValueError) as e:
        frappe.log_error(f"Failed to fetch or parse OIDC metadata from {metadata_url}: {e}")
        frappe.throw(_("Could not retrieve authentication provider's configuration. Please contact administrator."))

    # 3. Use the dynamically fetched jwks_uri to get the signing key
    jwks_client = PyJWKClient(jwks_uri)
    try:
        signing_key = jwks_client.get_signing_key_from_jwt(token)
    except jwt.exceptions.PyJWKClientError as e:
        frappe.log_error(f"Failed to get signing key from JWKS endpoint {jwks_uri}: {e}")
        raise

    # 4. Decode the token, validating against the dynamically fetched issuer
    decoded_token = jwt.decode(
        token,
        key=signing_key.key,
        algorithms=["RS256"],
        audience=provider.client_id,
        issuer=expected_issuer,
    )

    return decoded_token