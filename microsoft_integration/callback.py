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
    Decodes the JWT ID token and verifies its signature against Microsoft's public keys.
    This is the upgraded, secure implementation.
    """
    # URL to fetch Microsoft's public signing keys (JWKS). Make it configurable.
    jwks_url = frappe.get_conf().get(
        "microsoft_jwks_url",
        "https://login.microsoftonline.com/common/discovery/v2.0/keys",
    )
    
    # The PyJWKClient handles fetching, caching, and selecting the correct public key.
    jwks_client = PyJWKClient(jwks_url)
    
    try:
        # This one line replaces the entire old manual key lookup loop.
        signing_key = jwks_client.get_signing_key_from_jwt(token)
    except jwt.exceptions.PyJWKClientError as e:
        frappe.log_error(f"Failed to get signing key from JWKS endpoint: {e}")
        raise

    # Now decode the token. This function will automatically:
    # 1. Verify the signature using the `signing_key`.
    # 2. Verify the 'exp' (expiration) and 'nbf' (not before) claims.
    # 3. Verify the 'aud' (audience) claim matches our client_id.
    # 4. Verify the 'iss' (issuer) claim matches the provider's base_url.
    decoded_token = jwt.decode(
        token,
        key=signing_key.key,
        algorithms=["RS256"],
        audience=provider.client_id,
        issuer=provider.base_url,
    )
    
    return decoded_token