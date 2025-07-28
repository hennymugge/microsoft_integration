import base64
import json

import frappe
import jwt
from frappe import _
from frappe.utils import nowdate  # ### NEW: Import nowdate for setting enrollment date
from frappe.utils.oauth import login_oauth_user
from jwt import PyJWKClient

# This is the modern way to handle JWKS key fetching and verification.


@frappe.whitelist(allow_guest=True)
def azure_ad_b2c(*args, **kwargs):
    """
    Handles the OAuth2 callback from Azure AD.
    This function is now upgraded to use modern, secure JWT validation and
    assign LMS Programs based on Entra ID App Roles or Groups.
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
        if not decoded_id_token.get("email"):
            email = decoded_id_token.get("preferred_username") or decoded_id_token.get("upn")
            if email:
                decoded_id_token["email"] = email

        login_oauth_user(decoded_id_token, provider=provider.name, state=state)

        # --- MODIFIED: LMS Program Assignment & Debugging Logic ---
        try:
            # ### NEW: Robust check for roles and groups with clear logging ###
            user_roles = decoded_id_token.get("roles", [])
            user_groups = decoded_id_token.get("groups", [])

            # This log is CRUCIAL for debugging. It will appear in the Error Log UI.
            frappe.log_error(
                title="Entra SSO Token Debug",
                message=f"User {frappe.session.user} logged in. Roles: {user_roles}. Groups: {user_groups}"
            )

            # Prefer App Roles, but fall back to Security Groups if roles are not present.
            ids_to_check = user_roles or user_groups

            if ids_to_check:
                # Use a more generic function name for clarity
                _assign_programs_from_claims(frappe.session.user, ids_to_check)

        except Exception:
            # Log the error but do not block the user's login.
            frappe.log_error(
                frappe.get_traceback(),
                "Failed during LMS Program assignment post-login"
            )
        # --- END MODIFIED LOGIC ---

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
    response.raise_for_status()
    return response.json()


def get_decoded_and_verified_token(token: str, provider: "frappe.Document") -> dict:
    """
    Decodes the JWT ID token and verifies its signature.
    This version is fully dynamic and requires no extra configuration.
    """
    import requests

    base_url = provider.base_url.rstrip("/")
    metadata_url = f"{base_url}/v2.0/.well-known/openid-configuration"

    try:
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

    jwks_client = PyJWKClient(jwks_uri)
    try:
        signing_key = jwks_client.get_signing_key_from_jwt(token)
    except jwt.exceptions.PyJWKClientError as e:
        frappe.log_error(f"Failed to get signing key from JWKS endpoint {jwks_uri}: {e}")
        raise

    decoded_token = jwt.decode(
        token,
        key=signing_key.key,
        algorithms=["RS256"],
        audience=provider.client_id,
        issuer=expected_issuer,
    )

    return decoded_token


# ### MODIFIED: Renamed function and parameter for clarity ###
def _assign_programs_from_claims(user_email: str, claim_ids: list):
    """
    Assigns LMS Programs to a user based on their Entra ID App Roles or Group memberships.

    This function requires a custom DocType named 'LMS Program Entra Group'
    with 'lms_program' and 'entra_group_id' fields.
    """
    if not frappe.db.exists("DocType", "LMS Program"):
        frappe.log_error("Frappe LMS is not installed. Skipping program assignment.")
        return

    if not frappe.db.exists("DocType", "LMS Program Entra Group"):
        frappe.log_error(
            title="Entra SSO Program Sync Failed",
            message="DocType 'LMS Program Entra Group' not found. Please create it to enable auto-assignment."
        )
        return

    try:
        # Find all LMS Programs mapped to the user's claims
        program_mappings = frappe.get_all(
            "LMS Program Entra Group",
            filters={"entra_group_id": ("in", claim_ids)},
            fields=["lms_program"],
            pluck="lms_program",
            distinct=True
        )

        if not program_mappings:
            frappe.log_info(
                f"User {user_email} has claims {claim_ids}, but no matching Program mappings were found.",
                "Entra SSO Program Sync"
            )
            return

        # Enroll the user in each matched program if they aren't already
        for program_name in program_mappings:
            if not frappe.db.exists("Program Enrollment", {"student": user_email, "program": program_name}):
                enrollment_doc = frappe.new_doc("Program Enrollment")
                enrollment_doc.student = user_email
                enrollment_doc.program = program_name
                # ### NEW: Set mandatory enrollment date for safer insert ###
                enrollment_doc.enrollment_date = nowdate()
                enrollment_doc.insert(ignore_permissions=True) # ignore_mandatory is no longer needed
                frappe.log_info(
                    f"Enrolled user {user_email} in program '{program_name}'.",
                    "Entra SSO Program Sync"
                )

        frappe.db.commit()

    except Exception:
        frappe.db.rollback()
        frappe.log_error(frappe.get_traceback(), "LMS Program Auto-Assignment Failed")
