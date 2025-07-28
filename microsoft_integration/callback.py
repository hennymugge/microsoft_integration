import base64
import json

import frappe
import jwt
from frappe import _
from frappe.utils import nowdate
from frappe.utils.oauth import login_oauth_user
from jwt import PyJWKClient


@frappe.whitelist(allow_guest=True)
def azure_ad_b2c(*args, **kwargs):
    """
    Handles OAuth2 callback from Azure AD.
    - Assigns Frappe Roles based on Entra App Roles (permissions).
    - Enrolls users in LMS Programs based on Entra Groups (courses).
    - Uses a settings doctype for configuration.
    """
    try:
        # 1. Decode state parameter
        state_str = kwargs.get("state")
        if not state_str:
            frappe.throw(_("State missing from OAuth2 callback."), title=_("Invalid Request"))
        state = json.loads(base64.b64decode(state_str).decode("utf-8"))
        if not state.get("token"):
            frappe.throw(_("CSRF Token missing from state."), title=_("Invalid Request"))

        # 2. Get Social Login Key configuration
        provider_name = frappe.get_conf().get("azure_provider_key", "azure_ad_b2c")
        provider = frappe.get_doc("Social Login Key", provider_name)

        # 3. Exchange authorization code for token
        token_response = exchange_code_for_token(kwargs.get("code"), provider)
        id_token = token_response.get("id_token")
        if not id_token:
            frappe.throw(_("ID Token not found."), title=_("Login Failed"))

        # 4. Decode and verify the ID Token
        decoded_id_token = get_decoded_and_verified_token(id_token, provider)

        # 5. Prepare user info and log in
        if not decoded_id_token.get("email"):
            email = decoded_id_token.get("preferred_username") or decoded_id_token.get("upn")
            if email:
                decoded_id_token["email"] = email
        login_oauth_user(decoded_id_token, provider=provider.name, state=state)

        # --- DUAL-PURPOSE ASSIGNMENT LOGIC ---
        user_roles = decoded_id_token.get("roles", [])
        user_groups = decoded_id_token.get("groups", [])
        user_email = frappe.session.user

        frappe.log_error(
            title="Entra SSO Token Debug",
            message=f"User {user_email} logged in. Roles: {user_roles}. Groups: {user_groups}"
        )

        # Handle Frappe Role assignment based on App Roles
        _assign_frappe_roles(user_email, user_roles)

        # Handle LMS Program enrollment based on Groups
        if user_groups:
            _enroll_in_programs(user_email, user_groups)

    except jwt.exceptions.PyJWTError as e:
        frappe.log_error(f"JWT Validation Failed: {e}", "Azure AD Login")
        frappe.respond_as_web_page(_("Authentication Failed"), _("Invalid login token."), http_status_code=401)
    except Exception:
        frappe.log_error(frappe.get_traceback(), "Azure AD Login")
        frappe.respond_as_web_page(_("An Error Occurred"), _("Login process failed."), http_status_code=500)


def _assign_frappe_roles(user_email: str, entra_app_roles: list):
    """
    Assigns/removes Frappe Roles based on a user's Entra App Roles.
    If no specific roles are matched, assigns a default role from the Microsoft Integration Settings page.
    """
    if not frappe.db.exists("DocType", "Frappe Role Entra Role"):
        frappe.log_error("DocType 'Frappe Role Entra Role' not found. Skipping Frappe Role assignment.")
        return

    try:
        user = frappe.get_doc("User", user_email)
        
        roles_to_assign = frappe.get_all(
            "Frappe Role Entra Role",
            filters={"entra_app_role": ("in", entra_app_roles)},
            pluck="frappe_role",
            distinct=True
        )

        default_role = frappe.db.get_single_value("Microsoft Integration Settings", "default_sso_role")
        if default_role and not roles_to_assign:
            roles_to_assign.append(default_role)

        all_managed_roles = frappe.get_all("Frappe Role Entra Role", pluck="frappe_role", distinct=True)
        if default_role and default_role not in all_managed_roles:
            all_managed_roles.append(default_role)

        current_roles = {r.role for r in user.get("roles")}
        roles_to_add = set(roles_to_assign) - current_roles
        roles_to_remove = (set(all_managed_roles) & current_roles) - set(roles_to_assign)

        needs_save = False
        if roles_to_remove:
            user.set("roles", [r for r in user.get("roles") if r.role not in roles_to_remove])
            needs_save = True

        if roles_to_add:
            for role_name in roles_to_add:
                user.append("roles", {"role": role_name})
            needs_save = True

        if needs_save:
            user.save(ignore_permissions=True)
            frappe.db.commit()

    except Exception:
        frappe.db.rollback()
        frappe.log_error(frappe.get_traceback(), "Frappe Role Assignment Failed")


def _enroll_in_programs(user_email: str, entra_groups: list):
    """Enrolls a user in LMS Programs based on their Entra Group memberships."""
    if not frappe.db.exists("DocType", "LMS Program"):
        return
    if not frappe.db.exists("DocType", "LMS Program Entra Group"):
        frappe.log_error("DocType 'LMS Program Entra Group' not found. Skipping program enrollment.")
        return
    
    try:
        programs_to_enroll = frappe.get_all(
            "LMS Program Entra Group",
            filters={"entra_group_id": ("in", entra_groups)},
            pluck="lms_program",
            distinct=True
        )

        for program in programs_to_enroll:
            if not frappe.db.exists("Program Enrollment", {"student": user_email, "program": program}):
                enrollment = frappe.new_doc("Program Enrollment")
                enrollment.student = user_email
                enrollment.program = program
                enrollment.enrollment_date = nowdate()
                enrollment.insert(ignore_permissions=True)
        
        frappe.db.commit()
    except Exception:
        frappe.db.rollback()
        frappe.log_error(frappe.get_traceback(), "LMS Program Enrollment Failed")


def exchange_code_for_token(code: str, provider: "frappe.Document") -> dict:
    import requests
    scope = json.loads(provider.auth_url_data).get("scope")
    data = {"grant_type": "authorization_code", "client_id": provider.client_id, "scope": scope, "code": code, "redirect_uri": provider.redirect_url, "client_secret": provider.get_password("client_secret")}
    token_url = provider.base_url + provider.access_token_url
    response = requests.post(url=token_url, data=data)
    response.raise_for_status()
    return response.json()

def get_decoded_and_verified_token(token: str, provider: "frappe.Document") -> dict:
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
    decoded_token = jwt.decode(token, key=signing_key.key, algorithms=["RS256"], audience=provider.client_id, issuer=expected_issuer)
    return decoded_token
