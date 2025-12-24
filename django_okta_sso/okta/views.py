import os
import secrets
import urllib.parse
import requests
from datetime import timedelta

from django.contrib import messages
from django.contrib.auth import logout as dj_logout
from django.db.models import Count
from django.http import HttpResponseBadRequest
from django.shortcuts import redirect, render
from django.utils import timezone

from .models import SecurityEvent


# ----------------------------
# Config helpers
# ----------------------------
def oidc_cfg():
    """
    OIDC config (recommended env var names to avoid mixing with SAML).
    """
    return {
        "domain": os.getenv("OKTA_DOMAIN"),  # https://trial-xxxx.okta.com
        "client_id": os.getenv("OKTA_OIDC_CLIENT_ID"),
        "client_secret": os.getenv("OKTA_OIDC_CLIENT_SECRET"),
        "redirect_uri": os.getenv("OKTA_OIDC_REDIRECT_URI"),  # http://127.0.0.1:8000/oidc/callback/
        "authz_server": os.getenv("OKTA_AUTHZ_SERVER", "default"),
    }


def saml_cfg():
    return {
        "embed_link": os.getenv("OKTA_SAML_EMBED_LINK"),  # https://.../app/.../sso/saml
    }


def is_authenticated(request) -> bool:
    """
    User is authenticated if either SAML or OIDC markers exist in session.
    """
    return bool(
        request.session.get("google_authenticated")
        or request.session.get("google_userinfo")
        or request.session.get("saml_authenticated")
        or request.session.get("saml_xml")
        or request.session.get("oidc_authenticated")
        or request.session.get("oidc_userinfo")
    )


def auth_method(request) -> str:
    if request.session.get("google_authenticated") or request.session.get("google_userinfo"):
        return "google"
    if request.session.get("oidc_authenticated") or request.session.get("oidc_userinfo"):
        return "oidc"
    if request.session.get("saml_authenticated") or request.session.get("saml_xml"):
        return "saml"
    return "none"


# ----------------------------
# Public: login chooser
# ----------------------------
def login_choice(request):
    # If already authenticated, go straight to SOC dashboard
    if is_authenticated(request):
        return redirect("/soc/")

    return render(request, "login_choice.html")


# ----------------------------
# OIDC login
# ----------------------------

def okta_cfg():
    return {
        "domain": os.getenv("OKTA_DOMAIN"),
        "authz_server": os.getenv("OKTA_AUTHZ_SERVER", "default"),
        "client_id": os.getenv("OKTA_OIDC_CLIENT_ID"),
        "client_secret": os.getenv("OKTA_OIDC_CLIENT_SECRET"),
        "redirect_uri": os.getenv("OKTA_OIDC_REDIRECT_URI"),
    }

def google_cfg():
    return {
        "client_id": os.getenv("GOOGLE_CLIENT_ID"),
        "client_secret": os.getenv("GOOGLE_CLIENT_SECRET"),
        "redirect_uri": os.getenv("GOOGLE_REDIRECT_URI"),
    }

def oidc_login(request):
    cfg = okta_cfg()
    if not all([cfg["domain"], cfg["client_id"], cfg["redirect_uri"]]):
        return HttpResponseBadRequest(
            "Missing OIDC env vars: OKTA_DOMAIN / OKTA_OIDC_CLIENT_ID / OKTA_OIDC_REDIRECT_URI"
        )

    state = secrets.token_urlsafe(24)
    nonce = secrets.token_urlsafe(24)
    request.session["oidc_state"] = state
    request.session["oidc_nonce"] = nonce

    params = {
        "client_id": cfg["client_id"],
        "response_type": "code",
        "scope": "openid profile email",
        "redirect_uri": cfg["redirect_uri"],
        "state": state,
        "nonce": nonce,
    }

    authorize_url = f'{cfg["domain"]}/oauth2/{cfg["authz_server"]}/v1/authorize?{urllib.parse.urlencode(params)}'
    return redirect(authorize_url)



def oidc_callback(request):
    cfg = okta_cfg()

    code = request.GET.get("code")
    state = request.GET.get("state")

    if not code or not state:
        return HttpResponseBadRequest("Missing code/state.")
    if state != request.session.get("oidc_state"):
        return HttpResponseBadRequest("Invalid state.")

    if not all([cfg["domain"], cfg["client_id"], cfg["client_secret"], cfg["redirect_uri"]]):
        return HttpResponseBadRequest(
            "Missing OIDC env vars: OKTA_DOMAIN / OKTA_OIDC_CLIENT_ID / OKTA_OIDC_CLIENT_SECRET / OKTA_OIDC_REDIRECT_URI"
        )

    token_url = f'{cfg["domain"]}/oauth2/{cfg["authz_server"]}/v1/token'
    data = {"grant_type": "authorization_code", "code": code, "redirect_uri": cfg["redirect_uri"]}

    r = requests.post(token_url, data=data, auth=(cfg["client_id"], cfg["client_secret"]), timeout=15)
    if r.status_code != 200:
        return HttpResponseBadRequest(f"Token exchange failed: {r.status_code} {r.text}")

    access_token = r.json().get("access_token")
    if not access_token:
        return HttpResponseBadRequest("No access_token returned.")

    userinfo_url = f'{cfg["domain"]}/oauth2/{cfg["authz_server"]}/v1/userinfo'
    u = requests.get(userinfo_url, headers={"Authorization": f"Bearer {access_token}"}, timeout=15)
    if u.status_code != 200:
        return HttpResponseBadRequest(f"Userinfo failed: {u.status_code} {u.text}")

    request.session["userinfo"] = u.json()
    # Mark OIDC session so downstream checks recognize the login
    request.session["oidc_userinfo"] = u.json()
    request.session["oidc_authenticated"] = True
    return redirect("/soc/")

def google_login(request):
    cfg = google_cfg()
    if not all([cfg["client_id"], cfg["redirect_uri"]]):
        return HttpResponseBadRequest(
            "Missing Google env vars: GOOGLE_CLIENT_ID / GOOGLE_REDIRECT_URI (and optionally GOOGLE_CLIENT_SECRET for token exchange)"
        )

    state = secrets.token_urlsafe(24)
    request.session["google_state"] = state

    params = {
        "client_id": cfg["client_id"],
        "redirect_uri": cfg["redirect_uri"],
        "response_type": "code",
        "scope": "openid email profile",
        "state": state,
        "access_type": "offline",
        "prompt": "consent",
    }
    authorize_url = f"https://accounts.google.com/o/oauth2/v2/auth?{urllib.parse.urlencode(params)}"
    return redirect(authorize_url)


def google_callback(request):
    cfg = google_cfg()

    code = request.GET.get("code")
    state = request.GET.get("state")

    if not code or not state:
        return HttpResponseBadRequest("Missing code/state.")
    if state != request.session.get("google_state"):
        return HttpResponseBadRequest("Invalid state.")

    if not all([cfg["client_id"], cfg["client_secret"], cfg["redirect_uri"]]):
        return HttpResponseBadRequest(
            "Missing Google env vars: GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET / GOOGLE_REDIRECT_URI"
        )

    token_url = "https://oauth2.googleapis.com/token"
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": cfg["redirect_uri"],
        "client_id": cfg["client_id"],
        "client_secret": cfg["client_secret"],
    }

    r = requests.post(token_url, data=data, timeout=15)
    if r.status_code != 200:
        return HttpResponseBadRequest(f"Google token exchange failed: {r.status_code} {r.text}")

    access_token = r.json().get("access_token")
    if not access_token:
        return HttpResponseBadRequest("No access_token returned from Google.")

    userinfo_url = "https://www.googleapis.com/oauth2/v3/userinfo"
    u = requests.get(userinfo_url, headers={"Authorization": f"Bearer {access_token}"}, timeout=15)
    if u.status_code != 200:
        return HttpResponseBadRequest(f"Google userinfo failed: {u.status_code} {u.text}")

    userinfo = u.json()

    allowed_domain = os.getenv("GOOGLE_ALLOWED_DOMAIN")
    if allowed_domain:
        email = (userinfo.get("email") or "").lower()
        domain = email.split("@")[-1] if "@" in email else ""
        if domain != allowed_domain.lower():
            messages.error(request, f"Access denied: email domain must be {allowed_domain}.")
            return redirect("/")

    request.session["google_userinfo"] = userinfo
    request.session["google_authenticated"] = True
    return redirect("/soc/")



# ----------------------------
# Protected: SOC dashboard
# ----------------------------
def soc_dashboard(request):
    if not is_authenticated(request):
        messages.warning(request, "Please log in to access the SOC dashboard.")
        return redirect("/")

    since = timezone.now() - timedelta(hours=24)
    events = SecurityEvent.objects.filter(created_at__gte=since).order_by("-created_at")[:50]

    totals = SecurityEvent.objects.filter(created_at__gte=since).aggregate(total=Count("id"))
    sev_counts = (
        SecurityEvent.objects.filter(created_at__gte=since)
        .values("severity")
        .annotate(c=Count("id"))
    )
    proto_counts = (
        SecurityEvent.objects.filter(created_at__gte=since)
        .values("protocol")
        .annotate(c=Count("id"))
    )

    # Build a simple 6-bucket trend over the last 6 hours for the timeline chart
    trend_labels = []
    trend_counts = []
    now = timezone.now()
    for i in range(6, 0, -1):
        start = now - timedelta(hours=i)
        end = now - timedelta(hours=i-1)
        c = SecurityEvent.objects.filter(created_at__gte=start, created_at__lt=end).count()
        trend_labels.append(f"-{i}h")
        trend_counts.append(c)

    sev_map = {x["severity"]: x["c"] for x in sev_counts}
    proto_map = {x["protocol"]: x["c"] for x in proto_counts}

    return render(
        request,
        "soc_dashboard.html",
        {
        "auth_method": auth_method(request),
        "userinfo": request.session.get("oidc_userinfo"),
        "google_userinfo": request.session.get("google_userinfo"),
        "saml_xml": request.session.get("saml_xml"),

            "events": events,
            "total_events": totals["total"] or 0,
            "sev_low": sev_map.get("low", 0),
            "sev_medium": sev_map.get("medium", 0),
            "sev_high": sev_map.get("high", 0),
            "proto_oidc": proto_map.get("oidc", 0),
            "proto_saml": proto_map.get("saml", 0),
            "proto_system": proto_map.get("system", 0),
            "trend_labels": trend_labels,
            "trend_counts": trend_counts,
        },
    )


# ----------------------------
# Logout (clears BOTH SAML + OIDC session markers)
# ----------------------------
def logout_all(request):
    for k in [
        "saml_authenticated",
        "saml_xml",
        "oidc_authenticated",
        "oidc_userinfo",
        "oidc_state",
        "oidc_nonce",
        "post_login_redirect",
        "google_authenticated",
        "google_userinfo",
        "google_state",
    ]:
        request.session.pop(k, None)

    dj_logout(request)
    messages.info(request, "Logged out.")
    return redirect("/")
