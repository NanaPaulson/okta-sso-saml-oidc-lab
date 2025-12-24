import os
import base64

from django.contrib import messages
from django.http import HttpResponseBadRequest
from django.shortcuts import redirect
from django.views.decorators.csrf import csrf_exempt

from django.http import JsonResponse

def saml_debug(request):
    return JsonResponse({
        "OKTA_SAML_EMBED_LINK": os.getenv("OKTA_SAML_EMBED_LINK"),
    })

def saml_login(request):
    print("HIT SAML LOGIN")
    ...


def saml_login(request):
    embed_link = os.getenv("OKTA_SAML_EMBED_LINK")
    if not embed_link:
        messages.error(request, "SAML not configured yet (missing OKTA_SAML_EMBED_LINK).")
        return redirect("/")
    return redirect(embed_link)


@csrf_exempt
def saml_acs(request):
    saml_response = request.POST.get("SAMLResponse")
    if not saml_response:
        messages.error(request, "Missing SAMLResponse.")
        return redirect("/")

    try:
        xml_text = base64.b64decode(saml_response).decode("utf-8", errors="replace")
    except Exception as e:
        return HttpResponseBadRequest(f"Failed to decode SAMLResponse: {e}")

    request.session["saml_xml"] = xml_text
    messages.success(request, "Authenticated with SAML.")
    return redirect("/soc/")  # ✅ SOC dashboard after success

