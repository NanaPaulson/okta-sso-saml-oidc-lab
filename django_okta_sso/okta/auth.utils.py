def is_authenticated(request) -> bool:
    return bool(request.session.get("userinfo") or request.session.get("saml_xml"))
