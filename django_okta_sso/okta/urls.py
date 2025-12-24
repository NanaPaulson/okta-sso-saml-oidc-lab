from django.urls import path
from . import views
from . import saml_views

urlpatterns = [

    path("saml/debug/", saml_views.saml_debug),

    path("logout/", views.logout_all, name="logout_all"),

    # Public
    path("", views.login_choice, name="login_choice"),

    path("saml/login/", saml_views.saml_login, name="saml_login"),
    path("saml/acs/", saml_views.saml_acs, name="saml_acs"),
    path("soc/", views.soc_dashboard, name="soc_dashboard"),
    path("logout/", views.logout_all, name="logout_all"),

    #Octa
    path("oidc/login/", views.oidc_login, name="oidc_login"),
    path("oidc/callback/", views.oidc_callback, name="oidc_callback"),

    # Google OAuth
    path("google/login/", views.google_login, name="google_login"),
    path("google/callback/", views.google_callback, name="google_callback"),


]
