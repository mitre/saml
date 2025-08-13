from plugins.saml.app.saml_svc import SamlService

name = 'SAML'
description = 'A plugin that provides SAML authentication for CALDERA'
address = None

async def enable(services):
    app = services.get('app_svc').application
    saml_svc = SamlService()

    # Register all SAML routes to use the same handler but allow appropriate methods
    app.router.add_route('*', '/saml', saml_svc.saml)
    app.router.add_route('GET', '/saml/login', saml_svc.saml)
    app.router.add_route('POST', '/saml/acs', saml_svc.saml)  # This is critical!
    app.router.add_route('GET', '/saml/acs', saml_svc.saml)   # For testing
    app.router.add_route('GET', '/saml/metadata', saml_svc.saml)
    app.router.add_route('GET', '/saml/sls', saml_svc.saml)
    app.router.add_route('POST', '/saml/sls', saml_svc.saml)

    # Also register the auth/saml routes for compatibility
    app.router.add_route('GET', '/auth/saml/login', saml_svc.saml)
    app.router.add_route('POST', '/auth/saml/acs', saml_svc.saml)
    app.router.add_route('GET', '/auth/saml/metadata', saml_svc.saml)
    app.router.add_route('GET', '/auth/saml/sls', saml_svc.saml)
    app.router.add_route('POST', '/auth/saml/sls', saml_svc.saml)