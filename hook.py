from plugins.saml.app.saml_svc import SamlService

name = 'SAML'
description = 'A plugin that provides SAML authentication for CALDERA'
address = None

async def enable(services):
    app = services.get('app_svc').application
    saml_svc = SamlService()
    
    # Register specific handlers for each endpoint using the correct method names
    app.router.add_route('GET', '/saml/login', saml_svc.saml_login_handler)
    app.router.add_route('POST', '/saml/acs', saml_svc.saml_acs_handler)
    app.router.add_route('GET', '/saml/metadata', saml_svc.saml_metadata_handler)
    app.router.add_route('GET', '/saml/sls', saml_svc.saml_sls_handler)
    app.router.add_route('POST', '/saml/sls', saml_svc.saml_sls_handler)
    
    # Also register auth/saml routes for compatibility
    app.router.add_route('GET', '/auth/saml/login', saml_svc.saml_login_handler)
    app.router.add_route('POST', '/auth/saml/acs', saml_svc.saml_acs_handler)
    app.router.add_route('GET', '/auth/saml/metadata', saml_svc.saml_metadata_handler)
    app.router.add_route('GET', '/auth/saml/sls', saml_svc.saml_sls_handler)
    app.router.add_route('POST', '/auth/saml/sls', saml_svc.saml_sls_handler)
    
    # Keep the original saml route for backward compatibility with legacy handler
    app.router.add_route('*', '/saml', saml_svc.saml)