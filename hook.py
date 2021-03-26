from plugins.calderasaml.app.calderasaml_svc import CalderaSamlService

name = 'Calderasaml'
description = 'A plugin that provides SAML authentication for CALDERA'
address = None


async def enable(services):
    app = services.get('app_svc').application
    saml_svc = CalderaSamlService(services)

    # Set SAML login handler for auth service
    await saml_svc.set_saml_login_handler()

    # Add API routes here
    app.router.add_route('*', '/saml', saml_svc.saml)

