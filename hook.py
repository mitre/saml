from plugins.calderasaml.app.calderasaml_svc import CalderaSamlService

name = 'Calderasaml'
description = 'A plugin that provides SAML authentication for CALDERA'
address = None


async def enable(services):
    app = services.get('app_svc').application
    saml_svc = CalderaSamlService(services)
    app.router.add_route('*', '/saml', saml_svc.saml)

