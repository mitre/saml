from plugins.saml.app.saml_svc import SamlService

name = 'SAML'
description = 'A plugin that provides SAML authentication for CALDERA'
address = None


async def enable(services):
    app = services.get('app_svc').application
    saml_svc = SamlService()
    app.router.add_route('*', '/saml', saml_svc.saml)

