import logging
from aiohttp import web

from app.service.interfaces.i_login_handler import LoginHandlerInterface
from plugins.calderasaml.app.calderasaml_svc import CalderaSamlService as SamlSvc

def load_login_handler(services):
    return SamlLoginHandler(services)

class SamlLoginHandler(LoginHandlerInterface):
    def __init__(self, services):
        self.auth_svc = services.get('auth_svc')
        self.log = logging.getLogger('saml_login_handler')
        self._name = 'SAML Login Handler'

    @property
    def name(self):
        return self._name

    """ LoginHandlerInterface implementation """

    async def handle_login(self, request, **kwargs):
        """Redirects login request to SAML login page. If username/password were included in the request, then
        the default login handler mechanism will be used."""

        # Only handle login if username and password are not included in the request. If username and password
        # are included, then this is a standard login request and should not redirect to SAML.
        data = await request.post()
        if 'username' not in data and 'password' not in data:
            self.log.debug('Handling SAML login')
            await self.handle_login_redirect(request)
        else:
            self.log.debug('Requester provided login credentials. Using default login handler instead.')
            return await self.auth_svc.default_login_handler.handle_login(request, kwargs=kwargs)

    async def handle_login_redirect(self, request, **kwargs):
        """Will raise web.HTTPFound for identity provider redirect on success."""

        auth = await SamlSvc.get_saml_auth(request)
        redirect = auth.login()
        raise web.HTTPFound(redirect)