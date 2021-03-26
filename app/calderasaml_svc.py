import json
import logging
import os
import warnings
warnings.filterwarnings('ignore', 'defusedxml.lxml is no longer supported and will be removed in a future release.', DeprecationWarning)

from aiohttp import web
from aiohttp_jinja2 import render_template
from onelogin.saml2.auth import OneLogin_Saml2_Auth

from app.service.interfaces.i_login_handler import LoginHandlerInterface
from app.utility.base_service import BaseService

class CalderaSamlService(BaseService, LoginHandlerInterface):
    def __init__(self, services):
        self.services = services
        self.file_svc = services.get('file_svc')
        self.auth_svc = services.get('auth_svc')
        self.log = logging.getLogger('saml_svc')

        self._saml_config = None
        self.config_dir_path = os.path.relpath(os.path.join('plugins', 'calderasaml', 'conf'))
        self.settings_path = os.path.relpath(os.path.join(self.config_dir_path, 'settings.json'))
        with open(self.settings_path, 'rb') as settings_file:
            self._saml_config = json.load(settings_file)

    async def saml(self, request):
        """Handle SAML authentication."""

        try:
            await self._saml_login(request)
        except web.HTTPRedirection as http_redirect:
            raise http_redirect
        except Exception as e:
            self.log.error('Exception when handling /saml request: %s' % e)
        self.log.debug('Redirecting to main login page')
        raise web.HTTPFound('/login')

    async def set_saml_login_handler(self):
        """Set self as the optional login handler for the auth service"""
        self.log.debug('Setting SAML as primary login handler for auth service.')
        await self.auth_svc.set_optional_login_handler(self)

    """ LoginHandlerInterface implementation """

    async def handle_login(self, request):
        """Redirects login request to SAML login page."""

        # Only handle login if username and password are not included in the request. If username and password
        # are included, then this is a standard login request and should not redirect to SAML.
        data = await request.post()
        if 'username' not in data and 'password' not in data:
            self.log.debug('Handling SAML login')
            await self.handle_login_redirect(request)
        else:
            self.log.debug('Requester provided login credentials. Skipping SAML and falling back to default auth.')

    async def handle_login_redirect(self, request):
        """Will raise web.HTTPFound for identity provider redirect on success."""

        saml_request = await self._prepare_auth_parameter(request)
        auth = OneLogin_Saml2_Auth(saml_request, self._saml_config)
        redirect = auth.login()
        raise web.HTTPFound(redirect)

    """ PRIVATE """

    async def _saml_login(self, request):
        self.log.debug('Handling login from SAML identity provider.')
        saml_response = await self._prepare_auth_parameter(request)
        saml_auth = OneLogin_Saml2_Auth(saml_response, self._saml_config)
        saml_auth.process_response()
        errors = saml_auth.get_errors()
        if errors:
            self.log.error('Error when processing SAML response: %s' % ', '.join(errors))
        else:
            if saml_auth.is_authenticated():
                username = self._get_saml_login_username(saml_auth)
                self.log.debug('SAML provided username: %s' % username)
                if username:
                    if username in self.auth_svc.user_map:
                        # Will raise redirect on success
                        await self.auth_svc.provide_verified_login_response(request, username)
                    else:
                        self.log.warn('Username %s not configured for login' % username)
                else:
                    self.log.error('No NameID or username attribute provided in SAML response.')
            else:
                self.log.warn('Not authenticated.')

    @staticmethod
    def _get_saml_login_username(saml_auth):
        """If the SAML subject NameID is provided, use that as the username. Otherwise, use the 'username'
        attribute if available."""

        name_id = saml_auth.get_nameid()
        if name_id:
            return name_id
        attributes = saml_auth.get_attributes()
        username_attr_list = attributes.get('username', [])
        return username_attr_list[0] if len(username_attr_list) > 0 else None

    @staticmethod
    async def _prepare_auth_parameter(request):
        ret_parameters = {
            'http_host': request.url.host,
            'script_name': request.url.path,
            'server_port': request.url.port,
            'get_data': request.url.query.copy(),
            'post_data': (await request.post()).copy(),
        }
        return ret_parameters