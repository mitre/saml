import json
import os
import warnings
warnings.filterwarnings('ignore', 'defusedxml.lxml is no longer supported and will be removed in a future release.', DeprecationWarning)

from aiohttp import web
from onelogin.saml2.auth import OneLogin_Saml2_Auth

from app.utility.base_service import BaseService


class SamlService(BaseService):
    def __init__(self):
        self.config_dir_path = os.path.relpath(os.path.join('plugins', 'saml', 'conf'))
        self.settings_path = os.path.relpath(os.path.join(self.config_dir_path, 'settings.json'))
        self.log = self.add_service('saml_svc', self)
        try:
            with open(self.settings_path, 'rb') as settings_file:
                self._saml_config = json.load(settings_file)
        except OSError as e:
            self.log.exception('Could not load settings from conf/settings.json')
            self._saml_config = dict()

    async def saml(self, request):
        """Handle SAML authentication."""
        try:
            await self._saml_login(request)
        except web.HTTPRedirection as http_redirect:
            raise http_redirect
        except Exception as e:
            self.log.exception('Exception when handling /saml request: %s', e)
        self.log.debug('Redirecting to main login page')
        raise web.HTTPFound('/login')

    async def set_saml_login_handler(self):
        """Set self as the optional login handler for the auth service."""
        self.log.debug('Setting SAML as primary login handler for auth service.')
        auth_svc = self.get_service('auth_svc')
        if not auth_svc:
            raise Exception('Auth service not available')
        await auth_svc.set_optional_login_handler(self)

    async def get_saml_auth(self, request):
        saml_response = await self._prepare_auth_parameter(request)
        return OneLogin_Saml2_Auth(saml_response, self._saml_config)

    async def _saml_login(self, request):
        self.log.debug('Handling login from SAML identity provider.')
        auth_svc = self.get_service('auth_svc')
        if not auth_svc:
            raise Exception('Auth service not available')
        saml_auth = await self.get_saml_auth(request)
        saml_auth.process_response()
        errors = saml_auth.get_errors()
        if errors:
            errors = ', '.join(errors)
            raise Exception('Error when processing SAML response: %s' % errors)
        else:
            if saml_auth.is_authenticated():
                app_username = self._get_saml_login_username(saml_auth)
                username_attr = self._get_saml_username_attribute(saml_auth)
                self.log.debug('Identity Provider provided application username: %s', app_username)
                self.log.debug('Identity Provider provided username attribute: %s', username_attr)
                if not username_attr:
                    raise Exception('No username attribute provided in SAML request. Required for auditing purposes.')
                if app_username:
                    if app_username in auth_svc.user_map:
                        # Will raise redirect on success
                        self.log.info('User "%s" authenticated via SAML under application user "%s"',
                                      username_attr, app_username)
                        await auth_svc.handle_successful_login(request, app_username)
                    else:
                        self.log.warn('Application username "%s" not configured for login', app_username)
                        self.log.info('User "%s" failed to authenticate via SAML under application user "%s"',
                                      username_attr, app_username)
                else:
                    self.log.error('No NameID or username attribute provided in SAML response.')
            else:
                self.log.warn('SAML request not authenticated.')

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

    @staticmethod
    def _get_saml_login_username(saml_auth):
        """If the SAML subject NameID is provided, use that as the username. Otherwise, use the 'username'
        attribute if available."""

        name_id = saml_auth.get_nameid()
        if name_id:
            return name_id
        return SamlService._get_saml_username_attribute(saml_auth)

    @staticmethod
    def _get_saml_username_attribute(saml_auth):
        """Returns the "username" attribute for the SAML request. This should be the username
        for the identity provider, not necessarily the username for the application."""
        attributes = saml_auth.get_attributes()
        username_attr_list = attributes.get('username', [])
        return username_attr_list[0] if len(username_attr_list) > 0 else None
