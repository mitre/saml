import json
import os
import warnings
warnings.filterwarnings('ignore', 'defusedxml.lxml is no longer supported and will be removed in a future release.', DeprecationWarning)

from aiohttp import web
from pathlib import Path
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.settings import OneLogin_Saml2_Settings
from onelogin.saml2.utils import OneLogin_Saml2_Utils
from app.utility.base_service import BaseService


class SamlService(BaseService):
    def __init__(self):
        self.config_dir_path = os.path.join(Path(__file__).parents[1], 'conf')
        self.settings_path = os.path.join(self.config_dir_path, 'settings.json')
        
        # Load SAML configuration with better error handling
        try:
            with open(self.settings_path, 'rb') as settings_file:
                self._saml_config = json.load(settings_file)
        except FileNotFoundError:
            self.log.error(f'SAML configuration file not found: {self.settings_path}')
            self._saml_config = {}
        except json.JSONDecodeError as e:
            self.log.error(f'Invalid JSON in SAML configuration: {e}')
            self._saml_config = {}
            
        self.log = self.add_service('saml_svc', self)

    async def saml(self, request):
        """Legacy handler - routes to appropriate specific handler based on path and method"""
        path = request.path
        method = request.method
        
        self.log.debug(f'SAML legacy handler called: {method} {path}')
        
        try:
            # Route to specific handlers based on path
            if path.endswith('/metadata'):
                return await self.saml_metadata_handler(request)
            elif path.endswith('/acs'):
                return await self.saml_acs_handler(request)
            elif path.endswith('/sls'):
                return await self.saml_sls_handler(request)
            elif path.endswith('/login') or path in ['/saml', '/auth/saml']:
                return await self.saml_login_handler(request)
            else:
                # Default behavior - check if it's a SAML response or login initiation
                if method == 'POST' and 'SAMLResponse' in (await request.post()):
                    return await self.saml_acs_handler(request)
                else:
                    return await self.saml_login_handler(request)
                    
        except web.HTTPRedirection as http_redirect:
            raise http_redirect
        except Exception as e:
            self.log.exception('Exception when handling SAML request: %s', e)
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
        """Create OneLogin SAML Auth object from request"""
        if not self._saml_config:
            raise Exception('SAML configuration not loaded')
            
        saml_response = await self._prepare_auth_parameter(request)
        return OneLogin_Saml2_Auth(saml_response, self._saml_config)

    async def _saml_login(self, request):
        """Core SAML login logic"""
        self.log.debug(f'Handling SAML login: {request.method} {request.path}')
        
        try:
            saml_auth = await self.get_saml_auth(request)
            
            # Check if this is a SAML response (POST from IdP) or login initiation (GET)
            if request.method == 'POST':
                post_data = await request.post()
                if 'SAMLResponse' in post_data:
                    # Process SAML response from IdP
                    self.log.debug('Processing SAML response from IdP')
                    saml_auth.process_response()
                    
                    # Check for errors
                    self._handle_saml_auth_errors(saml_auth)
                    
                    # Handle successful authentication
                    if saml_auth.is_authenticated():
                        return await self._handle_app_authentication(request, saml_auth)
                    else:
                        self.log.error('SAML authentication failed: not authenticated')
                        raise web.HTTPFound('/login')
            
            # GET request or no SAML response - initiate login
            self.log.debug('Initiating SAML login redirect to IdP')
            redirect_url = saml_auth.login(return_to=str(request.url))
            self.log.debug(f'Redirecting to IdP: {redirect_url}')
            raise web.HTTPFound(redirect_url)
            
        except web.HTTPRedirection:
            raise
        except Exception as e:
            self.log.error(f'SAML login error: {e}')
            raise web.HTTPFound('/login')

    async def _handle_app_authentication(self, request, saml_auth):
        """Handle successful SAML authentication"""
        if saml_auth.is_authenticated():
            app_username = self._get_saml_login_username(saml_auth)
            username_attr = self._get_saml_username_attribute(saml_auth)
            self.log.debug('Identity Provider provided application username: %s', app_username)
            self.log.debug('Identity Provider provided username attribute: %s', username_attr)
            
            if not username_attr:
                raise Exception('No username attribute provided in SAML request. Required for auditing purposes.')
            
            if app_username:
                await self._validate_username(request, app_username, username_attr)
            else:
                self.log.error('No NameID or username attribute provided in SAML response.')
                raise web.HTTPFound('/login')
        else:
            self.log.warn('SAML request not authenticated.')
            raise web.HTTPFound('/login')

    async def _validate_username(self, request, app_username, username_attr):
        """Validate username and create session"""
        auth_svc = self.get_service('auth_svc')
        if not auth_svc:
            raise Exception('Auth service not available')
            
        if app_username in auth_svc.user_map:
            # Will raise redirect on success
            self.log.info('User "%s" authenticated via SAML under application user "%s"',
                          username_attr, app_username)
            await auth_svc.handle_successful_login(request, app_username)
        else:
            self.log.warn('Application username "%s" not configured for login', app_username)
            self.log.info('User "%s" failed to authenticate via SAML under application user "%s"',
                          username_attr, app_username)
            raise web.HTTPFound('/login')

    # Specific handler methods for different SAML endpoints
    async def saml_login_handler(self, request):
        """Handle SAML login initiation (GET)"""
        self.log.debug('SAML login handler called')
        return await self._saml_login(request)

    async def saml_acs_handler(self, request):
        """Handle SAML assertion consumer service (POST)"""
        self.log.debug('SAML ACS handler called')
        return await self._saml_login(request)

    async def saml_metadata_handler(self, request):
        """Handle SAML metadata requests (GET)"""
        self.log.debug('SAML metadata handler called')
        try:
            if not self._saml_config:
                raise Exception('SAML configuration not loaded')
                
            settings = OneLogin_Saml2_Settings(self._saml_config)
            metadata = settings.get_sp_metadata()
            
            # Validate metadata
            errors = settings.check_sp_settings()
            if errors:
                self.log.error(f'SP metadata validation errors: {errors}')
                raise Exception(f'SAML metadata validation failed: {errors}')
            
            self.log.debug('SAML metadata generated successfully')
            return web.Response(text=metadata, content_type='text/xml')
            
        except Exception as e:
            self.log.error(f'Error generating SAML metadata: {e}')
            raise web.HTTPInternalServerError(text=f'SAML metadata error: {str(e)}')

    async def saml_sls_handler(self, request):
        """Handle SAML single logout service"""
        self.log.debug('SAML SLS handler called')
        try:
            saml_auth = await self.get_saml_auth(request)
            
            if request.method == 'GET':
                # Handle logout request from IdP
                url = saml_auth.process_slo(delete_session_cb=lambda: None)
                errors = saml_auth.get_errors()
                if errors:
                    self.log.error(f'SLO errors: {errors}')
                if url:
                    raise web.HTTPFound(url)
                else:
                    raise web.HTTPFound('/')
            else:
                # Initiate logout
                url = saml_auth.logout()
                raise web.HTTPFound(url)
                
        except web.HTTPRedirection:
            raise
        except Exception as e:
            self.log.error(f'SAML SLS error: {e}')
            raise web.HTTPFound('/')

    # Utility methods
    @staticmethod
    def _handle_saml_auth_errors(saml_auth):
        """Check for SAML authentication errors"""
        errors = saml_auth.get_errors()
        if errors:
            combined_msg = ', '.join(errors)
            raise Exception('Error when processing SAML response: %s' % combined_msg)

    @staticmethod
    async def _prepare_auth_parameter(request):
        """Prepare request parameters for OneLogin SAML"""
        post_data = {}
        if request.method == 'POST':
            try:
                post_data = dict(await request.post())
            except:
                post_data = {}
                
        ret_parameters = {
            'https': 'on' if request.scheme == 'https' else 'off',
            'http_host': request.host,
            'script_name': request.path_qs,
            'server_port': str(request.port) if request.port else ('443' if request.scheme == 'https' else '80'),
            'get_data': dict(request.query),
            'post_data': post_data
        }
        return ret_parameters

    @staticmethod
    def _get_saml_login_username(saml_auth):
        """Get username from SAML NameID"""
        name_id = saml_auth.get_nameid()
        if name_id:
            return name_id
        return SamlService._get_saml_username_attribute(saml_auth)

    @staticmethod
    def _get_saml_username_attribute(saml_auth):
        """Get username from SAML attributes"""
        attributes = saml_auth.get_attributes()
        username_attr_list = attributes.get('username', [])
        return username_attr_list[0] if len(username_attr_list) > 0 else None