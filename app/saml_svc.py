import json
import os
import warnings
import logging
from typing import Dict, Any, Optional
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
        self.user_mapping_path = os.path.join(self.config_dir_path, 'user_mapping.json')
        
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
            
        # Load user mapping configuration
        try:
            with open(self.user_mapping_path, 'r') as mapping_file:
                self._user_mapping_config = json.load(mapping_file)
        except FileNotFoundError:
            self.log.info(f'User mapping file not found: {self.user_mapping_path}, using defaults')
            self._user_mapping_config = self._get_default_user_mapping()
        except json.JSONDecodeError as e:
            self.log.error(f'Invalid JSON in user mapping configuration: {e}')
            self._user_mapping_config = self._get_default_user_mapping()
            
        self.log = self.add_service('saml_svc', self)

    def _get_default_user_mapping(self) -> Dict[str, Any]:
        """Default user mapping configuration"""
        return {
            "role_mappings": {
                "admin": ["admin", "administrator", "sysadmin"],
                "blue": ["blue_team", "defender", "analyst"],
                "red": ["red_team", "attacker", "pentester"],
                "user": ["user", "viewer", "readonly"]
            },
            "group_mappings": {},
            "email_domain_mappings": {}
        }

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
        """Core SAML login logic with enhanced user provisioning"""
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
                    
                    # Handle successful authentication with enhanced provisioning
                    if saml_auth.is_authenticated():
                        return await self._handle_enhanced_authentication(request, saml_auth)
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

    async def _handle_enhanced_authentication(self, request, saml_auth):
        """Enhanced authentication handler with automatic user provisioning"""
        try:
            # Extract user information from SAML response
            user_info = self._extract_user_info(saml_auth)
            self.log.debug(f'Extracted user info: {user_info}')
            
            # Determine Caldera role based on SAML attributes
            caldera_role = self._determine_caldera_role(user_info)
            self.log.debug(f'Determined Caldera role: {caldera_role}')
            
            # Provision or update user if enabled
            if self._is_user_provisioning_enabled():
                await self._provision_user(user_info, caldera_role)
            
            # Authenticate user
            await self._authenticate_user(request, caldera_role, user_info)
            
        except Exception as e:
            self.log.error(f'Enhanced authentication failed: {e}')
            raise web.HTTPFound('/login')

    def _extract_user_info(self, saml_auth) -> Dict[str, Any]:
        """Extract user information from SAML response"""
        attributes = saml_auth.get_attributes()
        name_id = saml_auth.get_nameid()
        
        # Get configuration for attribute names
        user_provisioning = self._saml_config.get('user_provisioning', {})
        email_attr = user_provisioning.get('email_attribute', 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress')
        name_attr = user_provisioning.get('name_attribute', 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name')
        role_attr = user_provisioning.get('role_attribute', 'http://schemas.microsoft.com/ws/2008/06/identity/claims/role')
        group_attr = user_provisioning.get('group_attribute', 'http://schemas.xmlsoap.org/claims/Group')
        
        # Extract values
        user_info = {
            'name_id': name_id,
            'email': self._get_attribute_value(attributes, email_attr),
            'display_name': self._get_attribute_value(attributes, name_attr),
            'roles': self._get_attribute_values(attributes, role_attr),
            'groups': self._get_attribute_values(attributes, group_attr),
            'all_attributes': attributes
        }
        
        # Use name_id as email if email not found
        if not user_info['email'] and name_id:
            user_info['email'] = name_id
            
        return user_info

    def _get_attribute_value(self, attributes: Dict, attr_name: str) -> Optional[str]:
        """Get single attribute value"""
        values = attributes.get(attr_name, [])
        return values[0] if values else None

    def _get_attribute_values(self, attributes: Dict, attr_name: str) -> list:
        """Get multiple attribute values"""
        return attributes.get(attr_name, [])

    def _determine_caldera_role(self, user_info: Dict[str, Any]) -> str:
        """Determine Caldera role based on SAML attributes and mapping configuration"""
        user_provisioning = self._saml_config.get('user_provisioning', {})
        default_role = user_provisioning.get('default_role', 'user')
        admin_roles = user_provisioning.get('admin_roles', ['admin', 'administrator'])
        admin_groups = user_provisioning.get('admin_groups', [])
        
        # Check if user has admin roles
        for role in user_info.get('roles', []):
            if role.lower() in [r.lower() for r in admin_roles]:
                return 'admin'
        
        # Check if user is in admin groups
        for group in user_info.get('groups', []):
            if group in admin_groups:
                return 'admin'
        
        # Check role mappings
        role_mappings = self._user_mapping_config.get('role_mappings', {})
        for caldera_role, saml_roles in role_mappings.items():
            for user_role in user_info.get('roles', []):
                if user_role.lower() in [r.lower() for r in saml_roles]:
                    return caldera_role
        
        # Check group mappings
        group_mappings = self._user_mapping_config.get('group_mappings', {})
        for group in user_info.get('groups', []):
            if group in group_mappings:
                return group_mappings[group]
        
        # Check email domain mappings
        email_domain_mappings = self._user_mapping_config.get('email_domain_mappings', {})
        if user_info.get('email'):
            domain = user_info['email'].split('@')[-1] if '@' in user_info['email'] else ''
            if domain in email_domain_mappings:
                return email_domain_mappings[domain]
        
        return default_role

    def _is_user_provisioning_enabled(self) -> bool:
        """Check if user provisioning is enabled"""
        user_provisioning = self._saml_config.get('user_provisioning', {})
        return user_provisioning.get('enabled', False)

    async def _provision_user(self, user_info: Dict[str, Any], caldera_role: str):
        """Provision or update user in Caldera"""
        try:
            auth_svc = self.get_service('auth_svc')
            if not auth_svc:
                raise Exception('Auth service not available')
            
            email = user_info.get('email')
            display_name = user_info.get('display_name', email)
            
            if not email:
                self.log.warning('No email found in SAML response, cannot provision user')
                return
            
            # Check if user exists
            user_exists = caldera_role in auth_svc.user_map
            
            user_provisioning = self._saml_config.get('user_provisioning', {})
            create_missing = user_provisioning.get('create_missing_users', True)
            update_on_login = user_provisioning.get('update_on_login', True)
            
            if not user_exists and create_missing:
                # Create new user
                self.log.info(f'Creating new user: {caldera_role} for {email}')
                
                # Define privileges based on role
                privileges = self._get_role_privileges(caldera_role)
                
                # Add user to auth service
                auth_svc.user_map[caldera_role] = {
                    'password': self._generate_temp_password(),
                    'privileges': privileges,
                    'created_via_saml': True,
                    'saml_email': email,
                    'saml_display_name': display_name,
                    'last_saml_login': self._get_current_timestamp()
                }
                
                self.log.info(f'User {caldera_role} created successfully')
                
            elif user_exists and update_on_login:
                # Update existing user
                self.log.debug(f'Updating existing user: {caldera_role}')
                
                user_data = auth_svc.user_map[caldera_role]
                user_data.update({
                    'saml_email': email,
                    'saml_display_name': display_name,
                    'last_saml_login': self._get_current_timestamp()
                })
                
        except Exception as e:
            self.log.error(f'User provisioning failed: {e}')
            # Don't fail authentication if provisioning fails
            pass

    def _get_role_privileges(self, role: str) -> list:
        """Get privileges for a Caldera role"""
        role_privileges = {
            'admin': ['red', 'blue'],
            'red': ['red'],
            'blue': ['blue'],
            'user': []
        }
        return role_privileges.get(role, [])

    def _generate_temp_password(self) -> str:
        """Generate a temporary password for SAML users"""
        import secrets
        import string
        alphabet = string.ascii_letters + string.digits
        return ''.join(secrets.choice(alphabet) for _ in range(16))

    def _get_current_timestamp(self) -> str:
        """Get current timestamp as string"""
        from datetime import datetime
        return datetime.utcnow().isoformat()

    async def _authenticate_user(self, request, caldera_role: str, user_info: Dict[str, Any]):
        """Authenticate user with Caldera"""
        auth_svc = self.get_service('auth_svc')
        if not auth_svc:
            raise Exception('Auth service not available')
            
        email = user_info.get('email', 'unknown@unknown.com')
        display_name = user_info.get('display_name', email)
        
        if caldera_role in auth_svc.user_map:
            # Will raise redirect on success
            self.log.info(f'User "{display_name}" ({email}) authenticated via SAML as "{caldera_role}"')
            await auth_svc.handle_successful_login(request, caldera_role)
        else:
            self.log.warning(f'Caldera role "{caldera_role}" not configured for user "{display_name}" ({email})')
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

        # Check X-Forwarded-Proto header for ALB HTTPS termination
        forwarded_proto = request.headers.get('X-Forwarded-Proto', '').lower()
        is_https = (forwarded_proto == 'https') or (request.scheme == 'https')

        # Use X-Forwarded-Host if available (for ALB)
        http_host = request.headers.get('X-Forwarded-Host', request.host)

        # Determine port based on protocol
        if request.port:
            server_port = str(request.port)
        else:
            server_port = '443' if is_https else '80'

        ret_parameters = {
            'https': 'on' if is_https else 'off',
            'http_host': http_host,
            'script_name': request.path_qs,
            'server_port': server_port,
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
