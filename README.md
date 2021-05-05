# SAML

## Overview
`saml` is a CALDERA plugin that provides SAML authentication for CALDERA by establishing CALDERA as
a SAML Service Provider (SP). To use this plugin, users will need to have CALDERA configured as an application
in their Identity Provider (IdP), and a `conf/settings.json` file will need to be created in the plugin 
with the appropriate SAML settings and IdP and SP information.

When enabled and configured, this plugin will provide the following:
- When browsing to the main CALDERA site (e.g. `http://localhost:8888/`) or to the `/enter` URL for the CALDERA site
(e.g. `http://localhost:8888/enter`), unauthenticated users will
be redirected to their IdP login page rather than to the default CALDERA login page. If the SAML
settings are not properly configured or if there is an issue with attempting the redirect, the user will
be redirected to the default CALDERA login page as a failsafe.
- When users access the CALDERA application directly from their IdP, they will immediately authenticate
into CALDERA without having to provide login credentials, provided that CALDERA was configured correctly
within the IdP settings. If the SAML login fails for whatever reason (e.g. the application was provisioned
using a username that does not exist within CALDERA), the user will be taken to the default CALDERA login page.

## Setup
There are two main setup components required for SAML authentication within this plugin:
1. The IdP administrators need to configure CALDERA as an application within the IdP platform
1. CALDERA administrators need to configure the `conf/settings.json` settings file within the `saml` plugin.

### Installing Dependencies
To install dependencies, run the following from within the plugin directory::
```
pip3 install -r requirements.txt
```
Note that `requirements.txt` requires `xmlsec`, which in turn requires certain native libraries. 
See the [xmlsec page](https://pypi.org/project/xmlsec/) for more details and to see which native libraries are required
for the operating system that is hosting CALDERA in your particular environment.

### Configuring CALDERA Within the IdP Platform
To provision CALDERA access for users within the Identity Provider, follow the instructions for your particular
Identity Provider to create the CALDERA application with the appropriate SAML settings. 

- When asked for the "Single Sign On URL", "Recipient URL", and "Destination URL", set this to
the `/saml` URL for your CALDERA server (e.g. `http://localhost:8888/saml`). When the plugin is enabled, the server will listen on this endpoint for SAML requests.
- When asked for the "Audience URI" or "SP Entity ID", use the HTTP endpoint for your CALDERA server without the trailing slash (e.g. `http://localhost:8888`). 
- You may keep the "Default RelayState" blank
- If asked for a Name ID format, you may keep it as unspecified
- Include a `username` attribute statement with a value that contains
the user's username or login name for the Identity Provider (e.g. email address). 
This is required by CALDERA to track which users are logging into the system under which
CALDERA accounts.

Once the application is created with the appropriate SAML settings, follow your IdP instructions to provision 
access to the necessary users. You will also need to follow your IdP's instructions to find
the SSO URL for the IdP, the IdP Issuer URL, and the X.509 Certificate for the IdP.
This information is needed to configure the SAML settings within this plugin.

#### Application Usernames
To avoid having to create individual CALDERA accounts for each user in the IdP, one method is to create a fixed
set of CALDERA user accounts (e.g. `red` and `blue` users) and assign the CALDERA username as the
application username for the user assignment. This way, multiple users can log in using the same
CALDERA username, and the SAML request will also include their `username` attribute statement, so that
CALDERA's authentication service can distinguish between different users from the IdP platform.

### Configuring SAML settings within CALDERA
Once CALDERA is configured as an application within your IdP, you can start creating the `conf/settings.json`
file within the plugin according to the [python3-saml instructions](https://github.com/onelogin/python3-saml#settings)
. The following settings are required unless marked otherwise:
- Set `strict` to `true`
- Under `sp`:
    - For `entityId`, use the HTTP endpoint for the C2 Server (e.g. `"http://localhost:8888"`)
    - Under `assertionConsumerService`:
        - The `url` must be the `/saml` endpoint for the C2 server (e.g. `"http://localhost:8888/saml"`)
        - For `binding`, use `"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"`
    - Do not include an entry for `singleLogoutService`
- Under `idp`:
    - For `entityId`, use the Identity Provider's identifier URI. You will need to obtain this from
    your CALDERA application configuration for the Identity Provider.
    - Under `singleSignOnService`:
        - For `url`, use the IdP's SSO URL as provided by the IdP for the
        CALDERA application configuration.
        - For `binding`, use `"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"`
    - For the `x509cert`, use the base64-encoded string for the IdP's X.509 certificate.
- Under `security`:
    - Set `wantAttributeStatement` to `true`
    - Set the remaining security settings as needed for your environment. 
    - Note that the security settings as shown in the 
    [`python3-saml` readme](https://github.com/onelogin/python3-saml/#settings) are placed in a separate
    file called `advanced_settings.json`. For simplicity, the `saml` plugin requires you to combine all settings
    into the same `conf/settings.json` file, as shown in the example below.
    
You may adjust settings as needed for your environment.
  
Below is a sample template for the SAML settings JSON file, which is also located in `config/sample.json` in the plugin.
Refer to the [python3-saml page](https://github.com/onelogin/python3-saml/) for full documentation and examples.
```json
{
    "strict": true,
    "debug": true,
    "sp": {
        "entityId": "http://localhost:8888",
        "assertionConsumerService": {
            "url": "http://localhost:8888/saml",
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        }
    },
    "idp": {
        "entityId": "http://myidentityprovider.com/connector_id_url",
        "singleSignOnService": {
            "url": "https://myidentityprovider.com/sso_url",
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        },
        "x509cert": "base64-encoded certificate data"
    },
    "security": {
        "wantMessagesSigned": true,
        "wantAssertionsSigned": true,
        "wantAttributeStatement": true
    }
}
```

### Setting the SAML Login Handler
Once CALDERA's SAML settings are configured and CALDERA is set up on the IdP platform, the final
step requires setting the SAML login handler as the main login handler in the CALDERA config YAML file. 
Within the config file, set `auth.login.handler.module` to `plugins.saml.app.saml_login_handler`
as shown below:
```yaml
auth.login.handler.module: plugins.saml.app.saml_login_handler
```

Restart the CALDERA server, and any future authentication requests will now be handled via SAML according
to the previously established settings.
