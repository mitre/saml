# Overview

Calderasaml is a CALDERA plugin that provides SAML authentication for CALDERA by establishing CALDERA as
a SAML Service Provider (SP). To use this plugin, users will need to have CALDERA configured as an application
in their Identity Provider (IdP), and the `conf/settings.json` file in the plugin will need to be configured
with the appropriate SAML settings and IdP information.

When enabled and configured, this plugin will provide the following:
- When browsing to the main CALDERA site (e.g. `http://localhost:8888`) or to the `/enter` URL for the CALDERA site
(e.g. `http://localhost:8888/enter`), unauthenticated users will
be redirected to their IdP login page rather than to the default CALDERA login page. If the SAML
settings are not properly configured or if there is an issue with attempting the redirect, the user will
be redirected to the default CALDERA login page.
- When users access the CALDERA application directly from their IdP, they will immediately authenticate
into CALDERA without having to provide login credentials, provided that CALDERA was configured correctly
within the IdP settings. If the SAML login fails for whatever reason, the user will be taken to the 
default CALDERA login page.

# Dependencies
In order to use this plugin, the `python3-saml`(https://github.com/onelogin/python3-saml) Python package is required and can be installed via `pip`.
- `pip3 install python3-saml`

`python3-saml` requires `xmlsec` as an additional Python dependency, which 
in turn requires certain native libraries. See the [xmlsec page](https://pypi.org/project/xmlsec/) for more
details and  to see which native libraries are required for the operating system that is hosting CALDERA in your
particular environment.

# Setup
There are two main setup components required to have SAML authentication work properly:
1. CALDERA administrators need to configure the `conf/settings.json` settings file within the `calderasaml` plugin
1. The IdP administrators need to configure CALDERA as an application within the IdP platform

## Configuring SAML settings within CALDERA
CALDERA