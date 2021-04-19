import os
import pytest
import yaml

from http import HTTPStatus
from pathlib import Path
from aiohttp import web

from app.api.rest_api import RestApi
from app.service.app_svc import AppService
from app.service.auth_svc import AuthService
from app.service.contact_svc import ContactService
from app.service.data_svc import DataService
from app.service.file_svc import FileSvc
from app.service.learning_svc import LearningService
from app.service.planning_svc import PlanningService
from app.service.rest_svc import RestService
from app.utility.base_service import BaseService
from app.utility.base_world import BaseWorld
from plugins.saml.app.saml_login_handler import SamlLoginHandler


@pytest.fixture
def aiohttp_client(loop, aiohttp_client):

    async def initialize():
        with open(Path(__file__).parents[3] / 'conf' / 'default.yml', 'r') as fle:
            config = yaml.safe_load(fle)
            config.get('plugins', []).append('saml')
            BaseWorld.apply_config('main', config)
        with open(Path(__file__).parents[3] / 'conf' / 'payloads.yml', 'r') as fle:
            BaseWorld.apply_config('payloads', yaml.safe_load(fle))

        app_svc = AppService(web.Application())
        _ = DataService()
        _ = RestService()
        _ = PlanningService()
        _ = LearningService()
        auth_svc = AuthService()
        _ = ContactService()
        _ = FileSvc()
        services = app_svc.get_services()
        os.chdir(str(Path(__file__).parents[3]))

        await app_svc.register_contacts()
        await app_svc.load_plugins(['sandcat', 'ssl', 'saml'])
        _ = await RestApi(services).enable()
        await auth_svc.apply(app_svc.application, auth_svc.get_config('users'))
        await auth_svc.set_login_handlers(services)
        return app_svc.application

    app = loop.run_until_complete(initialize())
    return loop.run_until_complete(aiohttp_client(app))


@pytest.fixture
def saml_response_base64():
    raw = """<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response Destination="http://localhost:8888/saml" ID="id7724889827497172332527640" InResponseTo="ONELOGIN_57aafda050ce7885bb96e09cf0b2b6674ae3d37a" IssueInstant="2021-04-19T14:25:06.900Z" Version="2.0"
xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
xmlns:xs="http://www.w3.org/2001/XMLSchema">
<saml2:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity"
    xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">http://www.okta.com/exkbmdi9avpiwtanV5d6
</saml2:Issuer>
<ds:Signature
    xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <ds:SignedInfo>
        <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
        <ds:Reference URI="#id7724889827497172332527640">
            <ds:Transforms>
                <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
                <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
                    <ec:InclusiveNamespaces PrefixList="xs"
                        xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                    </ds:Transform>
                </ds:Transforms>
                <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                <ds:DigestValue>P7Ac1p6XbgC1WWpIZkI5CPU3Vc+GBVwEVsmXguqRZb0=</ds:DigestValue>
            </ds:Reference>
        </ds:SignedInfo>
        <ds:SignatureValue>HNUvVN8bsLn/1RJhxnqGitMMbi/9p7W+GxqpjBOFP9InpClTsM0iiFvP1vPjWx+JA3/oujfCKYeed+FWItI4vjehcvAHwhRtAcDVg1nBnweLq+41n5aEILaqQS2LQNcwKI0tdCWy9gRiAVfHc/MEqFHoYas61pDuJZUyrMlTtB+rEC1XNEwOXm+Jtog3S2zg57aJt5Sxq8Vau66rIZCl3FIjeKIqahWjvack7g4SPaGdvvxmb8kmdl0HkGzey21/F2bAFpY+KfTeHa/0prLkXA5iRurncipaIcX4JCAG1jAB7yxl3m9fSJoiFSnfgAKPwHehmo5nOU+vFkwlxNRVdw==</ds:SignatureValue>
        <ds:KeyInfo>
            <ds:X509Data>
                <ds:X509Certificate>MIIDqDCCApCgAwIBAgIGAXditqMWMA0GCSqGSIb3DQEBCwUAMIGUMQswCQYDVQQGEwJVUzETMBEG
A1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwET2t0YTEU
MBIGA1UECwwLU1NPUHJvdmlkZXIxFTATBgNVBAMMDGRldi02OTEzMzA0NzEcMBoGCSqGSIb3DQEJ
ARYNaW5mb0Bva3RhLmNvbTAeFw0yMTAyMDIxMjI2NTJaFw0zMTAyMDIxMjI3NTJaMIGUMQswCQYD
VQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsG
A1UECgwET2t0YTEUMBIGA1UECwwLU1NPUHJvdmlkZXIxFTATBgNVBAMMDGRldi02OTEzMzA0NzEc
MBoGCSqGSIb3DQEJARYNaW5mb0Bva3RhLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
ggEBAIz3vSiwVWr7iUyKHMpACjlgSJUKrll5qsXTl8cX5Fkj/OgAaWIBWcpkpdT7iARSwqQhcTYN
fHSsOknTcOD1uh1yjM5ycCQx0UO/n06+apP1GahDNfLFfbt2KLC1FvcmMqz8AUB/EEXvxVSkn0oU
KIYYe9jBLGIh6fQUdKfljSv6Ux/RUtTKRhoOSxOnLrX8HP7fHAjSZfPV8ODomuVAueOwitaYEf+Q
RBmxC3oyx9bMjfOusWUrlVeLwOrOh4CJBZZrxRjARp5p0jexIh405A4cS3m+R5cP+9jW6GVnhiEo
rJZOn1d8OuZ1nCvI9FZPsf5ngdwpKW0T+zCuQMq80tkCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEA
VnnRV0VhBkccaO12opDxNBRtWVSPkb52nMWDaXVE5J2H0gnL+9ZrFnlNMmRIeqkSeGFG6hvbWxrI
cW7QSsTDmMfWyxFjef5/9qHGhLCImFLBkraW+OxZmC29ftOocJAzXAGwJadaqrDn38BlgzwJSDRe
1xghXRNbYaejyGmCoNuriVXbNJFhoFU9JsXeVCw1gZ9HXP98Ud06c/MzrchlwMpSLZpu6HgtulLN
OTH+zakpmj3nVncVoI8r49fcjoS0811vfC3e/4yM+Tx0n3Bz6RaCnr+r0kG0O2d0rzLYWbrzIAcE
u4y7YIi6ym5t8VYjYlsMarT0OQYppp+6WtiF3g==</ds:X509Certificate>
            </ds:X509Data>
        </ds:KeyInfo>
    </ds:Signature>
    <saml2p:Status
        xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol">
        <saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
    </saml2p:Status>
    <saml2:Assertion ID="id7724889827571923973066861" IssueInstant="2021-04-19T14:25:06.900Z" Version="2.0"
        xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"
        xmlns:xs="http://www.w3.org/2001/XMLSchema">
        <saml2:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity"
            xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">http://www.okta.com/exkbmdi9avpiwtanV5d6
        </saml2:Issuer>
        <ds:Signature
            xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
            <ds:SignedInfo>
                <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
                <ds:Reference URI="#id7724889827571923973066861">
                    <ds:Transforms>
                        <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
                        <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
                            <ec:InclusiveNamespaces PrefixList="xs"
                                xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                            </ds:Transform>
                        </ds:Transforms>
                        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                        <ds:DigestValue>3cCpjBoy5U7Aq4tuV0xuzz2sw8x5SkmM2hkm2LML3IQ=</ds:DigestValue>
                    </ds:Reference>
                </ds:SignedInfo>
                <ds:SignatureValue>U9EjKnX7B8nkTBhduO2XZnBOjkVxar0Nb3Iwt18EMBmhDVzwkfK2Jf3EQ3d/BQZeLCMAJugTPKOCFkCXhiCZ2TFjDfZkI6oVHsjXpLj64LUTGqWpDtp6gkMqUs3sqh2ioMMkgUxou/viSb26RTRZGZSbpHBGm3JLozB1XfdfZx9mvTieh4Cr7nfsbfqPODwnZ/bK9lyWR8c0PDQ8QSUqmffZcAqO1glrX/XQyVzd89FDQrBY2YGOvTWRLYbt0keIFGSMiAL9HcOMnOAZIaMNH8XJf9KGdzYCvBfOgjsz6Xl8aE3yNHU44YeTv4hIQ/o0yBipVEjBfmEYv2+MfcjmXQ==</ds:SignatureValue>
                <ds:KeyInfo>
                    <ds:X509Data>
                        <ds:X509Certificate>MIIDqDCCApCgAwIBAgIGAXditqMWMA0GCSqGSIb3DQEBCwUAMIGUMQswCQYDVQQGEwJVUzETMBEG
A1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwET2t0YTEU
MBIGA1UECwwLU1NPUHJvdmlkZXIxFTATBgNVBAMMDGRldi02OTEzMzA0NzEcMBoGCSqGSIb3DQEJ
ARYNaW5mb0Bva3RhLmNvbTAeFw0yMTAyMDIxMjI2NTJaFw0zMTAyMDIxMjI3NTJaMIGUMQswCQYD
VQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsG
A1UECgwET2t0YTEUMBIGA1UECwwLU1NPUHJvdmlkZXIxFTATBgNVBAMMDGRldi02OTEzMzA0NzEc
MBoGCSqGSIb3DQEJARYNaW5mb0Bva3RhLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
ggEBAIz3vSiwVWr7iUyKHMpACjlgSJUKrll5qsXTl8cX5Fkj/OgAaWIBWcpkpdT7iARSwqQhcTYN
fHSsOknTcOD1uh1yjM5ycCQx0UO/n06+apP1GahDNfLFfbt2KLC1FvcmMqz8AUB/EEXvxVSkn0oU
KIYYe9jBLGIh6fQUdKfljSv6Ux/RUtTKRhoOSxOnLrX8HP7fHAjSZfPV8ODomuVAueOwitaYEf+Q
RBmxC3oyx9bMjfOusWUrlVeLwOrOh4CJBZZrxRjARp5p0jexIh405A4cS3m+R5cP+9jW6GVnhiEo
rJZOn1d8OuZ1nCvI9FZPsf5ngdwpKW0T+zCuQMq80tkCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEA
VnnRV0VhBkccaO12opDxNBRtWVSPkb52nMWDaXVE5J2H0gnL+9ZrFnlNMmRIeqkSeGFG6hvbWxrI
cW7QSsTDmMfWyxFjef5/9qHGhLCImFLBkraW+OxZmC29ftOocJAzXAGwJadaqrDn38BlgzwJSDRe
1xghXRNbYaejyGmCoNuriVXbNJFhoFU9JsXeVCw1gZ9HXP98Ud06c/MzrchlwMpSLZpu6HgtulLN
OTH+zakpmj3nVncVoI8r49fcjoS0811vfC3e/4yM+Tx0n3Bz6RaCnr+r0kG0O2d0rzLYWbrzIAcE
u4y7YIi6ym5t8VYjYlsMarT0OQYppp+6WtiF3g==</ds:X509Certificate>
                    </ds:X509Data>
                </ds:KeyInfo>
            </ds:Signature>
            <saml2:Subject
                xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">
                <saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">red</saml2:NameID>
                <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                    <saml2:SubjectConfirmationData InResponseTo="ONELOGIN_57aafda050ce7885bb96e09cf0b2b6674ae3d37a" NotOnOrAfter="2021-04-19T14:30:06.900Z" Recipient="http://localhost:8888/saml"/>
                </saml2:SubjectConfirmation>
            </saml2:Subject>
            <saml2:Conditions NotBefore="2021-04-19T14:20:06.900Z" NotOnOrAfter="2021-04-19T14:30:06.900Z"
                xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">
                <saml2:AudienceRestriction>
                    <saml2:Audience>http://localhost:8888</saml2:Audience>
                </saml2:AudienceRestriction>
            </saml2:Conditions>
            <saml2:AuthnStatement AuthnInstant="2021-04-19T14:25:06.900Z" SessionIndex="ONELOGIN_57aafda050ce7885bb96e09cf0b2b6674ae3d37a"
                xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">
                <saml2:AuthnContext>
                    <saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef>
                </saml2:AuthnContext>
            </saml2:AuthnStatement>
            <saml2:AttributeStatement
                xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">
                <saml2:Attribute Name="username" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified">
                    <saml2:AttributeValue
                        xmlns:xs="http://www.w3.org/2001/XMLSchema"
                        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">testuser@caldera.caldera
                    </saml2:AttributeValue>
                </saml2:Attribute>
            </saml2:AttributeStatement>
        </saml2:Assertion>
    </saml2p:Response>
    """
    #return b64encode(raw.encode('utf-8')).decode('utf-8')
    return 'PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz48c2FtbDJwOlJlc3BvbnNlIERlc3RpbmF0aW9uPSJodHRwOi8vbG9jYWxob3N0Ojg4ODgvc2FtbCIgSUQ9ImlkNzcyNzY5MzQzNzA4NjU1NTIxMzYxMDg2MjgiIEluUmVzcG9uc2VUbz0iT05FTE9HSU5fYTg2YzY4MGIxNmUzY2ZlZjlmNjYwNjIyMTBiZGIwMzAzNDkwNjk2OSIgSXNzdWVJbnN0YW50PSIyMDIxLTA0LTE5VDE1OjExOjQ4LjQ5N1oiIFZlcnNpb249IjIuMCIgeG1sbnM6c2FtbDJwPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6cHJvdG9jb2wiIHhtbG5zOnhzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYSI+PHNhbWwyOklzc3VlciBGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpuYW1laWQtZm9ybWF0OmVudGl0eSIgeG1sbnM6c2FtbDI9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphc3NlcnRpb24iPmh0dHA6Ly93d3cub2t0YS5jb20vZXhrYm1kaTlhdnBpd3RhblY1ZDY8L3NhbWwyOklzc3Vlcj48ZHM6U2lnbmF0dXJlIHhtbG5zOmRzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjIj48ZHM6U2lnbmVkSW5mbz48ZHM6Q2Fub25pY2FsaXphdGlvbk1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIyIvPjxkczpTaWduYXR1cmVNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGRzaWctbW9yZSNyc2Etc2hhMjU2Ii8+PGRzOlJlZmVyZW5jZSBVUkk9IiNpZDc3Mjc2OTM0MzcwODY1NTUyMTM2MTA4NjI4Ij48ZHM6VHJhbnNmb3Jtcz48ZHM6VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI2VudmVsb3BlZC1zaWduYXR1cmUiLz48ZHM6VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIj48ZWM6SW5jbHVzaXZlTmFtZXNwYWNlcyBQcmVmaXhMaXN0PSJ4cyIgeG1sbnM6ZWM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIyIvPjwvZHM6VHJhbnNmb3JtPjwvZHM6VHJhbnNmb3Jtcz48ZHM6RGlnZXN0TWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8wNC94bWxlbmMjc2hhMjU2Ii8+PGRzOkRpZ2VzdFZhbHVlPjl5WS94S0xwZHV1TSs0SE5vcnQraE05U3lKNzhvRVhQOXFTSUlsNG94VW89PC9kczpEaWdlc3RWYWx1ZT48L2RzOlJlZmVyZW5jZT48L2RzOlNpZ25lZEluZm8+PGRzOlNpZ25hdHVyZVZhbHVlPmVUTnpQV2k5cEdMTEdUSzNsY2NlbGNqa2RIczdhdE56bE8xMWtnMWgvY3dtcmxUMVRya1FUSDk1bmRrZ2J2Y3hBUXNHZnY4bHY3UDZHMHpLMWFHZ2ZydnJKaG1HYVZVTGR2aDFMdFB4MFFBS1pseFRkdmxjWFowT3EyeFA1NlQ5Q1M0ZGhKc2xQbTJOdW50bzl3UkVsa201UWpPb3B1ZjRDczBBZkhZTVVrOGxaTWhTUWdsSjhWTms1MDlwVVlpNzYxYW1yN1dvbExFUXpaTEsvWlZoSm0rWnNPTm4yN0JDUDJ6aStNUzlObVF4d0swYlNLSTRKdG1sODBJQll5ZGtuVUhObHNzZ2UzOUdqN1FFQUYycFUzd3hqdCtUZ29Ed2RCQmQzUHN2cmVWWXpQV3lWcndqeGdzRmhJdWIvcmFRWG9TUFV4Zmtuc1Ywa2VtaFhHejg1UT09PC9kczpTaWduYXR1cmVWYWx1ZT48ZHM6S2V5SW5mbz48ZHM6WDUwOURhdGE+PGRzOlg1MDlDZXJ0aWZpY2F0ZT5NSUlEcURDQ0FwQ2dBd0lCQWdJR0FYZGl0cU1XTUEwR0NTcUdTSWIzRFFFQkN3VUFNSUdVTVFzd0NRWURWUVFHRXdKVlV6RVRNQkVHCkExVUVDQXdLUTJGc2FXWnZjbTVwWVRFV01CUUdBMVVFQnd3TlUyRnVJRVp5WVc1amFYTmpiekVOTUFzR0ExVUVDZ3dFVDJ0MFlURVUKTUJJR0ExVUVDd3dMVTFOUFVISnZkbWxrWlhJeEZUQVRCZ05WQkFNTURHUmxkaTAyT1RFek16QTBOekVjTUJvR0NTcUdTSWIzRFFFSgpBUllOYVc1bWIwQnZhM1JoTG1OdmJUQWVGdzB5TVRBeU1ESXhNakkyTlRKYUZ3MHpNVEF5TURJeE1qSTNOVEphTUlHVU1Rc3dDUVlEClZRUUdFd0pWVXpFVE1CRUdBMVVFQ0F3S1EyRnNhV1p2Y201cFlURVdNQlFHQTFVRUJ3d05VMkZ1SUVaeVlXNWphWE5qYnpFTk1Bc0cKQTFVRUNnd0VUMnQwWVRFVU1CSUdBMVVFQ3d3TFUxTlBVSEp2ZG1sa1pYSXhGVEFUQmdOVkJBTU1ER1JsZGkwMk9URXpNekEwTnpFYwpNQm9HQ1NxR1NJYjNEUUVKQVJZTmFXNW1iMEJ2YTNSaExtTnZiVENDQVNJd0RRWUpLb1pJaHZjTkFRRUJCUUFEZ2dFUEFEQ0NBUW9DCmdnRUJBSXozdlNpd1ZXcjdpVXlLSE1wQUNqbGdTSlVLcmxsNXFzWFRsOGNYNUZrai9PZ0FhV0lCV2Nwa3BkVDdpQVJTd3FRaGNUWU4KZkhTc09rblRjT0QxdWgxeWpNNXljQ1F4MFVPL24wNithcFAxR2FoRE5mTEZmYnQyS0xDMUZ2Y21NcXo4QVVCL0VFWHZ4VlNrbjBvVQpLSVlZZTlqQkxHSWg2ZlFVZEtmbGpTdjZVeC9SVXRUS1Job09TeE9uTHJYOEhQN2ZIQWpTWmZQVjhPRG9tdVZBdWVPd2l0YVlFZitRClJCbXhDM295eDliTWpmT3VzV1VybFZlTHdPck9oNENKQlpacnhSakFScDVwMGpleEloNDA1QTRjUzNtK1I1Y1ArOWpXNkdWbmhpRW8KckpaT24xZDhPdVoxbkN2STlGWlBzZjVuZ2R3cEtXMFQrekN1UU1xODB0a0NBd0VBQVRBTkJna3Foa2lHOXcwQkFRc0ZBQU9DQVFFQQpWbm5SVjBWaEJrY2NhTzEyb3BEeE5CUnRXVlNQa2I1Mm5NV0RhWFZFNUoySDBnbkwrOVpyRm5sTk1tUkllcWtTZUdGRzZodmJXeHJJCmNXN1FTc1REbU1mV3l4RmplZjUvOXFIR2hMQ0ltRkxCa3JhVytPeFptQzI5ZnRPb2NKQXpYQUd3SmFkYXFyRG4zOEJsZ3p3SlNEUmUKMXhnaFhSTmJZYWVqeUdtQ29OdXJpVlhiTkpGaG9GVTlKc1hlVkN3MWdaOUhYUDk4VWQwNmMvTXpyY2hsd01wU0xacHU2SGd0dWxMTgpPVEgremFrcG1qM25WbmNWb0k4cjQ5ZmNqb1MwODExdmZDM2UvNHlNK1R4MG4zQno2UmFDbnIrcjBrRzBPMmQwcnpMWVdicnpJQWNFCnU0eTdZSWk2eW01dDhWWWpZbHNNYXJUME9RWXBwcCs2V3RpRjNnPT08L2RzOlg1MDlDZXJ0aWZpY2F0ZT48L2RzOlg1MDlEYXRhPjwvZHM6S2V5SW5mbz48L2RzOlNpZ25hdHVyZT48c2FtbDJwOlN0YXR1cyB4bWxuczpzYW1sMnA9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpwcm90b2NvbCI+PHNhbWwycDpTdGF0dXNDb2RlIFZhbHVlPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6c3RhdHVzOlN1Y2Nlc3MiLz48L3NhbWwycDpTdGF0dXM+PHNhbWwyOkFzc2VydGlvbiBJRD0iaWQ3NzI3NjkzNDM3MTU3MjI4MzI2MjI2MzY0IiBJc3N1ZUluc3RhbnQ9IjIwMjEtMDQtMTlUMTU6MTE6NDguNDk3WiIgVmVyc2lvbj0iMi4wIiB4bWxuczpzYW1sMj0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFzc2VydGlvbiIgeG1sbnM6eHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hIj48c2FtbDI6SXNzdWVyIEZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOm5hbWVpZC1mb3JtYXQ6ZW50aXR5IiB4bWxuczpzYW1sMj0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFzc2VydGlvbiI+aHR0cDovL3d3dy5va3RhLmNvbS9leGtibWRpOWF2cGl3dGFuVjVkNjwvc2FtbDI6SXNzdWVyPjxkczpTaWduYXR1cmUgeG1sbnM6ZHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyMiPjxkczpTaWduZWRJbmZvPjxkczpDYW5vbmljYWxpemF0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+PGRzOlNpZ25hdHVyZU1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZHNpZy1tb3JlI3JzYS1zaGEyNTYiLz48ZHM6UmVmZXJlbmNlIFVSST0iI2lkNzcyNzY5MzQzNzE1NzIyODMyNjIyNjM2NCI+PGRzOlRyYW5zZm9ybXM+PGRzOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNlbnZlbG9wZWQtc2lnbmF0dXJlIi8+PGRzOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIyI+PGVjOkluY2x1c2l2ZU5hbWVzcGFjZXMgUHJlZml4TGlzdD0ieHMiIHhtbG5zOmVjPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiLz48L2RzOlRyYW5zZm9ybT48L2RzOlRyYW5zZm9ybXM+PGRzOkRpZ2VzdE1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZW5jI3NoYTI1NiIvPjxkczpEaWdlc3RWYWx1ZT5ZT1IyWnlhdGpOMEhlK1AxbFQycmJCaTczUWZQdVBjeTQ1encvQkpFY2JnPTwvZHM6RGlnZXN0VmFsdWU+PC9kczpSZWZlcmVuY2U+PC9kczpTaWduZWRJbmZvPjxkczpTaWduYXR1cmVWYWx1ZT5JVjNjT0pKR2N2dHo5VFJoWGhpZHluTm1wR0tEVm1VSmlPTnJqRmV4emhHSEYvbHdWRmFINnVWSXM4UFRoeUU3VFJYWUFYM1M1WkRVRys1OVVhcnlDZ3RHZ2JLVEZLcHlsOWU5ZEtibkI4Y2xPaEZCNHB6VlFpTzlIN2NmRGVhZ2hWL2xDQXFKVDV1SEZzRC85VldSVlN1UVBLeDFvNlVMZDJicHE2UFVwZGxtaDFqYythY2pLemNJN3BuL3pNTFFhYkxHb2c4cFRWMk9jTTVkOWdXZjB3T2VaNnR4bUhOeE1kb2JOaHY4cWxObkk1dzdIRmNUTmJpSU9aSE5jWWtqZFZUTXNKUFFac1paa2FOejNSMDRSaXVWM21sRGk2UFN2U3FlMDlEUmp2Z1lkdTRhNFlSRHhIMmxiajY3bGdkNm5aQ3BWTStKdjRhek93eCtKYnJQU1E9PTwvZHM6U2lnbmF0dXJlVmFsdWU+PGRzOktleUluZm8+PGRzOlg1MDlEYXRhPjxkczpYNTA5Q2VydGlmaWNhdGU+TUlJRHFEQ0NBcENnQXdJQkFnSUdBWGRpdHFNV01BMEdDU3FHU0liM0RRRUJDd1VBTUlHVU1Rc3dDUVlEVlFRR0V3SlZVekVUTUJFRwpBMVVFQ0F3S1EyRnNhV1p2Y201cFlURVdNQlFHQTFVRUJ3d05VMkZ1SUVaeVlXNWphWE5qYnpFTk1Bc0dBMVVFQ2d3RVQydDBZVEVVCk1CSUdBMVVFQ3d3TFUxTlBVSEp2ZG1sa1pYSXhGVEFUQmdOVkJBTU1ER1JsZGkwMk9URXpNekEwTnpFY01Cb0dDU3FHU0liM0RRRUoKQVJZTmFXNW1iMEJ2YTNSaExtTnZiVEFlRncweU1UQXlNREl4TWpJMk5USmFGdzB6TVRBeU1ESXhNakkzTlRKYU1JR1VNUXN3Q1FZRApWUVFHRXdKVlV6RVRNQkVHQTFVRUNBd0tRMkZzYVdadmNtNXBZVEVXTUJRR0ExVUVCd3dOVTJGdUlFWnlZVzVqYVhOamJ6RU5NQXNHCkExVUVDZ3dFVDJ0MFlURVVNQklHQTFVRUN3d0xVMU5QVUhKdmRtbGtaWEl4RlRBVEJnTlZCQU1NREdSbGRpMDJPVEV6TXpBME56RWMKTUJvR0NTcUdTSWIzRFFFSkFSWU5hVzVtYjBCdmEzUmhMbU52YlRDQ0FTSXdEUVlKS29aSWh2Y05BUUVCQlFBRGdnRVBBRENDQVFvQwpnZ0VCQUl6M3ZTaXdWV3I3aVV5S0hNcEFDamxnU0pVS3JsbDVxc1hUbDhjWDVGa2ovT2dBYVdJQldjcGtwZFQ3aUFSU3dxUWhjVFlOCmZIU3NPa25UY09EMXVoMXlqTTV5Y0NReDBVTy9uMDYrYXBQMUdhaEROZkxGZmJ0MktMQzFGdmNtTXF6OEFVQi9FRVh2eFZTa24wb1UKS0lZWWU5akJMR0loNmZRVWRLZmxqU3Y2VXgvUlV0VEtSaG9PU3hPbkxyWDhIUDdmSEFqU1pmUFY4T0RvbXVWQXVlT3dpdGFZRWYrUQpSQm14QzNveXg5Yk1qZk91c1dVcmxWZUx3T3JPaDRDSkJaWnJ4UmpBUnA1cDBqZXhJaDQwNUE0Y1MzbStSNWNQKzlqVzZHVm5oaUVvCnJKWk9uMWQ4T3VaMW5Ddkk5RlpQc2Y1bmdkd3BLVzBUK3pDdVFNcTgwdGtDQXdFQUFUQU5CZ2txaGtpRzl3MEJBUXNGQUFPQ0FRRUEKVm5uUlYwVmhCa2NjYU8xMm9wRHhOQlJ0V1ZTUGtiNTJuTVdEYVhWRTVKMkgwZ25MKzlackZubE5NbVJJZXFrU2VHRkc2aHZiV3hySQpjVzdRU3NURG1NZld5eEZqZWY1LzlxSEdoTENJbUZMQmtyYVcrT3habUMyOWZ0T29jSkF6WEFHd0phZGFxckRuMzhCbGd6d0pTRFJlCjF4Z2hYUk5iWWFlanlHbUNvTnVyaVZYYk5KRmhvRlU5SnNYZVZDdzFnWjlIWFA5OFVkMDZjL016cmNobHdNcFNMWnB1NkhndHVsTE4KT1RIK3pha3BtajNuVm5jVm9JOHI0OWZjam9TMDgxMXZmQzNlLzR5TStUeDBuM0J6NlJhQ25yK3Iwa0cwTzJkMHJ6TFlXYnJ6SUFjRQp1NHk3WUlpNnltNXQ4VllqWWxzTWFyVDBPUVlwcHArNld0aUYzZz09PC9kczpYNTA5Q2VydGlmaWNhdGU+PC9kczpYNTA5RGF0YT48L2RzOktleUluZm8+PC9kczpTaWduYXR1cmU+PHNhbWwyOlN1YmplY3QgeG1sbnM6c2FtbDI9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphc3NlcnRpb24iPjxzYW1sMjpOYW1lSUQgRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoxLjE6bmFtZWlkLWZvcm1hdDp1bnNwZWNpZmllZCI+cmVkPC9zYW1sMjpOYW1lSUQ+PHNhbWwyOlN1YmplY3RDb25maXJtYXRpb24gTWV0aG9kPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6Y206YmVhcmVyIj48c2FtbDI6U3ViamVjdENvbmZpcm1hdGlvbkRhdGEgSW5SZXNwb25zZVRvPSJPTkVMT0dJTl9hODZjNjgwYjE2ZTNjZmVmOWY2NjA2MjIxMGJkYjAzMDM0OTA2OTY5IiBOb3RPbk9yQWZ0ZXI9IjIwMjEtMDQtMTlUMTU6MTY6NDguNDk3WiIgUmVjaXBpZW50PSJodHRwOi8vbG9jYWxob3N0Ojg4ODgvc2FtbCIvPjwvc2FtbDI6U3ViamVjdENvbmZpcm1hdGlvbj48L3NhbWwyOlN1YmplY3Q+PHNhbWwyOkNvbmRpdGlvbnMgTm90QmVmb3JlPSIyMDIxLTA0LTE5VDE1OjA2OjQ4LjQ5N1oiIE5vdE9uT3JBZnRlcj0iMjAyMS0wNC0xOVQxNToxNjo0OC40OTdaIiB4bWxuczpzYW1sMj0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFzc2VydGlvbiI+PHNhbWwyOkF1ZGllbmNlUmVzdHJpY3Rpb24+PHNhbWwyOkF1ZGllbmNlPmh0dHA6Ly9sb2NhbGhvc3Q6ODg4ODwvc2FtbDI6QXVkaWVuY2U+PC9zYW1sMjpBdWRpZW5jZVJlc3RyaWN0aW9uPjwvc2FtbDI6Q29uZGl0aW9ucz48c2FtbDI6QXV0aG5TdGF0ZW1lbnQgQXV0aG5JbnN0YW50PSIyMDIxLTA0LTE5VDE1OjExOjQ4LjQ5N1oiIFNlc3Npb25JbmRleD0iT05FTE9HSU5fYTg2YzY4MGIxNmUzY2ZlZjlmNjYwNjIyMTBiZGIwMzAzNDkwNjk2OSIgeG1sbnM6c2FtbDI9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphc3NlcnRpb24iPjxzYW1sMjpBdXRobkNvbnRleHQ+PHNhbWwyOkF1dGhuQ29udGV4dENsYXNzUmVmPnVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphYzpjbGFzc2VzOlBhc3N3b3JkUHJvdGVjdGVkVHJhbnNwb3J0PC9zYW1sMjpBdXRobkNvbnRleHRDbGFzc1JlZj48L3NhbWwyOkF1dGhuQ29udGV4dD48L3NhbWwyOkF1dGhuU3RhdGVtZW50PjxzYW1sMjpBdHRyaWJ1dGVTdGF0ZW1lbnQgeG1sbnM6c2FtbDI9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphc3NlcnRpb24iPjxzYW1sMjpBdHRyaWJ1dGUgTmFtZT0idXNlcm5hbWUiIE5hbWVGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphdHRybmFtZS1mb3JtYXQ6dW5zcGVjaWZpZWQiPjxzYW1sMjpBdHRyaWJ1dGVWYWx1ZSB4bWxuczp4cz0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEiIHhtbG5zOnhzaT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEtaW5zdGFuY2UiIHhzaTp0eXBlPSJ4czpzdHJpbmciPnRlc3R1c2VyQGNhbGRlcmEuY2FsZGVyYTwvc2FtbDI6QXR0cmlidXRlVmFsdWU+PC9zYW1sMjpBdHRyaWJ1dGU+PC9zYW1sMjpBdHRyaWJ1dGVTdGF0ZW1lbnQ+PC9zYW1sMjpBc3NlcnRpb24+PC9zYW1sMnA6UmVzcG9uc2U+'


@pytest.fixture
def saml_post_data(saml_response_base64):
    return dict(
        SAMLResponse=saml_response_base64,
        RelayState='http://localhost:8888/'
    )


@pytest.fixture
def saml_settings():
    return {
        "strict": False,
        "debug": True,
        "sp": {
            "entityId": "http://localhost:8888",
            "assertionConsumerService": {
                "url": "http://localhost:8888/saml",
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
            }
        },
        "idp": {
            "entityId": "http://idp.example.com/",
            "singleSignOnService": {
                "url": "http://idp.example.com/SSOService.php",
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
            },
            "x509cert": "MIIDqDCCApCgAwIBAgIGAXditqMWMA0GCSqGSIb3DQEBCwUAMIGUMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwET2t0YTEUMBIGA1UECwwLU1NPUHJvdmlkZXIxFTATBgNVBAMMDGRldi02OTEzMzA0NzEcMBoGCSqGSIb3DQEJARYNaW5mb0Bva3RhLmNvbTAeFw0yMTAyMDIxMjI2NTJaFw0zMTAyMDIxMjI3NTJaMIGUMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwET2t0YTEUMBIGA1UECwwLU1NPUHJvdmlkZXIxFTATBgNVBAMMDGRldi02OTEzMzA0NzEcMBoGCSqGSIb3DQEJARYNaW5mb0Bva3RhLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAIz3vSiwVWr7iUyKHMpACjlgSJUKrll5qsXTl8cX5Fkj/OgAaWIBWcpkpdT7iARSwqQhcTYNfHSsOknTcOD1uh1yjM5ycCQx0UO/n06+apP1GahDNfLFfbt2KLC1FvcmMqz8AUB/EEXvxVSkn0oUKIYYe9jBLGIh6fQUdKfljSv6Ux/RUtTKRhoOSxOnLrX8HP7fHAjSZfPV8ODomuVAueOwitaYEf+QRBmxC3oyx9bMjfOusWUrlVeLwOrOh4CJBZZrxRjARp5p0jexIh405A4cS3m+R5cP+9jW6GVnhiEorJZOn1d8OuZ1nCvI9FZPsf5ngdwpKW0T+zCuQMq80tkCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAVnnRV0VhBkccaO12opDxNBRtWVSPkb52nMWDaXVE5J2H0gnL+9ZrFnlNMmRIeqkSeGFG6hvbWxrIcW7QSsTDmMfWyxFjef5/9qHGhLCImFLBkraW+OxZmC29ftOocJAzXAGwJadaqrDn38BlgzwJSDRe1xghXRNbYaejyGmCoNuriVXbNJFhoFU9JsXeVCw1gZ9HXP98Ud06c/MzrchlwMpSLZpu6HgtulLNOTH+zakpmj3nVncVoI8r49fcjoS0811vfC3e/4yM+Tx0n3Bz6RaCnr+r0kG0O2d0rzLYWbrzIAcEu4y7YIi6ym5t8VYjYlsMarT0OQYppp+6WtiF3g=="
        },
    }


@pytest.fixture
async def setup_saml(saml_settings):
    login_handler = SamlLoginHandler(BaseService.get_services())
    await BaseService.get_service('auth_svc').set_login_handlers(
        BaseService.get_services(),
        login_handler
    )
    saml_svc = BaseService.get_service('saml_svc')
    saml_svc._saml_config = saml_settings


async def test_saml_redirect(aiohttp_client, setup_saml):
    resp = await aiohttp_client.post('/', allow_redirects=False)
    assert resp.status == HTTPStatus.FOUND
    assert resp.headers.get('Location').startswith('http://idp.example.com/SSOService.php?SAMLRequest=')


async def test_saml_login(aiohttp_client, setup_saml, saml_post_data):
    resp = await aiohttp_client.post('/saml', allow_redirects=False, data=saml_post_data)
    assert resp.status == HTTPStatus.FOUND
    assert resp.headers.get('Location') == '/'
    assert 'API_SESSION' in resp.cookies