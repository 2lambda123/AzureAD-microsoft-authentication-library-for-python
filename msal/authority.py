import re

import requests

from .exceptions import MsalServiceError


WORLD_WIDE = 'login.microsoftonline.com'  # There was an alias login.windows.net
WELL_KNOWN_AUTHORITY_HOSTS = set([
    WORLD_WIDE,
    'login.chinacloudapi.cn',
    'login-us.microsoftonline.com',
    'login.microsoftonline.us',
    'login.microsoftonline.de',
    ])


class Authority(object):
    """This class represents an (already-validated) authority.

    Once constructed, it contains members named "*_endpoint" for this instance.
    TODO: It will also cache the previously-validated authority instances.
    """
    AUTHORIZE_ENDPOINT_PATH = '/oauth2/authorize'
    TOKEN_ENDPOINT_PATH = '/oauth2/token'

    def __init__(self, authority_url, validate_authority=True):
        """Creates an authority instance, and also validates it.

        :param validate_authority:
            The Authority validation process actually checks two parts:
            instance (a.k.a. host) and tenant. We always do a tenant discovery.
            This parameter only controls whether an instance discovery will be
            performed.
        """
        canonicalized, host, tenant = canonicalize(authority_url)
        tenant_discovery_endpoint = (  # Hard code a V2 pattern as default value
            'https://{}/{}/v2.0/.well-known/openid-configuration'
            .format(WORLD_WIDE, tenant))
        self.authorization_endpoint = canonicalized + self.AUTHORIZE_ENDPOINT_PATH
        self.token_endpoint = canonicalized + self.TOKEN_ENDPOINT_PATH
        if tenant == 'adfs':  # But, what if there is a tenant named "adfs"?
           return  # Skip instance discovery and tenant discovery
        if validate_authority and host not in WELL_KNOWN_AUTHORITY_HOSTS:
            tenant_discovery_endpoint = instance_discovery(
                canonicalized + "/oauth2/v2.0/authorize")
        openid_config = tenant_discovery(tenant_discovery_endpoint)
        self.authorization_endpoint = openid_config['authorization_endpoint']
        self.token_endpoint = openid_config['token_endpoint']


def canonicalize(url):
    # Returns (canonicalized_url, host, tenant). Raises ValueError on errors.
    match_object = re.match("https://([^/]+)/([^/\?#]+)", url.lower())
    if not match_object:
        raise ValueError(
            "Your given address (%s) should consist of "
            "an https url with a minimum of one segment in a path: e.g. "
            "https://login.microsoftonline.com/<tenant_name>" % url)
    return match_object.group(0), match_object.group(1), match_object.group(2)

def instance_discovery(url, response=None):  # Returns tenant discovery endpoint
    resp = requests.get(  # Note: This URL seemingly returns V1 endpoint only
        'https://{}/common/discovery/instance'.format(WORLD_WIDE),
        params={'authorization_endpoint': url, 'api-version': '1.0'})
    payload = response or resp.json()
    if 'tenant_discovery_endpoint' not in payload:
        raise MsalServiceError(status_code=resp.status_code, **payload)
    return payload['tenant_discovery_endpoint']

def tenant_discovery(tenant_discovery_endpoint):  # Returns Openid Configuration
    resp = requests.get(tenant_discovery_endpoint)
    payload = resp.json()
    if 'authorization_endpoint' in payload and 'token_endpoint' in payload:
        return payload
    raise MsalServiceError(status_code=resp.status_code, **payload)

