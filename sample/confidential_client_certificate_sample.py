"""
The configuration file would look like this (sans those // comments):

{
    "authority": "https://login.microsoftonline.com/Enter_the_Tenant_Name_Here",
    "client_id": "your_client_id came from https://learn.microsoft.com/entra/identity-platform/quickstart-register-app",
    "scope": ["https://graph.microsoft.com/.default"],
        // Specific to Client Credentials Grant i.e. acquire_token_for_client(),
        // you don't specify, in the code, the individual scopes you want to access.
        // Instead, you statically declared them when registering your application.
        // Therefore the only possible scope is "resource/.default"
        // (here "https://graph.microsoft.com/.default")
        // which means "the static permissions defined in the application".

    "thumbprint": "790E... The thumbprint generated by AAD when you upload your public cert",
    "private_key_file": "filename.pem",
        // For information about generating thumbprint and private key file, refer:
        // https://github.com/AzureAD/microsoft-authentication-library-for-python/wiki/Client-Credentials#client-credentials-with-certificate

    "endpoint": "https://graph.microsoft.com/v1.0/users"
        // For this resource to work, you need to visit Application Permissions
        // page in portal, declare scope User.Read.All, which needs admin consent
        // https://github.com/Azure-Samples/ms-identity-python-daemon/blob/master/2-Call-MsGraph-WithCertificate/README.md
}

You can then run this sample with a JSON configuration file:

    python sample.py parameters.json
"""

import sys  # For simplicity, we'll read config file from 1st CLI param sys.argv[1]
import json
import logging
import time

import requests
import msal


# Optional logging
# logging.basicConfig(level=logging.DEBUG)  # Enable DEBUG log for entire script
# logging.getLogger("msal").setLevel(logging.INFO)  # Optionally disable MSAL DEBUG logs

config = json.load(open(sys.argv[1]))

# If for whatever reason you plan to recreate same ClientApplication periodically,
# you shall create one global token cache and reuse it by each ClientApplication
global_token_cache = msal.TokenCache()  # The TokenCache() is in-memory.
    # See more options in https://msal-python.readthedocs.io/en/latest/#tokencache

# Create a preferably long-lived app instance, to avoid the overhead of app creation
global_app = msal.ConfidentialClientApplication(
    config["client_id"], authority=config["authority"],
    client_credential={"thumbprint": config["thumbprint"], "private_key": open(config['private_key_file']).read()},
    token_cache=global_token_cache,  # Let this app (re)use an existing token cache.
        # If absent, ClientApplication will create its own empty token cache
    )


def acquire_and_use_token():
    # Since MSAL 1.23, acquire_token_for_client(...) will automatically look up
    # a token from cache, and fall back to acquire a fresh token when needed.
    result = global_app.acquire_token_for_client(scopes=config["scope"])

    if "access_token" in result:
        print("Token was obtained from:", result["token_source"])  # Since MSAL 1.25
        # Calling graph using the access token
        graph_data = requests.get(  # Use token to call downstream service
            config["endpoint"],
            headers={'Authorization': 'Bearer ' + result['access_token']},timeout=60).json()
        print("Graph API call result: %s" % json.dumps(graph_data, indent=2))
    else:
        print("Token acquisition failed", result)  # Examine result["error_description"] etc. to diagnose error


while True:  # Here we mimic a long-lived daemon
    acquire_and_use_token()
    print("Press Ctrl-C to stop.")
    time.sleep(5)  # Let's say your app would run a workload every X minutes

