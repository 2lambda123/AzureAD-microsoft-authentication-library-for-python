import json
import base64
import time
import string
import warnings
import hashlib
import logging

from . import oauth2
import secrets


logger = logging.getLogger(__name__)

def decode_part(raw, encoding="utf-8"):
    """    Decode a part of the JWT.

    JWT is encoded by padding-less base64url, based on `JWS specs
    <https://tools.ietf.org/html/rfc7515#appendix-C>`_.

    Args:
        raw (str): The part of the JWT to be decoded.
        encoding (str?): The encoding to be used for decoding.
            If decoding the first 2 parts (header or payload) of a JWT,
            use "utf-8". For decoding the last part (signature), use `None`.

    Returns:
        str: The decoded part of the JWT.

    Note:
        If you are going to decode the first 2 parts of a JWT, i.e., the header
        or the payload, the default value "utf-8" would work fine.
        - If you are going to decode the last part, i.e., the signature part,
        it is a binary string, so you should use `None` as encoding here.
    """
    raw += '=' * (-len(raw) % 4)  # https://stackoverflow.com/a/32517907/728675
    raw = str(
        # On Python 2.7, argument of urlsafe_b64decode must be str, not unicode.
        # This is not required on Python 3.
        raw)
    output = base64.urlsafe_b64decode(raw)
    if encoding:
        output = output.decode(encoding)
    return output

base64decode = decode_part  # Obsolete. For backward compatibility only.

def _epoch_to_local(epoch):
    """Convert the given epoch time to a local date and time string.

    Args:
        epoch (int): The epoch time to be converted.

    Returns:
        str: A string representing the local date and time in the format "%Y-%m-%d
            %H:%M:%S".
    """

    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(epoch))

class IdTokenError(RuntimeError):  # We waised RuntimeError before, so keep it
    """In unlikely event of an ID token is malformed, this exception will be raised."""
    def __init__(self, reason, now, claims):
        super(IdTokenError, self).__init__(
            "%s Current epoch = %s.  The id_token was approximately: %s" % (
            reason, _epoch_to_local(now), json.dumps(dict(
                claims,
                iat=_epoch_to_local(claims["iat"]) if claims.get("iat") else None,
                exp=_epoch_to_local(claims["exp"]) if claims.get("exp") else None,
            ), indent=2)))

class _IdTokenTimeError(IdTokenError):  # This is not intended to be raised and caught
    _SUGGESTION = "Make sure your computer's time and time zone are both correct."
    def __init__(self, reason, now, claims):
        super(_IdTokenTimeError, self).__init__(reason+ " " + self._SUGGESTION, now, claims)
    def log(self):
        """Log a warning message related to the token based on JWT and OIDC
        specifications.

        This method logs a warning message instead of raising an error, as per
        the following reasons: 1. If the issue is due to incorrect local machine
        time, the tokens are still valid and functional. 2. If the issue is due
        to incorrect IdP time, it is the IdP's responsibility, and the client
        can't do much about it.

        Args:
            self: The instance of the class.
        """

        # Influenced by JWT specs https://tools.ietf.org/html/rfc7519#section-4.1.5
        # and OIDC specs https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
        # We used to raise this error, but now we just log it as warning, because:
        # 1. If it is caused by incorrect local machine time,
        # then the token(s) are still correct and probably functioning,
        # so, there is no point to error out.
        # 2. If it is caused by incorrect IdP time, then it is IdP's fault,
        # There is not much a client can do, so, we might as well return the token(s)
        # and let downstream components to decide what to do.
        logger.warning(str(self))

class IdTokenIssuerError(IdTokenError):
    pass

class IdTokenAudienceError(IdTokenError):
    pass

class IdTokenNonceError(IdTokenError):
    pass

def decode_id_token(id_token, client_id=None, issuer=None, nonce=None, now=None):
    """    Decodes and validates an id_token and returns its claims as a
    dictionary.

    ID token claims would at least contain: "iss", "sub", "aud", "exp",
    "iat", per `specs <https://openid.net/specs/openid-connect-
    core-1_0.html#IDToken>`_ and it may contain other optional content such
    as "preferred_username", `maybe more <https://openid.net/specs/openid-
    connect-core-1_0.html#Claims>`_
    """
    decoded = json.loads(decode_part(id_token.split('.')[1]))
    # Based on https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
    _now = int(now or time.time())
    skew = 120  # 2 minutes

    if _now + skew < decoded.get("nbf", _now - 1):  # nbf is optional per JWT specs
        # This is not an ID token validation, but a JWT validation
        # https://tools.ietf.org/html/rfc7519#section-4.1.5
        _IdTokenTimeError("0. The ID token is not yet valid.", _now, decoded).log()

    if issuer and issuer != decoded["iss"]:
        # https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationResponse
        raise IdTokenIssuerError(
            '2. The Issuer Identifier for the OpenID Provider, "%s", '
            "(which is typically obtained during Discovery), "
            "MUST exactly match the value of the iss (issuer) Claim." % issuer,
            _now,
            decoded)

    if client_id:
        valid_aud = client_id in decoded["aud"] if isinstance(
            decoded["aud"], list) else client_id == decoded["aud"]
        if not valid_aud:
            raise IdTokenAudienceError(
                "3. The aud (audience) claim must contain this client's client_id "
                '"%s", case-sensitively. Was your client_id in wrong casing?'
                # Some IdP accepts wrong casing request but issues right casing IDT
                % client_id,
                _now,
                decoded)

    # Per specs:
    # 6. If the ID Token is received via direct communication between
    # the Client and the Token Endpoint (which it is during _obtain_token()),
    # the TLS server validation MAY be used to validate the issuer
    # in place of checking the token signature.

    if _now - skew > decoded["exp"]:
        _IdTokenTimeError("9. The ID token already expires.", _now, decoded).log()

    if nonce and nonce != decoded.get("nonce"):
        raise IdTokenNonceError(
            "11. Nonce must be the same value "
            "as the one that was sent in the Authentication Request.",
            _now,
            decoded)

    return decoded


def _nonce_hash(nonce):
    """Calculate the SHA-256 hash of the provided nonce.

    This function takes a nonce as input, encodes it to ASCII, and then
    calculates the SHA-256 hash of the encoded nonce.

    Args:
        nonce (str): The nonce value to be hashed.

    Returns:
        str: The SHA-256 hash of the provided nonce.
    """

    # https://openid.net/specs/openid-connect-core-1_0.html#NonceNotes
    return hashlib.sha256(nonce.encode("ascii")).hexdigest()


class Prompt(object):
    """This class defines the constant strings for prompt parameter.

    The values are based on
    https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
    """
    NONE = "none"
    LOGIN = "login"
    CONSENT = "consent"
    SELECT_ACCOUNT = "select_account"
    CREATE = "create"  # Defined in https://openid.net/specs/openid-connect-prompt-create-1_0.html#PromptParameter


class Client(oauth2.Client):
    """OpenID Connect is a layer on top of the OAuth2.

    See its specs at https://openid.net/connect/
    """

    def decode_id_token(self, id_token, nonce=None):
        """        Decode the given ID token using the provided nonce for validation.

        This method decodes the ID token using the specified nonce for
        validation.

        Args:
            id_token (str): The ID token to be decoded.
            nonce (str?): Nonce value used for validation. Defaults to None.

        Returns:
            dict: Decoded information from the ID token.
        """
        return decode_id_token(
            id_token, nonce=nonce,
            client_id=self.client_id, issuer=self.configuration.get("issuer"))

    def _obtain_token(self, grant_type, *args, **kwargs):
        """        Obtain the token for the specified grant type.

        The result will also contain one more key "id_token_claims", whose value
        will be a dictionary returned by :func:`~decode_id_token`.

        Args:
            grant_type (str): The type of grant for obtaining the token.
            *args: Additional positional arguments.
            **kwargs: Additional keyword arguments.

        Returns:
            dict: A dictionary containing the obtained token and id_token_claims.
        """
        ret = super(Client, self)._obtain_token(grant_type, *args, **kwargs)
        if "id_token" in ret:
            ret["id_token_claims"] = self.decode_id_token(ret["id_token"])
        return ret

    def build_auth_request_uri(self, response_type, nonce=None, **kwargs):
        """        Generate an authorization URI to be visited by the resource owner.

        This function generates an authorization URI to be visited by the
        resource owner for initiating the authentication flow. It is recommended
        to use initiate_auth_code_flow() instead of this method.

        Args:
            response_type (str): The type of response expected from the authorization server.
            nonce (str?): A hard-to-guess string used to mitigate replay attacks.
                Refer to OIDC specs for more information.

        Returns:
            str: The generated authorization URI.
        """
        warnings.warn("Use initiate_auth_code_flow() instead", DeprecationWarning)
        return super(Client, self).build_auth_request_uri(
            response_type, nonce=nonce, **kwargs)

    def obtain_token_by_authorization_code(self, code, nonce=None, **kwargs):
        """        Get a token via authorization code. a.k.a. Authorization Code Grant.

        Return value and all other parameters are the same as
        :func:`oauth2.Client.obtain_token_by_authorization_code`, plus new
        parameter(s):
        """
        warnings.warn(
            "Use obtain_token_by_auth_code_flow() instead", DeprecationWarning)
        result = super(Client, self).obtain_token_by_authorization_code(
            code, **kwargs)
        nonce_in_id_token = result.get("id_token_claims", {}).get("nonce")
        if "id_token_claims" in result and nonce and nonce != nonce_in_id_token:
            raise ValueError(
                'The nonce in id token ("%s") should match your nonce ("%s")' %
                (nonce_in_id_token, nonce))
        return result

    def initiate_auth_code_flow(
            self,
            scope=None,
            **kwargs):
        """        Initiate an auth code flow.

        It provides nonce protection automatically.
        """
        if "id_token" in kwargs.get("response_type", ""):
            # Implicit grant would cause auth response coming back in #fragment,
            # but fragment won't reach a web service.
            raise ValueError('response_type="id_token ..." is not allowed')
        _scope = list(scope) if scope else []  # We won't modify input parameter
        if "openid" not in _scope:
            # "If no openid scope value is present,
            # the request may still be a valid OAuth 2.0 request,
            # but is not an OpenID Connect request." -- OIDC Core Specs, 3.1.2.2
            # https://openid.net/specs/openid-connect-core-1_0.html#AuthRequestValidation
            # Here we just automatically add it. If the caller do not want id_token,
            # they should simply go with oauth2.Client.
            _scope.append("openid")
        nonce = "".join(secrets.SystemRandom().sample(string.ascii_letters, 16))
        flow = super(Client, self).initiate_auth_code_flow(
            scope=_scope, nonce=_nonce_hash(nonce), **kwargs)
        flow["nonce"] = nonce
        if kwargs.get("max_age") is not None:
            flow["max_age"] = kwargs["max_age"]
        return flow

    def obtain_token_by_auth_code_flow(self, auth_code_flow, auth_response, **kwargs):
        """        Validate the auth_response being redirected back, and then obtain
        tokens,
        including ID token which can be used for user sign in.  Internally, it
        implements nonce to mitigate replay attack. It also implements PKCE to
        mitigate the auth code interception attack.
        """
        result = super(Client, self).obtain_token_by_auth_code_flow(
            auth_code_flow, auth_response, **kwargs)
        if "id_token_claims" in result:
            nonce_in_id_token = result.get("id_token_claims", {}).get("nonce")
            expected_hash = _nonce_hash(auth_code_flow["nonce"])
            if nonce_in_id_token != expected_hash:
                raise RuntimeError(
                    'The nonce in id token ("%s") should match our nonce ("%s")' %
                    (nonce_in_id_token, expected_hash))

            if auth_code_flow.get("max_age") is not None:
                auth_time = result.get("id_token_claims", {}).get("auth_time")
                if not auth_time:
                    raise RuntimeError(
                        "13. max_age was requested, ID token should contain auth_time")
                now = int(time.time())
                skew = 120  # 2 minutes. Hardcoded, for now
                if now - skew > auth_time + auth_code_flow["max_age"]:
                    raise RuntimeError(
                            "13. auth_time ({auth_time}) was requested, "
                            "by using max_age ({max_age}) parameter, "
                            "and now ({now}) too much time has elasped "
                            "since last end-user authentication. "
                            "The ID token was: {id_token}".format(
                        auth_time=auth_time,
                        max_age=auth_code_flow["max_age"],
                        now=now,
                        id_token=json.dumps(result["id_token_claims"], indent=2),
                        ))
        return result

    def obtain_token_by_browser(
            self,
            display=None,
            prompt=None,
            max_age=None,
            ui_locales=None,
            id_token_hint=None,  # It is relevant,
                # because this library exposes raw ID token
            login_hint=None,
            acr_values=None,
            **kwargs):
        """        A native app can use this method to obtain token via a local browser.

        Internally, it implements nonce to mitigate replay attack. It also
        implements PKCE to mitigate the auth code interception attack.

        Args:
            display (str): Defined in OIDC.
            prompt (str or list): Defined in OIDC. Valid values defined in oidc.Prompt.
            max_age (int): Defined in OIDC.
            ui_locales (str): Defined in OIDC.
            id_token_hint (str): Defined in OIDC.
            login_hint (str): Defined in OIDC.
            acr_values (str): Defined in OIDC.

        Returns:
            The return value is described in the parent class method
                oauth2.Client.obtain_token_by_browser.
        """
        filtered_params = {k:v for k, v in dict(
            prompt=" ".join(prompt) if isinstance(prompt, (list, tuple)) else prompt,
            display=display,
            max_age=max_age,
            ui_locales=ui_locales,
            id_token_hint=id_token_hint,
            login_hint=login_hint,
            acr_values=acr_values,
            ).items() if v is not None}  # Filter out None values
        return super(Client, self).obtain_token_by_browser(
            auth_params=dict(kwargs.pop("auth_params", {}), **filtered_params),
            **kwargs)

