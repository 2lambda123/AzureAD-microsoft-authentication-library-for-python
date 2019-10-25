import os

from msal.authority import *
from msal.exceptions import MsalServiceError
from tests import unittest


@unittest.skipIf(os.getenv("TRAVIS_TAG"), "Skip network io during tagged release")
class TestAuthority(unittest.TestCase):

    def test_wellknown_host_and_tenant(self):
        # Assert all well known authority hosts are using their own "common" tenant
        for host in WELL_KNOWN_AUTHORITY_HOSTS:
            a = Authority('https://{}/common'.format(host))
            self.assertEqual(
                a.authorization_endpoint,
                'https://%s/common/oauth2/v2.0/authorize' % host)
            self.assertEqual(
                a.token_endpoint, 'https://%s/common/oauth2/v2.0/token' % host)

    @unittest.skip("As of Jan 2017, the server no longer returns V1 endpoint")
    def test_lessknown_host_will_return_a_set_of_v1_endpoints(self):
        # This is an observation for current (2016-10) server-side behavior.
        # It is probably not a strict API contract. I simply mention it here.
        less_known = 'login.windows.net'  # less.known.host/
        v1_token_endpoint = 'https://{}/common/oauth2/token'.format(less_known)
        a = Authority('https://{}/common'.format(less_known))
        self.assertEqual(a.token_endpoint, v1_token_endpoint)
        self.assertNotIn('v2.0', a.token_endpoint)

    def test_unknown_host_wont_pass_instance_discovery(self):
        with self.assertRaisesRegexp(ValueError, "invalid_instance"):
            Authority('https://unknown.host/tenant_doesnt_matter_in_this_case')

    def test_invalid_host_skipping_validation_meets_connection_error_down_the_road(self):
        with self.assertRaises(requests.exceptions.RequestException):
            Authority('https://unknown.host/invalid', validate_authority=False)


class TestAuthorityInternalHelperCanonicalize(unittest.TestCase):

    def test_canonicalize_tenant_followed_by_extra_paths(self):
        _, i, t = canonicalize("https://example.com/tenant/subpath?foo=bar#fragment")
        self.assertEqual("example.com", i)
        self.assertEqual("tenant", t)

    def test_canonicalize_tenant_followed_by_extra_query(self):
        _, i, t = canonicalize("https://example.com/tenant?foo=bar#fragment")
        self.assertEqual("example.com", i)
        self.assertEqual("tenant", t)

    def test_canonicalize_tenant_followed_by_extra_fragment(self):
        _, i, t = canonicalize("https://example.com/tenant#fragment")
        self.assertEqual("example.com", i)
        self.assertEqual("tenant", t)

    def test_canonicalize_rejects_non_https(self):
        with self.assertRaises(ValueError):
            canonicalize("http://non.https.example.com/tenant")

    def test_canonicalize_rejects_tenantless(self):
        with self.assertRaises(ValueError):
            canonicalize("https://no.tenant.example.com")

    def test_canonicalize_rejects_tenantless_host_with_trailing_slash(self):
        with self.assertRaises(ValueError):
            canonicalize("https://no.tenant.example.com/")


@unittest.skipIf(os.getenv("TRAVIS_TAG"), "Skip network io during tagged release")
class TestAuthorityInternalHelperUserRealmDiscovery(unittest.TestCase):
    def test_memorize(self):
        # We use a real authority so the constructor can finish tenant discovery
        authority = "https://login.microsoftonline.com/common"
        self.assertNotIn(authority, Authority._domains_without_user_realm_discovery)
        a = Authority(authority, validate_authority=False)

        # We now pretend this authority supports no User Realm Discovery
        class MockResponse(object):
            status_code = 404
        a.user_realm_discovery("john.doe@example.com", "ecbecaf4-1759-498d-ae24-25a98a8eca27", response=MockResponse())
        self.assertIn(
            "login.microsoftonline.com",
            Authority._domains_without_user_realm_discovery,
            "user_realm_discovery() should memorize domains not supporting URD")
        a.user_realm_discovery("john.doe@example.com",
                               "ecbecaf4-1759-498d-ae24-25a98a8eca27",
                               response="This would cause exception if memorization did not work")

