
import unittest
from smc import session
from smc.tests.constants import url, api_key, verify
from smc.elements.profiles import DNSRelayProfile


class Test(unittest.TestCase):

    def setUp(self):
        session.login(url=url, api_key=api_key, verify=verify)

    def tearDown(self):
        try:
            session.logout()
        except SystemExit:
            pass

    def test_dns_profile(self):
        profile = DNSRelayProfile('myprofile')
        # Will be created as it doesn't exist yet
        profile.add_domain_specific_dns_server(as_list=[('foo.com', '1.1.1.1'),
                                                        ('boo.com', '2.2.2.2'),
                                                        ('voo.com', '3.3.3.3')])

        profile.add_domain_specific_dns_server(domain_name='last.com',
                                               dns_server_addresses='2.2.2.3,2.2.2.4')

        for entry in profile.domain_specific_dns_server:
            self.assertIn(entry.get('domain_name'), [
                          'foo.com', 'boo.com', 'voo.com', 'last.com'])
            self.assertIn(entry.get('dns_server_addresses'), [
                          '1.1.1.1', '2.2.2.2', '2.2.2.3,2.2.2.4', '3.3.3.3'])

        profile.add_hostname_mapping(as_list=[('myhost', '1.1.1.1'),
                                              ('myhost2', '2.2.2.2')])

        profile.add_hostname_mapping(hostnames='myhost3', ipaddress='3.3.3.3')

        for entry in profile.hostname_mapping:
            self.assertIn(entry.get('hostnames'), [
                          'myhost', 'myhost2', 'myhost3'])
            self.assertIn(entry.get('ipaddress'), [
                          '1.1.1.1', '2.2.2.2', '3.3.3.3'])

        profile.add_fixed_domain_answer(domain_name='mydomain.net',
                                        translated_domain_name='a.com')

        profile.add_fixed_domain_answer(as_list=[('domain2.local', 'redirect2.local'),
                                                 ('domain3.local', 'redirect3.local')])

        for entry in profile.fixed_domain_answer:
            self.assertIn(entry.get('domain_name'), [
                          'mydomain.net', 'domain2.local', 'domain3.local'])
            self.assertIn(entry.get('translated_domain_name'), [
                          'a.com', 'redirect2.local', 'redirect3.local'])

        profile.add_dns_answer_translation(
            original_ipaddress='2.2.2.2', translated_ipaddress='23.23.23.23')
        profile.add_dns_answer_translation(as_list=[('3.3.3.3', '10.10.10.10'),
                                                    ('3.3.3.4', '10.10.10.11'),
                                                    ('3.3.3.5', '10.10.10.12')])

        for entry in profile.dns_answer_translation:
            self.assertIn(entry.get('original_ipaddress'), [
                          '2.2.2.2', '3.3.3.3', '3.3.3.4', '3.3.3.5'])
            self.assertIn(entry.get('translated_ipaddress'), [
                          '23.23.23.23', '10.10.10.10', '10.10.10.11', '10.10.10.12'])

        profile.delete()


if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
