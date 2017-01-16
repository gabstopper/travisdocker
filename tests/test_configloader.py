'''
Test ConfigLoader using preference file ~/.smcrc or loaded through
session.login(alt_filepath='/path/to/config/file.txt')
'''
import io
import unittest
import mock
import requests
import requests_mock
from smc import session
from smc.api.configloader import load_from_file
from smc.api.exceptions import ConfigLoadError, UnsupportedEntryPoint,\
    SMCConnectionError
from smc.api.session import SessionCache
from smc.api.web import SMCAPIConnection

class TestConfigloader(unittest.TestCase):
        
    @mock.patch('smc.api.configloader.io.open', create=True)
    def test_missing_section(self, mock_open):
        """
        Raises NoSectionError when missing main section [smc]
        """
        cfg = ("[foo]\n"
               "smc_address=1.1.1.1")
    
        mock_open.return_value = io.StringIO(u'{}'.format(cfg))
        self.assertRaises(ConfigLoadError, lambda: load_from_file())
        
    @mock.patch('smc.api.configloader.io.open', create=True)
    def test_missing_field_for_section(self, mock_open):
        """
        Raises NoOptionError when [smc] section is present but
        credential information is not complete
        """
        cfg = ("[smc]\n"
               "smc_address=1.1.1.1")
            
        mock_open.return_value = io.StringIO(u'{}'.format(cfg))
        self.assertRaises(ConfigLoadError, lambda: load_from_file())
    
    @mock.patch('smc.api.configloader.io.open', create=True)    
    def test_missing_credential_file_in_home_directory(self, mock_open):
        """
        Raises IOError because ~/.smcrc not found and alt_filepath not
        specified during login.
        """
        mock_open.side_effect = IOError()
        self.assertRaises(ConfigLoadError, lambda: load_from_file())
    
    @mock.patch('smc.api.configloader.load_from_file')
    @mock.patch('smc.api.configloader.io.open', create=True)    
    def test_called_with_alt_file(self, mock_open, mock_load):
        cfg = ("[smc]\n"
               "smc_address=1.1.1.1\n"
               "smc_apikey=12345abcdef")
        
        mock_open.return_value = io.StringIO(u'{}'.format(cfg))
        load_from_file(alt_filepath='/Users/myfile')
        mock_open.assert_called_once_with('/Users/myfile', 'rt', encoding='UTF-8')
    
    @mock.patch('smc.api.configloader.io.open', create=True) 
    def test_bogus_entries_are_ignored(self, mock_open):
        cfg = ("[smc]\n"
               "smc_address=1.1.1.1\n"
               "smc_apikey=12345abcdef\n"
               "foo=bar\n"
               "bar=foo")
    
        mock_open.return_value = io.StringIO(u'{}'.format(cfg))
        # This will fall down to transform_login to build the structure to call
        # login. This should not have unknown attributes in the dict
        login_dict = load_from_file()
        self.assertNotIn('foo', login_dict)
        self.assertNotIn('bar', login_dict)
    
    @mock.patch('smc.api.configloader.io.open', create=True) 
    def test_ssl_enabled_settings(self, mock_open):
        """
        SSL specified, but verify disabled
        """
        cfg = ("[smc]\n"
               "smc_address=1.1.1.1\n"
               "smc_apikey=12345\n"
               "smc_ssl=True\n")
        mock_open.return_value = io.StringIO(u'{}'.format(cfg))
        login_dict = load_from_file()
        self.assertTrue(login_dict.get('verify') == False)
    
    @mock.patch('smc.api.configloader.io.open', create=True) 
    def test_ssl_with_no_cert_file_and_ssl_enabled(self, mock_open):
        """
        SSL specified, verify enabled, not cert to verify against,
        verify will be disabled
        """
        cfg = ("[smc]\n"
               "smc_address=1.1.1.1\n"
               "smc_apikey=12345\n"
               "smc_ssl=True\n"
               "verify_ssl=True")
        mock_open.return_value = io.StringIO(u'{}'.format(cfg))
        login_dict = load_from_file()
        self.assertTrue(login_dict.get('verify') == False)
    
    @mock.patch('smc.api.configloader.io.open', create=True)
    def test_ssl_enabled_with_cert_verify(self, mock_open):
        """
        SSL specified, verification enabled and cert file provided
        """
        cfg = ("[smc]\n"
               "smc_address=1.1.1.1\n"
               "smc_apikey=12345\n"
               "smc_ssl=True\n"
               "verify_ssl=True\n"
               "ssl_cert_file=/usr/local/cert.pem")
        mock_open.return_value = io.StringIO(u'{}'.format(cfg))
        login_dict = load_from_file()
        self.assertEqual(login_dict.get('verify'), '/usr/local/cert.pem')
        # Transformed out of the final configuration
        self.assertNotIn('smc_ssl', login_dict)
        self.assertNotIn('verify_ssl', login_dict)
        
    @mock.patch('smc.api.configloader.io.open', create=True)
    def test_valid_timeout_and_apiversion(self, mock_open):
        """
        Test the timeout field as valid value
        """
        cfg = ("[smc]\n"
               "smc_address=1.1.1.1\n"
               "smc_apikey=12345\n"
               "timeout=60\n"
               "api_version=6.1")
        mock_open.return_value = io.StringIO(u'{}'.format(cfg))
        login_dict = load_from_file()
        self.assertEqual(login_dict.get('timeout'), 60)
        self.assertEqual(login_dict.get('api_version'), 6.1)
    
    @mock.patch('smc.api.configloader.io.open', create=True)    
    def test_invalid_timeout_and_api_version(self, mock_open):
        """
        If invalid timeout setting provided, i.e. 10a, 20b, etc,
        timeout is disabled
        """
        cfg = ("[smc]\n"
               "smc_address=1.1.1.1\n"
               "smc_apikey=12345\n"
               "timeout=60a\n"
               "api_version=abc")
        mock_open.return_value = io.StringIO(u'{}'.format(cfg))
        login_dict = load_from_file()
        self.assertIsNone(login_dict.get('timeout'))
        self.assertIsNone(login_dict.get('api_version'))
    
    @mock.patch('smc.api.configloader.io.open', create=True) 
    def test_session_login_fail(self, mock_open):
        """
        Session login is called via session.login() or 
        session.login(alt_filepath='/path') or by specifying 
        credentials directly in login constructor. In case of
        reading from file, verify exception bubbles up.
        """
        cfg = ("[smc]\n")
        mock_open.return_value = io.StringIO(u'{}'.format(cfg))
        self.assertRaises(ConfigLoadError, lambda: session.login(alt_filepath='foo'))
            
class TestSessionApi(unittest.TestCase):
    
    def entry_point_dict(self):
        """
        Entry point dictionary for session login
        """
        url = 'http://1.1.1.1:8082/6.1'
        return {'entry_point':[{'href':'{}/logout'.format(url),'method': 'PUT', 'rel':'logout'},
                               {'href':'{}/login'.format(url),'method': 'POST', 'rel':'login'},
                               {'href':'{}/api'.format(url),'method':'GET', 'rel':'api'}]}
    
    def version_dict(self):
        """
        Dict for version numbers, returned when calling url/api
        """
        url = 'http://1.1.1.1:8082/6.1'
        return {"version":[{"href":'{}/api'.format(url),'method': 'GET', 'rel':'6.1'},
                           {"href":'{}/api'.format(url),'method': 'GET', 'rel':'6.0'},
                           {"href":'{}/api'.format(url),'method': 'GET', 'rel':'5.10'}]}
    
    def raise_requests_exception(self, request, context):
        """
        Raise a requests exception, can happen for timed out connections, etc
        """
        raise requests.exceptions.RequestException('Request exception raised')
    
    def raise_requests_ssl_exception(self, request, context):
        """   
        Raise SSL Exception from requests module
        """
        raise requests.exceptions.SSLError("SSL error from requests")
    
    @mock.patch('smc.api.configloader.io.open', create=True)
    @requests_mock.mock()
    def test_session_login_pass_from_file(self, mock_open, m):
        """
        Test a valid login session through smc.api.session. Login will be done
        through the login file method of session.login(alt_filepath='foo').
        Verify the session afterwards.
        """
        cfg = ("[smc]\n"
               "smc_address=1.1.1.1\n"
               "smc_apikey=12345\n"
               "timeout=60\n"
               "api_version=6.1")
        mock_open.return_value = io.StringIO(u'{}'.format(cfg))

        entry_points = self.entry_point_dict()
        
        m.register_uri('GET', '/api', json=self.version_dict())
        m.register_uri('GET', '/6.1/api', json=entry_points)
        m.register_uri('POST', '/6.1/login', status_code=200)
        
        session.login(alt_filepath='foo')
        # Session object now has everything we need
        self.assertIsInstance(session.cache, SessionCache)
        self.assertEqual(session.api_key, '12345')
        self.assertIsInstance(session.connection, SMCAPIConnection)
        self.assertEqual(session.timeout, 60)
        self.assertEqual(session.url, 'http://1.1.1.1:8082')
        self.assertEqual(session.api_version, 6.1)
        # Entry points should match 
        self.assertDictEqual(entry_points.get('entry_point')[0], session.cache.get_all_entry_points()[0])
        # Get an entry point that doesn't exist
        self.assertRaises(UnsupportedEntryPoint, lambda: session.cache.get_entry_href('foo'))
        
        # Entry points by name; without href,rel,method
        entry_rel = [p.get('rel') for p in entry_points.get('entry_point')]
        self.assertEqual(entry_rel, session.cache.get_entry_points())
        self.assertEqual(session.cache.get_entry_points(), session.cache.entry_points)
        
        # Successful logout. No status returned..
        m.register_uri('PUT', '/6.1/logout', status_code=204)
        self.assertIsNone(session.logout())

        # Session logged out. This would indicate no valid login session
        self.assertRaises(SMCConnectionError, lambda: session.cache.get_entry_href('boo'))
    
    @mock.patch('smc.api.configloader.io.open', create=True)
    @requests_mock.mock()
    def test_session_login_find_api_version_failed_reply(self, mock_open, m):
        cfg = ("[smc]\n"
               "smc_address=1.1.1.1\n"
               "smc_apikey=12345\n"
               "timeout=60")
        mock_open.return_value = io.StringIO(u'{}'.format(cfg))
        
        # First call is without an api_version specified 
        m.register_uri('GET', '/api', json=self.version_dict())
    
        # Unexpected reply back from call to API
        m.register_uri('GET', '/6.1/api', status_code=400)
        self.assertRaises(SMCConnectionError, lambda: session.login(alt_filepath='foo'))
        
    @requests_mock.mock()
    def test_login_credentials_in_constructor(self, m):
        """
        Log in using credentials in the constructor. Double check the
        sesison object to make sure settings are set.
        """
        m.register_uri('GET', '/api', json=self.version_dict()) #Initial connect
        m.register_uri('GET', '/6.1/api', json=self.entry_point_dict()) #Get entry points
        m.register_uri('POST', '/6.1/login', status_code=200)
        
        session.login(url='http://1.1.1.1:8082', api_key='12345', api_version=6.1, timeout=60)
        self.assertEqual(session.url, 'http://1.1.1.1:8082')
        self.assertEqual(session.api_version, 6.1)
        self.assertEqual(session.timeout, 60)
        self.assertEqual(session.api_key, '12345')
        
        #Fail the logout, nothing should be returned unless logging
        m.register_uri('PUT', '/6.1/logout', status_code=400)
        self.assertIsNone(session.logout())
    
    @requests_mock.mock()
    def test_login_failed(self, m):
        """
        Verify proper return for failed login attempt. Expected HTTP response
        is status code 200
        """
        m.register_uri('GET', '/api', json=self.version_dict()) #Initial connect
        m.register_uri('GET', '/6.1/api', json=self.entry_point_dict()) #Get entry points
        m.register_uri('POST', '/6.1/login', status_code=400)
        
        self.assertRaises(SMCConnectionError, lambda: session.login(url='http://1.1.1.1:8082', 
                                                                    api_key='12345', 
                                                                    api_version=6.1))
    @requests_mock.mock()
    def test_requests_error_during_connection(self, m):
        """
        Requests can raise exceptions during connecting, such as time
        out when the IP address of SMC is incorrect. 
        """
        m.register_uri('GET', '/api', json=self.raise_requests_exception)
        self.assertRaises(SMCConnectionError, lambda: session.login(url='http://1.1.1.1:8082', 
                                                                    api_key='12345', 
                                                                    api_version=6.1))
    
    @requests_mock.mock()
    def test_out_of_bounds_api_version(self, m):
        m.register_uri('GET', '/api', json=self.version_dict()) #Initial connect
        m.register_uri('GET', '/6.1/api', json=self.entry_point_dict())
        m.register_uri('POST', '/6.1/login', status_code=200)
        session.login(url='http://1.1.1.1:8082', 
                      api_key='12345', 
                      api_version=6.5)
        # Version dict has max 6.1. Check session to verify
        self.assertEqual(session.api_version, 6.1)
    
    @requests_mock.mock()
    def test_invalid_format_api_version(self, m):
        m.register_uri('GET', '/api', json=self.version_dict()) #Initial connect
        m.register_uri('GET', '/6.1/api', json=self.entry_point_dict())
        m.register_uri('POST', '/6.1/login', status_code=200)
        session.login(url='http://1.1.1.1:8082', 
                      api_key='12345', 
                      api_version='blahfoo')
        # Version dict has max 6.1. Check session to verify
        self.assertEqual(session.api_version, 6.1)
        
    @requests_mock.mock()
    def test_requests_error_during_logout_with_ssl(self, m):
        m.register_uri('GET', '/api', json=self.version_dict()) #Initial connect
        m.register_uri('GET', '/6.1/api', json=self.entry_point_dict()) #Get entry points
        m.register_uri('POST', '/6.1/login', status_code=200)
        session.login(url='http://1.1.1.1:8082', 
                      api_key='12345', 
                      api_version=6.1)
        m.register_uri('PUT', '/6.1/logout', json=self.raise_requests_ssl_exception)
        # Entry point cache exists
        self.assertTrue(len(session.cache.api_entry) > 0)
        # Logout will catch an SSL Error
        self.assertIsNone(session.logout())
        # Entry point cache is still removed
        self.assertIsNone(session.cache.api_entry)
        