import unittest
from smc import session as mysession
import requests_mock
from smc.api.exceptions import LicenseError
from smc.core.node import Node
from constants import url, api_key
from smc.base.model import Meta


def register_first_request(adapter, uri, status_code=200,
                           headers={'content-type': 'application/json'}):
    """
    URI should be the 'rel' link for the resource. The expected json returned
    will be the 'link' resource with the follow on href. This href will match 
    the mock address to intercept.
    """
    adapter.register_uri('GET', '/{}'.format(uri),
                         json={'link':[{'href': '{}/{}'.format(url, uri),
                                        'method': 'POST',
                                        'rel': uri}]},
                         status_code=status_code,
                         headers=headers)

def register_post_reply(adapter, uri, status_code=400,
                        json=None, headers={}):
    """
    Reply for POST to specific uri
    """
    adapter.register_uri('POST', '/{}'.format(uri),
                         json=json,
                         status_code=status_code,
                         headers=headers)
         
@requests_mock.Mocker()
class HttpMocks(unittest.TestCase):
    
    def setUp(self):
        mysession.login(url, api_key)
        
    def tearDown(self):
        mysession.logout()
    
    def test_fetch_license_fail(self, m):
        uri = 'fetch'
        register_first_request(m, uri)
        register_post_reply(m, uri, 
                            status_code=400,
                            json={'message':'Impossible to fetch the license',
                                  'status':0},
                            headers={'content-type': 'application/json'})

        node = Node(meta=Meta(href='{}/{}'.format(url, uri)))
        self.assertRaises(LicenseError, lambda: node.fetch_license())
    
    def test_fetch_license_pass(self, m):
        uri = 'fetch'
        register_first_request(m, uri)
        register_post_reply(m, uri, status_code=200)

        node = Node(meta=Meta(href='{}/{}'.format(url, uri)))
        self.assertIsNone(node.fetch_license())
          
    def test_bind_license_pass(self, m):
        uri = 'bind'
        register_first_request(m, uri)
        register_post_reply(m, uri, status_code=200)
    
        node = Node(meta=Meta(href='{}/{}'.format(url, uri)))
        self.assertIsNone(node.bind_license())
    
    def test_bind_license_fail(self, m):
        uri = 'bind'
        
        register_first_request(m, uri)
        register_post_reply(m, uri, 
                            status_code=400,
                            json={'details': ['Another license is already bound to this component.\\nPlease unbind the license first.'],
                                  'message': 'Impossible to auto-bind the license.',
                                  'status': 0},
                            headers={'content-type': 'application/json'})
        
        node = Node(meta=Meta(href='{}/{}'.format(url, uri)))
        self.assertRaises(LicenseError, lambda: node.bind_license())

    def test_unbind_license_pass(self, m):
        uri = 'unbind'
        
        register_first_request(m, uri)
        register_post_reply(m, uri, status_code=200)
        
        node = Node(meta=Meta(href='{}/{}'.format(url, uri)))
        self.assertIsNone(node.unbind_license())
       
    def test_unbind_license_fail(self, m):
        uri = 'unbind'
        
        register_first_request(m, uri)
        register_post_reply(m, uri, status_code=400)
    
        node = Node(meta=Meta(href='{}/{}'.format(url, uri)))
        self.assertRaises(LicenseError, lambda: node.unbind_license())
    
    def test_cancel_unbind_pass(self, m):
        uri = 'cancel_unbind'
        register_first_request(m, uri)
        register_post_reply(m, uri, status_code=200)
    
        node = Node(meta=Meta(href='{}/{}'.format(url, uri)))
        self.assertIsNone(node.cancel_unbind_license())
        
    def test_cancel_unbund_fail(self, m):
        uri = 'cancel_unbind'
        register_first_request(m, uri)
        register_post_reply(m, uri, status_code=400)
        
        node = Node(meta=Meta(href='{}/{}'.format(url, uri)))
        self.assertRaises(LicenseError, lambda: node.cancel_unbind_license())
    '''
    def test_initial_contact_pass(self, m):
        pass
    
    def test_initial_contact_fail(self, m):
        pass
    
    def test_appliance_status_pass(self, m):
        pass
    
    def test_appliance_status_fail(self, m):
        pass
    
    def test_status_pass(self, m):
        pass
    
    def test_status_fail(self, m):
        pass
    
    def test_go_online_pass(self, m):
        pass
    
    def test_go_online_fail(self, m):
        pass
    
    def test_go_offline_pass(self, m):
        pass
    
    def test_go_offline_fail(self, m):
        pass
    
    def test_go_standby_pass(self, m):
        pass
    
    def test_go_standby_fail(self, m):
        pass
    
    def test_lock_online_pass(self, m):
        pass
    
    def test_lock_online_fail(self, m):
        pass
    
    def test_lock_offline_pass(self, m):
        pass
    
    def test_lock_offline_fail(self, m):
        pass
    
    def test_reset_user_db_pass(self, m):
        pass
    
    def test_reset_user_db_fail(self, m):
        pass
    
    def test_diagnostic_pass(self, m):
        pass
    
    def test_diagnostic_fail(self, m):
        pass
    
    def test_send_diagnostic_pass(self, m):
        pass
    
    def test_send_diagnostic_fail(self, m):
        pass
    
    def test_reboot_pass(self):
        pass
    
    def test_reboot_fail(self):
        pass
    
    def test_sginfo_pass(self):
        pass
    
    def test_sginfo_fail(self):
        pass
    
    def test_ssh_pass(self, m):
        pass
    
    def test_ssh_fail(self, m):
        pass
    
    def test_change_ssh_pwd_pass(self, m):
        pass
    
    def test_change_ssh_pwd_fail(self, m):
        pass
    
    def test_time_sync_pass(self, m):
        pass
    
    def test_time_sync_fail(self, m):
        pass
    
    def test_certificate_info_pass(self):
        pass
    
    def test_certificate_info_fail(self):
        pass
    '''
    