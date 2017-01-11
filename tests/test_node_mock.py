import unittest
from smc import session as mysession
import requests_mock
from smc.api.exceptions import LicenseError, NodeCommandFailed
from smc.core.node import Node, ApplianceStatus, NodeStatus
from constants import url, api_key
from smc.base.model import Meta


def register_request(adapter, uri, 
                     status_code=200,
                     json=None, 
                     method='GET',
                     headers={'content-type': 'application/json'}):
    """
    URI should be the 'rel' link for the resource. The expected json returned
    will be the 'link' resource with the follow on href. This href will match 
    the mock address to intercept.
    Json is the payload returned when the URI mapping matches
    """
    # JSON is returned when URI is matched
    json = {'link':[
                    {
                     'href': '{}/{}'.format(url, uri),
                     'method': 'POST',
                     'rel': uri
                     }
                    ]
            } if json is None else json
    
    adapter.register_uri(method, '/{}'.format(uri),
                         json=json,
                         status_code=status_code,
                         headers=headers)

def register_post_reply(adapter, uri, status_code=400,
                        json=None, text=None, 
                        headers={}):
    """
    Reply for POST to specific uri
    """
    adapter.register_uri('POST', '/{}'.format(uri),
                         json=json,
                         text=text,
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
        register_request(m, uri)
        register_post_reply(m, uri, 
                            status_code=400,
                            json={'message':'Impossible to fetch the license',
                                  'status':0},
                            headers={'content-type': 'application/json'})

        node = Node(meta=Meta(href='{}/{}'.format(url, uri)))
        self.assertRaises(LicenseError, lambda: node.fetch_license())
    
    def test_fetch_license_pass(self, m):
        uri = 'fetch'
        register_request(m, uri)
        register_post_reply(m, uri, status_code=200)

        node = Node(meta=Meta(href='{}/{}'.format(url, uri)))
        self.assertIsNone(node.fetch_license())
          
    def test_bind_license_pass(self, m):
        uri = 'bind'
        register_request(m, uri)
        register_post_reply(m, uri, status_code=200)
    
        node = Node(meta=Meta(href='{}/{}'.format(url, uri)))
        self.assertIsNone(node.bind_license())
    
    def test_bind_license_fail(self, m):
        uri = 'bind'
        
        register_request(m, uri)
        register_post_reply(m, uri, 
                            status_code=400,
                            json={'details': ['Another license is already bound to this component.'],
                                  'message': 'Impossible to auto-bind the license.',
                                  'status': 0},
                            headers={'content-type': 'application/json'})
        
        node = Node(meta=Meta(href='{}/{}'.format(url, uri)))
        self.assertRaises(LicenseError, lambda: node.bind_license())

    def test_unbind_license_pass(self, m):
        uri = 'unbind'
        
        register_request(m, uri)
        register_post_reply(m, uri, status_code=200)
        
        node = Node(meta=Meta(href='{}/{}'.format(url, uri)))
        self.assertIsNone(node.unbind_license())
       
    def test_unbind_license_fail(self, m):
        uri = 'unbind'
        
        register_request(m, uri)
        register_post_reply(m, uri, status_code=400)
    
        node = Node(meta=Meta(href='{}/{}'.format(url, uri)))
        self.assertRaises(LicenseError, lambda: node.unbind_license())
    
    def test_cancel_unbind_pass(self, m):
        uri = 'cancel_unbind'
        register_request(m, uri)
        register_post_reply(m, uri, status_code=200)
    
        node = Node(meta=Meta(href='{}/{}'.format(url, uri)))
        self.assertIsNone(node.cancel_unbind_license())
           
    def test_cancel_unbund_fail(self, m):
        uri = 'cancel_unbind'
        register_request(m, uri)
        register_post_reply(m, uri, status_code=400)
        
        node = Node(meta=Meta(href='{}/{}'.format(url, uri)))
        self.assertRaises(LicenseError, lambda: node.cancel_unbind_license())

    def test_initial_contact_fail_node_not_supported(self, m):
        # Some nodes do not support initial contact and will not have an
        # initial contact link
        uri = 'initial_contact'
        # Simulate no 'rel' being returned
        register_request(m, uri, status_code=200,
                        json={'link':[
                                        {
                                         'href': '{}/{}'.format(url, uri),
                                         'method': 'POST',
                                         'rel': 'foo'
                                        }
                                      ]
                              })
        
        node = Node(meta=Meta(href='{}/{}'.format(url, uri)))
        self.assertRaises(NodeCommandFailed, lambda: node.initial_contact())
    
    def test_initial_contact_pass_as_content(self, m):
        uri = 'initial_contact'
        register_request(m, uri, status_code=200)
        register_post_reply(m, uri, status_code=200, text='INITIAL CONFIG',
                            headers={'content-type': 'text/plain'})
        
        node = Node(meta=Meta(href='{}/{}'.format(url, uri)))
        result = node.initial_contact()
        self.assertEqual(result, 'INITIAL CONFIG')
    
    def test_initial_contact_as_file(self, m):
        uri = 'initial_contact'
        register_request(m, uri, status_code=200)
        register_post_reply(m, uri, status_code=200, text='INITIAL CONFIG',
                            headers={'content-type': 'application/octet-stream'})
        
        node = Node(meta=Meta(href='{}/{}'.format(url, uri)))
        self.assertRaises(NodeCommandFailed, lambda: node.initial_contact(filename='/foo'))
        self.assertEqual(node.initial_contact(filename='~'), 'INITIAL CONFIG')
    
    def test_appliance_status_pass(self, m):
        uri = 'appliance_status'
        # Return different follower link
        register_request(m, uri,
                         json={'link':[
                                        {
                                         'href': '{}/appliance_class'.format(url),
                                         'method': 'POST',
                                         'rel': uri
                                        }
                                       ]
                               })
        
        status = {'interface_statuses': {'interface_status': []}, 
                  'hardware_statuses': {'hardware_statuses': []}}
        # Register follower link
        register_request(m, 'appliance_class', json=status)
        
        node = Node(meta=Meta(href='{}/{}'.format(url, uri)))
        result = node.appliance_status()
        self.assertIsInstance(result, ApplianceStatus)
        self.assertEqual(result.hardware_statuses, status.get('hardware_statuses')['hardware_statuses'])
        
    def test_appliance_status_fail(self, m):
        uri = 'appliance_status'
        register_request(m, uri,
                         json={'link':[
                                       {
                                        'href': '{}/appliance_class'.format(url),
                                        'method': 'POST',
                                        'rel': uri
                                        }
                                       ]
                               })
        register_request(m, 'appliance_class', json={'message':'Impossible to retrieve status',
                                                           'status':0},
                               status_code=404)
        node = Node(meta=Meta(href='{}/{}'.format(url, uri)))
        self.assertRaises(NodeCommandFailed, lambda: node.appliance_status())
        
    def test_status_pass(self, m):
        uri = 'status'
        register_request(m, uri,
                         json={'link':[
                                       {
                                        'href': '{}/appliance_class'.format(url),
                                        'method': 'POST',
                                        'rel': uri
                                        }
                                       ]
                               })
        
        status = {'dyn_up': '838', 'configuration_status': 'Installed', 
                  'version': 'version 6.1 #17028', 'name': 've-1 node 1', 
                  'status': 'Locked Online', 'state': 'READY', 
                  'installed_policy': 'Master Engine Policy', 
                  'platform': 'x86-64'}
        
        register_request(m, 'appliance_class', json=status)
        
        node = Node(meta=Meta(href='{}/{}'.format(url, uri)))
        self.assertIsInstance(node.status(), NodeStatus)
        self.assertDictEqual(status, vars(node.status()))   
    
    def test_status_fail(self, m):
        uri = 'status'
        register_request(m, uri,
                         json={'link':[
                                       {
                                        'href': '{}/appliance_class'.format(url),
                                        'method': 'POST',
                                        'rel': uri
                                        }
                                       ]
                               })
        register_request(m, 'appliance_class', json={'message':'Impossible to retrieve status',
                                                           'status':0},
                               status_code=404)
        node = Node(meta=Meta(href='{}/{}'.format(url, uri)))
        self.assertRaises(NodeCommandFailed, lambda: node.status())   
    
    def test_go_online_offline_standby_lock_fail(self, m):
        actions = ['go_online', 'go_offline', 'go_standby', 'lock_online',
                   'lock_offline']
        
        for action in actions:
            uri = action
            post_uri = uri.split('_')
            register_request(m, uri,
                             json={'link':[
                                           {
                                            'href': '{}/{}'.format(url, post_uri[1]),
                                            'method': 'POST',
                                            'rel': uri
                                            }
                                           ]
                                   })
            register_request(m, post_uri[1], status_code=404, method='PUT',
                            json={'details': 'error'})
            
            node = Node(meta=Meta(href='{}/{}'.format(url, uri)))
            #self.assertRaises(NodeCommandFailed, lambda: node.go_online())
            self.assertRaises(NodeCommandFailed, lambda: getattr(node, action)())

    def test_go_online_offline_standby_lock_pass(self, m):
        actions = ['go_online', 'go_offline', 'go_standby', 'lock_online',
                   'lock_offline']
        
        for action in actions:
            uri = action
            post_uri = uri.split('_')
            register_request(m, uri,
                             json={'link':[
                                           {
                                            'href': '{}/{}'.format(url, post_uri[1]),
                                            'method': 'POST',
                                            'rel': uri
                                            }
                                           ]
                                   })
            register_request(m, post_uri[1], method='PUT', status_code=200)
            node = Node(meta=Meta(href='{}/{}'.format(url, uri)))
            self.assertIsNone(getattr(node, action)())
    '''
    
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