import unittest
from smc import session as mysession
import requests_mock
from smc.api.exceptions import LicenseError, NodeCommandFailed
from smc.core.node import Node, ApplianceStatus, NodeStatus, Diagnostic
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

def register_get_and_reply(adapter, uri, 
                           reply_status=200,# status code to return
                           reply_json=None, # return response.json
                           reply_text=None, # return response.content
                           reply_method='POST',
                           reply_headers={'content-type': 'application/json'}):
    
    # First GET is to return the LINK of the resource URI
    # Note: href is modified so method response goes to different bound URL
    uri_reply = '{}_reply'.format(uri)  
    adapter.register_uri('GET', '/{}'.format(uri),
                         json={'link':[
                                        {
                                         'href': '{}/{}'.format(url, uri_reply),
                                         'method': 'POST',
                                         'rel': uri
                                         }
                                       ]
                               },
                         status_code=200,
                         headers={'content-type': 'application/json'})
    # Register the URI for the reply to above GET
    # Other attributes are included in the POST/PUT reply
    json = reply_json if reply_json is not None else {}
    if reply_text is not None:
        json = None
    
    adapter.register_uri(reply_method, '/{}'.format(uri_reply),
                         json=json,
                         text=reply_text,
                         status_code=reply_status,
                         headers=reply_headers)
    
         
@requests_mock.Mocker()
class HttpMocks(unittest.TestCase):
    
    def setUp(self):
        mysession.login(url, api_key)
        
    def tearDown(self):
        mysession.logout()
    
    def test_fetch_license_fail(self, m):
        uri = 'fetch'
        
        register_get_and_reply(m, uri, 
                               reply_status=400, 
                               reply_json={'message':'Impossible to fetch the license',
                                           'status':0})

        node = Node(meta=Meta(href='{}/{}'.format(url, uri)))
        self.assertRaises(LicenseError, lambda: node.fetch_license())
    
    def test_fetch_license_pass(self, m):
        uri = 'fetch'
        register_get_and_reply(m, uri, 
                               reply_status=200)

        node = Node(meta=Meta(href='{}/{}'.format(url, uri)))
        self.assertIsNone(node.fetch_license())
    
     
    def test_bind_license_pass(self, m):
        uri = 'bind'
        register_get_and_reply(m, uri, 
                               reply_status=200)

        node = Node(meta=Meta(href='{}/{}'.format(url, uri)))
        self.assertIsNone(node.bind_license())
    
    def test_bind_license_fail(self, m):
        uri = 'bind'
        
        register_get_and_reply(m, uri, 
                               reply_status=400, 
                               reply_json={'details': ['Another license is already bound to this component.'],
                                           'message': 'Impossible to auto-bind the license.',
                                           'status': 0})
        
        node = Node(meta=Meta(href='{}/{}'.format(url, uri)))
        self.assertRaises(LicenseError, lambda: node.bind_license())
    
    def test_unbind_license_pass(self, m):
        uri = 'unbind'
        
        register_get_and_reply(m, uri, 
                               reply_status=200)
        
        node = Node(meta=Meta(href='{}/{}'.format(url, uri)))
        self.assertIsNone(node.unbind_license())
    
    def test_unbind_license_fail(self, m):
        uri = 'unbind'
        
        register_get_and_reply(m, uri, 
                               reply_status=400,
                               reply_json={'message': 'error unbind'})

        node = Node(meta=Meta(href='{}/{}'.format(url, uri)))
        self.assertRaises(LicenseError, lambda: node.unbind_license())
    
    def test_cancel_unbind_pass(self, m):
        uri = 'cancel_unbind'
        register_get_and_reply(m, uri, 
                               reply_status=200)

        node = Node(meta=Meta(href='{}/{}'.format(url, uri)))
        self.assertIsNone(node.cancel_unbind_license())
         
    def test_cancel_unbind_fail(self, m):
        uri = 'cancel_unbind'
        
        register_get_and_reply(m, uri,
                               reply_status=400, 
                               reply_json={'message': 'error unbind'})

        node = Node(meta=Meta(href='{}/{}'.format(url, uri)))
        self.assertRaises(LicenseError, lambda: node.cancel_unbind_license())

    def test_initial_contact_fail_node_not_supported(self, m):
        # Some nodes do not support initial contact and will not have an
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
        
        register_get_and_reply(m, uri, 
                               reply_status=200, 
                               reply_text='INITIAL CONFIG',
                               reply_headers={'content-type': 'text/plain'})
        
        node = Node(meta=Meta(href='{}/{}'.format(url, uri)))
        result = node.initial_contact()
        self.assertEqual(result, 'INITIAL CONFIG')
    
    def test_initial_contact_as_file(self, m):
        uri = 'initial_contact'
        register_get_and_reply(m, uri, 
                               reply_status=200, 
                               reply_text='INITIAL CONFIG', 
                               reply_headers={'content-type': 'application/octet-stream'})
        
        node = Node(meta=Meta(href='{}/{}'.format(url, uri)))
        self.assertRaises(NodeCommandFailed, lambda: node.initial_contact(filename='/foo'))
        self.assertEqual(node.initial_contact(filename='~'), 'INITIAL CONFIG')
    
    def test_appliance_status_pass(self, m):
        uri = 'appliance_status'
        
        status = {'interface_statuses': {'interface_status': []}, 
                  'hardware_statuses': {'hardware_statuses': []}}
        
        register_get_and_reply(m, uri, 
                               reply_json=status,
                               reply_method='GET')
        
        node = Node(meta=Meta(href='{}/{}'.format(url, uri)))
        result = node.appliance_status()
        self.assertIsInstance(result, ApplianceStatus)
        self.assertEqual(result.hardware_statuses, status.get('hardware_statuses')['hardware_statuses'])
    
    def test_appliance_status_fail(self, m):
        uri = 'appliance_status'
        
        register_get_and_reply(m, uri, 
                               reply_status=404, 
                               reply_json={'message':'Impossible to retrieve status',
                                           'status':0},
                               reply_method='GET')
        
        node = Node(meta=Meta(href='{}/{}'.format(url, uri)))
        self.assertRaises(NodeCommandFailed, lambda: node.appliance_status())
    
    def test_status_pass(self, m):
        uri = 'status'
        
        status = {'dyn_up': '838', 'configuration_status': 'Installed', 
                  'version': 'version 6.1 #17028', 'name': 've-1 node 1', 
                  'status': 'Locked Online', 'state': 'READY', 
                  'installed_policy': 'Master Engine Policy', 
                  'platform': 'x86-64'}
        
        register_get_and_reply(m, uri, 
                               reply_json=status, 
                               reply_method='GET')

        node = Node(meta=Meta(href='{}/{}'.format(url, uri)))
        self.assertIsInstance(node.status(), NodeStatus)
        self.assertDictEqual(status, vars(node.status()))   
    
    def test_status_fail(self, m):
        uri = 'status'
        register_get_and_reply(m, uri, 
                               reply_status=404, 
                               reply_json={'message':'Impossible to retrieve status',
                                           'status':0},
                               reply_method='GET')
        
        node = Node(meta=Meta(href='{}/{}'.format(url, uri)))
        self.assertRaises(NodeCommandFailed, lambda: node.status())   
    
    def test_go_online_offline_standby_lock_fail(self, m):
        actions = ['go_online', 'go_offline', 'go_standby', 'lock_online',
                   'lock_offline']
        
        for action in actions:
            uri = action
            
            register_get_and_reply(m, uri, 
                                   reply_status=404, 
                                   reply_json={'details' : '{}'.format(action)}, 
                                   reply_method='PUT')

            node = Node(meta=Meta(href='{}/{}'.format(url, uri)))
            self.assertRaises(NodeCommandFailed, lambda: getattr(node, action)())
    
    def test_go_online_offline_standby_lock_pass(self, m):
        actions = ['go_online', 'go_offline', 'go_standby', 'lock_online',
                   'lock_offline']
        
        for action in actions:
            uri = action
            register_get_and_reply(m, uri, 
                                   reply_status=200, 
                                   reply_method='PUT')

            node = Node(meta=Meta(href='{}/{}'.format(url, uri)))
            self.assertIsNone(getattr(node, action)())
    
    def test_reset_user_db_unsupported_node_fail(self, m):
        uri = 'reset_user_db'
        register_request(m, uri,
                         json={'link':[
                                           {
                                            'href': '{}/{}'.format(url, uri),
                                            'method': 'POST',
                                            'rel': 'foo'
                                            }
                                           ]
                                   })
        node = Node(meta=Meta(href='{}/{}'.format(url, uri)))
        self.assertRaises(NodeCommandFailed, lambda: node.reset_user_db())
       
    def test_reset_user_db_fail(self, m):
        uri = 'reset_user_db'
        
        register_get_and_reply(m, uri, 
                               reply_status=404, 
                               reply_json={'details': 'error'},
                               reply_method='PUT')
            
        node = Node(meta=Meta(href='{}/{}'.format(url, uri)))
        self.assertRaises(NodeCommandFailed, lambda: node.reset_user_db())
    
    def test_reset_user_db_pass(self, m):
        uri = 'reset_user_db'
        
        register_get_and_reply(m, uri, 
                               reply_status=200, 
                               reply_method='PUT')
    
        node = Node(meta=Meta(href='{}/{}'.format(url, uri)))
        self.assertIsNone(node.reset_user_db())
       
    def test_diagnostic_unsupported_node_fail(self, m):
        uri = 'diagnostic'
        register_request(m, uri,
                         json={'link':[
                                           {
                                            'href': '{}/{}'.format(url, uri),
                                            'method': 'POST',
                                            'rel': 'foo'
                                            }
                                           ]
                                   })
        node = Node(meta=Meta(href='{}/{}'.format(url, uri)))
        self.assertRaises(NodeCommandFailed, lambda: node.diagnostic())
    
    def test_diagnostic_pass(self, m):
        uri = 'diagnostic'
        
        diag = {'diagnostics': [
                    {'diagnostic': {'name': 'SNMP Monitoring', 'enabled': False}}, 
                    {'diagnostic': {'name': 'User defined', 'enabled': False}}, 
                    {'diagnostic': {'name': 'Syslog', 'enabled': False}}]}
        
        register_get_and_reply(m, uri,
                               reply_status=200,
                               reply_json=diag, 
                               reply_method='GET')
        
        node = Node(meta=Meta(href='{}/{}'.format(url, uri)))
        diagnostics = node.diagnostic()
        self.assertIsInstance(diagnostics, list)
        for diag in diagnostics:
            self.assertIsInstance(diag, Diagnostic)
    
    def test_send_diagnostic_fail(self, m):
        uri = 'send_diagnostic'
        register_get_and_reply(m, uri, 
                               reply_status=400, 
                               reply_json={'message': 'error send diag'}, 
                               reply_method='POST')
        
        node = Node(meta=Meta(href='{}/{}'.format(url, uri)))
        self.assertRaises(NodeCommandFailed, lambda: node.send_diagnostic([]))       
    
    def test_reboot_fail(self, m):
        uri = 'reboot'
        register_get_and_reply(m, uri, 
                               reply_method='PUT', 
                               reply_json={'message': 'error on reboot'},
                               reply_status=400)
    
        node = Node(meta=Meta(href='{}/{}'.format(url, uri)))
        self.assertRaises(NodeCommandFailed, lambda: node.reboot())
    
    def test_reboot_pass(self, m):
        uri = 'reboot'
        register_get_and_reply(m, uri, 
                               reply_method='PUT')
        node = Node(meta=Meta(href='{}/{}'.format(url, uri)))
        self.assertIsNone(node.reboot())
    
    #def test_sginfo_pass(self, m):
    #    pass
    
    #def test_sginfo_fail(self, m):
    #    pass
    
    def test_ssh_pass(self, m):
        uri = 'ssh'
        
        register_get_and_reply(m, uri, 
                               reply_status=200, 
                               reply_method='PUT')
        
        node = Node(meta=Meta(href='{}/{}'.format(url, uri)))
        self.assertIsNone(node.ssh())
    
    def test_ssh_unsupported_node_fail(self, m):
        uri = 'ssh'
        register_request(m, uri,
                         json={'link':[
                                           {
                                            'href': '{}/{}'.format(url, uri),
                                            'method': 'POST',
                                            'rel': 'foo'
                                            }
                                           ]
                                   })
        node = Node(meta=Meta(href='{}/{}'.format(url, uri)))
        self.assertRaises(NodeCommandFailed, lambda: node.ssh())
        
    def test_ssh_fail(self, m):
        uri = 'ssh'
        
        register_get_and_reply(m, uri, 
                               reply_status=400, 
                               reply_json={'message': 'error in ssh'}, 
                               reply_method='PUT')
        
        node = Node(meta=Meta(href='{}/{}'.format(url, uri)))
        self.assertRaises(NodeCommandFailed, lambda: node.ssh())
    
    def test_change_ssh_pwd_unsupported_node_fail(self, m):
        uri = 'change_ssh_pwd'
        register_request(m, uri,
                         json={'link':[
                                           {
                                            'href': '{}/{}'.format(url, uri),
                                            'method': 'POST',
                                            'rel': 'foo'
                                            }
                                           ]
                                   })
        node = Node(meta=Meta(href='{}/{}'.format(url, uri)))
        self.assertRaises(NodeCommandFailed, lambda: node.change_ssh_pwd('pwd'))
      
    def test_change_ssh_pwd_fail(self, m):
        uri = 'change_ssh_pwd'
        
        register_get_and_reply(m, uri, 
                               reply_status=400, 
                               reply_json={'message': 'error in change ssh'}, 
                               reply_method='PUT')
        
        node = Node(meta=Meta(href='{}/{}'.format(url, uri)))
        self.assertRaises(NodeCommandFailed, lambda: node.change_ssh_pwd('pwd'))
        
    def test_change_ssh_pwd_pass(self, m):
        uri = 'change_ssh_pwd'
        register_get_and_reply(m, uri, 
                               reply_status=200, 
                               reply_method='PUT')
        
        node = Node(meta=Meta(href='{}/{}'.format(url, uri)))
        self.assertIsNone(node.change_ssh_pwd('pwd'))
    
    def test_time_sync_unsupported_node_fail(self, m):
        uri = 'time_sync'
        register_request(m, uri,
                         json={'link':[
                                           {
                                            'href': '{}/{}'.format(url, uri),
                                            'method': 'POST',
                                            'rel': 'foo'
                                            }
                                           ]
                                   })
        node = Node(meta=Meta(href='{}/{}'.format(url, uri)))
        self.assertRaises(NodeCommandFailed, lambda: node.time_sync())
    
    def test_time_sync_fail(self, m):
        uri = 'time_sync'
        
        register_get_and_reply(m, uri, 
                               reply_status=400, 
                               reply_json={'message': 'error in time sync'}, 
                               reply_method='PUT')
        
        node = Node(meta=Meta(href='{}/{}'.format(url, uri)))
        self.assertRaises(NodeCommandFailed, lambda: node.time_sync())
     
    def test_time_sync_pass(self, m):
        uri = 'time_sync'
        register_get_and_reply(m, uri, 
                               reply_status=200, 
                               reply_method='PUT')
        
        node = Node(meta=Meta(href='{}/{}'.format(url, uri)))
        self.assertIsNone(node.time_sync())
  
    def test_certificate_info_pass(self, m):
        uri = 'certificate_info'
        
        cert = {'revocation_date': 0, 
                'contactable_href': 'http://1.1.1.1', 
                'expiration_date': 0, 
                'serial_number': 0}
        
        register_get_and_reply(m, uri, 
                               reply_status=200, 
                               reply_json=cert, 
                               reply_method='GET')
        
        node = Node(meta=Meta(href='{}/{}'.format(url, uri)))
        result = node.certificate_info()
        self.assertDictEqual(result, cert)
  