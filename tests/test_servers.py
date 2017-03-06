'''
Created on Nov 11, 2016

@author: davidlepage
'''
import unittest
from smc.tests.constants import url, api_key, verify
from smc import session
from smc.elements.servers import ManagementServer
from smc.elements.collection import describe_log_server
from smc.elements.helpers import location_helper

class Test(unittest.TestCase):
    tmp = {}
    def setUp(self):
        session.login(url=url, api_key=api_key, verify=verify)
        
    def tearDown(self):
        try:
            session.logout()
        except SystemExit:
            pass

    def test_add_remove_mgmt_contact_address(self):
        # Add then remove a contact address
        mgt = ManagementServer('Management Server') 
        mgt.add_contact_address(contact_address='2.2.2.2', location='newlocation')
        location_ref = location_helper('newlocation')
        for contact in mgt.contact_addresses():
            if contact.get('location_ref' == location_ref):
                self.assertIn('2.2.2.2', contact.get('addresses'))
        # Now remove
        mgt.remove_contact_address(location_ref)
        self.assertTrue(len(mgt.contact_addresses()) == 0)
                            
    def test_add_remove_log_contact_address(self):
        # Assuming only one log server
        servers = describe_log_server()
        self.assertIsNotNone(servers)
        log_srv = servers[0]
        log_srv.add_contact_address(contact_address='3.3.3.3', location='logserverlocation')
        location_ref = location_helper('logserverlocation')
        for contact in log_srv.contact_addresses():
            if contact.get('location_ref' == location_ref):
                self.assertIn('3.3.3.3', contact.get('addresses'))
        # Now remove
        log_srv.remove_contact_address(location_ref)
        self.assertTrue(len(log_srv.contact_addresses()) == 0)
