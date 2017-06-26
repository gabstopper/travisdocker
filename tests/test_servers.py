'''
Created on Nov 11, 2016

@author: davidlepage
'''
import unittest
from smc.tests.constants import url, api_key, verify
from smc import session
from smc.elements.servers import ManagementServer, LogServer
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
        mgt.add_contact_address(
            contact_address='2.2.2.2', location='newlocation')
        location_ref = location_helper('newlocation')
        for contact in mgt.contact_addresses():
            if contact.location_ref == location_ref:
                self.assertIn('2.2.2.2', contact.addresses)
        # Same location, just append new address
        mgt.add_contact_address(
            contact_address='3.3.3.3', location='newlocation')
        # Test append to existing contact addresses but new location
        mgt.add_contact_address(contact_address='4.4.4.4', location='foobar')
        # Now remove
        mgt.remove_contact_address('newlocation')
        self.assertTrue(len(mgt.contact_addresses()) == 1)

        # Check remaining - should just be contact addr with location foobar
        addresses = mgt.contact_addresses()
        self.assertTrue(len(addresses) == 1)
        self.assertTrue(addresses[0].location == 'foobar')

    def test_add_remove_log_contact_address(self):
        # Assuming only one log server
        log_srv = LogServer.objects.first()
        log_srv.add_contact_address(
            contact_address='3.3.3.3', location='logserverlocation')
        location_ref = location_helper('logserverlocation')
        for contact in log_srv.contact_addresses():
            if contact.location_ref == location_ref:
                self.assertIn('3.3.3.3', contact.addresses)
        # Now remove
        log_srv.remove_contact_address('logserverlocation')
        self.assertTrue(len(log_srv.contact_addresses()) == 0)
