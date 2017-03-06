'''
Created on Nov 13, 2016

@author: davidlepage
'''
import unittest
import time
from smc import session
from constants import url, api_key, verify
from smc.base.util import save_to_file
from smc.core.engine import Engine
from smc.api.exceptions import LoadEngineFailed, NodeCommandFailed,\
    TaskRunFailed, LicenseError, EngineCommandFailed
from smc.core.route import Routing, Routes
from smc.core.node import NodeStatus, HardwareStatus,\
    InterfaceStatus
from smc.actions.search import element_by_href_as_json
from smc.api.common import SMCRequest
from smc.core.engines import Layer3Firewall

# !! This requires a validly deployed firewall to test as it will test options within the node and 
# a couple engine level methods (upload/refresh) as well.
# In addition, it will test node when the node is not ready to verify the exception catching
running_firewall = 've-1' #For these tests to succeed, this is a virtual FW
engine = None
engine_not_initialized = None

class Test(unittest.TestCase):
    def setUp(self):
        session.login(url=url, api_key=api_key, 
                      verify=True)
        try:
            global engine
            engine = Engine(running_firewall).load()
        except LoadEngineFailed:
            print("Running firewall engine NOT defined. ")
            raise

        global engine_not_initialized
        engine_not_initialized = Layer3Firewall.create('smc-python-api-nodetest', 
                                                       mgmt_ip='1.1.1.1', 
                                                       mgmt_network='1.1.1.0/24')
    
    def tearDown(self):
        try:
            engine_not_initialized.delete()
            session.logout()
        except SystemExit:
            pass
    
    ### Should be in engine, but this class requires an engine that is valid so easier to
    #just put it here for now
    
    def test_engine_export(self):
        ### Test the iterator, this is a short lived operation
        for _ in engine.export(wait_for_finish=True):
            pass
    
    def test_save_to_file(self):
        # Valid
        self.assertIsNone(save_to_file('blah', 'foo'))
        
    def test_save_to_bad_file(self):
        # Invalid file
        self.assertRaises(IOError, lambda: save_to_file('foo/efwef/', 'foo'))
    
    def test_node_bad_attribute(self):
        for node in engine.nodes:
            self.assertRaises(AttributeError, lambda: node.blah())
            
    def test_engine_route_table_success(self):
        # Return route table
        routes = engine.routing_monitoring
        if routes:
            self.assertIsInstance(engine.routing_monitoring, Routes)
        else:
            self.assertTrue(len(routes) == 0)
        
    def test_engine_refresh_policy_success(self):
        # Verify we get a task returned
        href = next(engine.refresh(wait_for_finish=False))
        self.assertRegexpMatches(href, r'^http')
        d = SMCRequest(href=href).delete()
        self.assertEqual(204, d.code)
        
        wait_times = 0
        while True:
            status = element_by_href_as_json(href)
            if not status.get('in_progress') and \
                status.get('last_message').startswith('Operation abort'):
                #Abort
                break
            elif wait_times == 10:
                print("Aborted after waiting 20 seconds for policy to stop")
                break
            else:
                wait_times += 1
                time.sleep(2)
        
    def test_engine_refresh_policy_failure(self):
        self.assertRaises(TaskRunFailed, lambda: engine_not_initialized.refresh(wait_for_finish=False))
        
    def test_engine_upload_and_go_online_offline_lock_success(self):
        # Verify policy upload
        task = engine.upload(policy=None)
        href = next(task)
        
        self.assertRegexpMatches(href, r'^http')
        d = SMCRequest(href=href).delete()
        self.assertEqual(204, d.code)

        #Wait for task to be aborted
        wait_times = 0
        while True:
            status = element_by_href_as_json(href)
            if not status.get('in_progress') and \
                status.get('last_message').startswith('Operation abort'):
                #Abort
                break
            elif wait_times == 10:
                print("Aborted after waiting 20 seconds for upload to stop")
                break
            else:
                time.sleep(2)
                 
    def test_offline_online_lock_success(self):
        for node in engine.nodes:
            self.assertIsNone(node.go_offline())
            self.assertIsNone(node.lock_offline())
            self.assertIsNone(node.go_online())
            self.assertIsNone(node.lock_online())
        
    def test_engine_upload_failure(self): #Bad Policy
        self.assertRaises(TaskRunFailed, lambda: next(engine.upload(policy='someboguspolicy')))
    
    def test_engine_generate_snapshot(self):
        # Generate snapshot will save filename in SMCResult.content
        self.assertIsNone(engine.generate_snapshot())
    
    def test_engine_generate_snapshot_failure(self):
        with self.assertRaises(EngineCommandFailed):
            engine_not_initialized.generate_snapshot()
        
        
    def test_node_fetch_license_fail(self):
        # Fetch is not available on some node types (virtual)
        for node in engine.nodes:
            self.assertIsNone(node.fetch_license())
            
    def test_node_fetch_license_success(self): # Invalid POS
        for node in engine_not_initialized.nodes:
            self.assertRaises(LicenseError, lambda: node.fetch_license())
    
    def test_node_bind_license(self):
        for node in engine_not_initialized.nodes:
            # Test fail, no POS
            self.assertIsNone(node.bind_license())
            # Unbind
            self.assertIsNone(node.unbind_license())
            # Unbind fail
            self.assertRaises(LicenseError, lambda: node.unbind_license())
            #Cancel unbind fail (no POS)
            self.assertRaises(LicenseError, lambda: node.cancel_unbind_license())
            # Cause LicenseError due to invalid license id specified
            self.assertRaises(LicenseError, lambda: node.bind_license(license_item_id='fooo'))
    
    def test_node_initial_contact_to_file(self):
        # Initial contact
        for node in engine_not_initialized.nodes:
            self.assertIsNotNone(node.initial_contact()) #Base level init, shown as text
            result = node.initial_contact(filename='initial_contact.txt') #Saved to file
            self.assertIsNotNone(result)
        import os
        self.assertTrue(os.path.isfile('initial_contact.txt'))
        cwd = os.getcwd() #Force failure of initial contact
        self.assertRaises(NodeCommandFailed, lambda: node.initial_contact(filename=cwd))
        
    def test_node_initial_contact_fail(self):
        # Fails on VE nodes for example
        for node in engine.nodes:
            self.assertRaises(NodeCommandFailed, lambda: node.initial_contact())

    def test_go_standby_fail(self):
        for node in engine.nodes:
            self.assertRaises(NodeCommandFailed, lambda: node.go_standby())
    
    def test_lock_online_offline_failure(self): #Not initialized fw
        for node in engine_not_initialized.nodes:
            self.assertRaises(NodeCommandFailed, lambda: node.lock_offline())
            self.assertRaises(NodeCommandFailed, lambda: node.lock_online())
        
    def test_node_go_offline_failure(self):
        for node in engine_not_initialized.nodes:
            self.assertRaises(NodeCommandFailed, lambda: node.go_offline())
    
    def test_node_go_online_failure(self):
        for node in engine_not_initialized.nodes:
            self.assertRaises(NodeCommandFailed, lambda: node.go_online())
    
    def test_node_appliance_status_success(self): #VE-1
        for node in engine.nodes:
            for status in node.appliance_status.hardware_status:
                self.assertIsInstance(status, HardwareStatus)
                self.assertIsNotNone(status.name)
                self.assertIsInstance(status.items, list)
            for status in node.appliance_status.interface_status:
                self.assertIsInstance(status, InterfaceStatus)
                self.assertIsNotNone(status.name)
                print('type of interface: %s' % type(status.items))
                                   
    def test_node_appliance_status_fail(self):
        # Fails for virtual engines
        self.assertRaises(NodeCommandFailed, lambda: engine_not_initialized.nodes[0].appliance_status)

    def test_node_status_success(self):
        # Return node status
        for node in engine.nodes:
            self.assertIsInstance(node.status(), NodeStatus)
    
    def test_node_status_fail(self):
        time.sleep(3)
        for node in engine_not_initialized.nodes:
            self.assertEqual(node.status().state, 'NO_STATUS')
    
    def test_time_sync_failure(self):
        self.assertRaises(NodeCommandFailed, lambda: engine_not_initialized.nodes[0].time_sync())
        self.assertRaises(NodeCommandFailed, lambda: engine.nodes[0].time_sync())

    def test_reset_user_db_failure(self):
        for node in engine.nodes: #Virtual 
            self.assertRaises(NodeCommandFailed, lambda: node.reset_user_db())
        for node in engine_not_initialized.nodes:
            self.assertRaises(NodeCommandFailed, lambda: node.reset_user_db())
    
    def test_ssh_enable_disable_fail(self):
        # These will fail, enable ssh on uninitialized node, or virtual engine
        self.assertRaises(NodeCommandFailed, lambda: engine.nodes[0].ssh())
        self.assertRaises(NodeCommandFailed, lambda: engine_not_initialized.nodes[0].ssh())
    
    def test_ssh_change_pwd_fail(self):
        # Cant change pwd on uninit node or virtual engine
        self.assertRaises(NodeCommandFailed, lambda: engine.nodes[0].change_ssh_pwd(pwd='password'))
        self.assertRaises(NodeCommandFailed, lambda: engine_not_initialized.nodes[0].change_ssh_pwd(pwd='password'))
        
    def test_diagnostic(self):
        # Unsupported node type (virtual_fw)
        self.assertRaises(NodeCommandFailed, lambda: engine.nodes[0].diagnostic())
        # Not initialized node
        self.assertRaises(NodeCommandFailed, lambda: engine_not_initialized.nodes[0].diagnostic())
    
    def test_reboot_fail(self):
        # Not initialized node
        self.assertRaises(NodeCommandFailed, lambda: engine_not_initialized.nodes[0].reboot())
    
    def test_engine_snapshot(self):
        # Existing engine will have at least one snapshot from initial policy push
        snapshots = engine.snapshots()
        self.assertTrue(len(snapshots)>0)
        self.assertTrue(snapshots[0].name is not None)
        # No filename provided for download
        self.assertIsNone(snapshots[0].download())
        # Failed download, incorrect directory
        self.assertRaises(EngineCommandFailed, lambda: snapshots[0].download(filename='/'))
    
    def test_engine_routing_all(self):
        # Test getting routes back
        routes = engine.routing.all()
        self.assertIsInstance(routes, list)
        for route in routes:
            self.assertIsInstance(route, Routing)
            if route.name == 'Interface 1':
                for r in route.all():
                    self.assertEqual(r.ip, u'10.29.248.9/30')
        
if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()