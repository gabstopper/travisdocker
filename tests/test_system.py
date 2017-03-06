'''
Created on Feb 20, 2017

@author: davidlepage
'''
import unittest
import requests_mock
from smc import session
from .constants import url, api_key, verify
from smc.administration.system import System
from smc.administration.updates import UpdatePackage, EngineUpgrade
from smc.administration.license import License
from smc.elements.network import Host
from smc.elements.group import Group
from smc.api.exceptions import ActionCommandFailed, FetchElementFailed
from smc.administration.access_rights import AccessControlList

class Test(unittest.TestCase):

    def setUp(self):
        session.login(url=url, api_key=api_key, verify=verify,
                      timeout=40)
        
    def tearDown(self):
        try:
            session.logout()
        except SystemExit:
            pass
    
    def testSMCInfo(self):
        system = System()
        version = system.smc_version
        self.assertTrue(len(version.split(' ')) == 2)
        self.assertIsNotNone(system.smc_time)
        package = int(system.last_activated_package)
        self.assertIsInstance(package, int)
        self.assertIsNone(system.empty_trash_bin())
        self.assertIsInstance(system.system_properties(), list)
        
    def testPackageUpdates(self):
        system = System()
        for package in system.update_package():
            self.assertIsInstance(package, UpdatePackage)
            self.assertEqual(package.state, 'active')
            self.assertTrue(package.name.startswith('Update'))
            self.assertTrue(package.href.startswith('http'))
            self.assertIsNotNone(package.activation_date)
            self.assertIsInstance(package.package_id, int)
            self.assertIsNotNone(package.release_date)
    
            # Already active
            with self.assertRaises(ActionCommandFailed):
                package.activate()
            #Already active
            with self.assertRaises(ActionCommandFailed):
                package.download()
        

    def testLicense(self):
        system = System()
        with self.assertRaises(FetchElementFailed):
            system.license_check_for_new()
        
        with self.assertRaises(FetchElementFailed):
            system.license_details()
            
        with self.assertRaises(FetchElementFailed):
            system.license_fetch()
            
        for licenses in system.licenses:
            self.assertIsInstance(licenses, License)
            self.assertIsNotNone(licenses.name)
            with self.assertRaises(TypeError):
                licenses.foo = 'bar'
            self.assertIsNone(licenses.foo)
            
        
    def testExportElements(self):
        system = System()
        export = next(system.export_elements(filename='system-elements.zip', 
                                             typeof='foo', #Will get all elements
                                             wait_for_finish=False))
        self.assertTrue(export.startswith('http'))
        
    def testVisbileVirtualEngineMapping(self):
        # This doesnt really do much except return dict
        system = System()
        self.assertFalse(system.visible_virtual_engine_mapping().get('mapping'))
    
    def testReferencesByElement(self):
        system = System()
        Host.create('systemhost', '1.1.1.1')
        host = Host('systemhost')
        
        self.assertFalse(system.references_by_element(host.href))
        # Add a group and the member to create a reference
        Group.create(name='systemgroup', members=[host.href])
        for references in system.references_by_element(host.href):
            self.assertEqual(references.get('href'), Group('systemgroup').href)
        
        Group('systemgroup').delete()
        Host('systemhost').delete()
        
    def testSystemBlacklist(self):
        # Global blacklist
        system = System()
        with self.assertRaises(ActionCommandFailed):
            system.blacklist('1.1.1.1/32', '2.2.2.2/32')
            
    def test_access_controlList(self):
        acl = AccessControlList('ALL Elements')
        self.assertIsNotNone(acl.comment)
        self.assertIsInstance(acl.granted_element(), list)
    
    @requests_mock.mock()    
    def test_engine_upgrade_as_mock(self, m):
        
        upgrade_cache = {'filename': 'Security Engine upgrade 5.5.16 build 9927 for Express',
                         'guid': 'fw_engine_upgrade_express_5.5.16_9927_express',
                         'link': [{'href': '{}/fw_engine_upgrade_express_5.5.16_9927_express'.format(url),
                                   'method': 'GET',
                                   'rel': 'self',
                                   'type': 'engine_upgrade'},
                                  {'href': '{}/download'.format(url),
                                   'method': 'POST',
                                   'rel': 'download'},
                                  {'href': '{}/activate'.format(url),
                                   'method': 'POST',
                                   'rel': 'activate'}],
                         'name': 'Security Engine upgrade 5.5.16 build 9927 for Express',
                         'platform': 'Express',
                         'release_date': '2015-09-08T11:46:46Z',
                         'release_notes': 'https:/FW_5_5_16-express-RLNT.pdf',
                         'version': '5.5.16 build 9927'}
    
        upgrade = EngineUpgrade(meta='{}/upgrade'.format(url))
        upgrade.add_cache(upgrade_cache)
        
        self.assertEqual(upgrade.platform, 'Express')
        self.assertEqual(upgrade.release_date, '2015-09-08T11:46:46Z')
        self.assertTrue(upgrade.release_notes.startswith('https'))
        self.assertEqual(upgrade.version, '5.5.16 build 9927')
                   
        task_progress = {"follower":"{}/progress/MmM0ZmYxYzU3M2VmMGU4Yzo2OGIyNTlkODoxNWE5YjY1ZDU2OToxOTg2".format(url),
                         "in_progress":True,
                         "last_message":"",
                         "link":[{"href":"{}/progress/MmM0ZmYxYzU3M2VmMGU4Yzo2OGIyNTlkODoxNWE5YjY1ZDU2OToxOTg2".format(url),
                                  "method":"GET",
                                  "rel":"self",
                                  "type":"task_progress"},
                                 {"href":"{}/progress/MmM0ZmYxYzU3M2VmMGU4Yzo2OGIyNTlkODoxNWE5YjY1ZDU2OToxOTg2".format(url),
                                  "method":"DELETE",
                                  "rel":"abort"}],
                         "resource":[],
                         "success":False,
                         "waiting_inputs":False}
        
        m.post('/download', [{'status_code': 200, 'json': task_progress,
                              'headers': {'content-type': 'application/json'}}])
        
        self.assertTrue(next(upgrade.download()).startswith('http'))
        
        m.post('/activate', [{'status_code': 200, 'json': task_progress,
                              'headers': {'content-type': 'application/json'}}])
        
        self.assertTrue(next(upgrade.activate()).startswith('http'))
        
        # First query is GET /system
        system = {'version': '6.1.2 [10223]', 
                  'link': [{'rel': 'engine_upgrade', 
                            'href': '{}/engine_upgrade'.format(url), 
                            'method': 'GET'}]}
                
        engine_upgrade = [{'name': 'Security Engine upgrade 6.1.1 build 17035 for x86-64-small', 
                           'href': '{}/fw_engine_upgrade_6.1.1_17035_x86-64-small'.format(url), 
                           'type': 'engine_upgrade'}]
        
        m.get('/system', [{'status_code': 200,
                           'json': system,
                           'headers': {'content-type': 'application/json'}}])
        m.get('/engine_upgrade', [{'status_code': 200,
                                   'json': engine_upgrade,
                                   'headers': {'content-type': 'application/json'}}])
        smc_system = System()
        smc_system.add_cache(system)
        for x in smc_system.engine_upgrade():
            self.assertIsInstance(x, EngineUpgrade)
            
        
if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()