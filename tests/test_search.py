'''
Created on Jul 10, 2016

@author: davidlepage
'''
import unittest
from .constants import url, api_key, verify
from smc import session
from smc.elements.network import Host
import smc.actions
from smc.api.exceptions import SMCConnectionError, UnsupportedEntryPoint
from smc.api.web import SMCResult
from smc.api.common import fetch_href_by_name, fetch_entry_point, SMCRequest
from smc.elements.collection import describe_log_server

common_host = None
test_api = None
class Test(unittest.TestCase):
       
    def setUp(self):
        session.login(url=url, api_key=api_key, verify=verify)
        Host.create('test-common-api-user', '12.12.12.12')
        Host.create('test-api-user', '12.12.12.12') #used for wildcard searches
    
    def tearDown(self):
        try:
            host = smc.actions.search.element_href_use_filter('test-common-api-user', 'host')
            SMCRequest(href=host).delete()
            t = smc.actions.search.element_href_use_filter('test-api-user', 'host')
            SMCRequest(href=t).delete()
            session.logout()
        except SystemExit:
            pass

    def test_fetch_entry_point_failure(self):
        self.assertRaises(UnsupportedEntryPoint, lambda: fetch_entry_point('tedgsgshf'))
    
    def test_search_element_references(self):
        # Check for element references
        host = Host('test-common-api-user').href
        self.assertTrue(len(smc.actions.search.element_references(host)) == 0)
    
    def test_search_element_references_as_smcresult(self):
        host = Host('test-common-api-user').href
        result = smc.actions.search.element_references_as_smcresult(host)
        self.assertIsInstance(result, SMCResult)
            
    def test_element_by_name(self):
        result = smc.actions.search.element('test-common-api-user')
        self.assertRegexpMatches(result, r'^http')

    #@unittest.skip("good")
    def test_element_href(self):
        """ Test element href """
        href = smc.actions.search.element_href('test-common-api-user')
        self.util_check_for_href(href)
        
        """ Test unknown host """
        href = smc.actions.search.element_href('1234test-common-api-user')
        self.assertIsNone(href)
        
        """ Test None """
        href = smc.actions.search.element_href(None)
        self.assertIsNone(href)
    
    #@unittest.skip("good")    
    def test_element_as_json(self):
        """ Test element href """
        result = smc.actions.search.element_as_json('test-common-api-user')
        self.assertEqual(result.get('name'), 'test-common-api-user')
        
        """ Test unknown host """
        result = smc.actions.search.element_as_json('1234test-common-api-user')
        self.assertIsNone(result)
        
        """ Test None """
        result = smc.actions.search.element_as_json(None)
        self.assertIsNone(result)
    
    #@unittest.skip("good")    
    def test_element_as_json_with_etag(self):
        """ Test element json with etag (returns SMCResult) """
        href = smc.actions.search.element_as_json_with_etag('test-common-api-user')
        self.assertIsNotNone(href.etag)
        self.assertEqual(href.json.get('name'), 'test-common-api-user')
        
        """ Test unknown host """
        href = smc.actions.search.element_as_json_with_etag('1234test-common-api-user')
        self.assertIsNone(href.href)
        
        """ Test None """
        href = smc.actions.search.element_as_json_with_etag(None)
        self.assertIsNone(href)
    
    #@unittest.skip("good")         
    def test_element_info_as_json(self):
        """ Test element json - returns dict from SMC query returned from common_api """
        href = smc.actions.search.element_info_as_json('test-common-api-user')
        self.assertEqual(href[0].get('name'), 'test-common-api-user')
        
        """ Test unknown host """
        href = smc.actions.search.element_info_as_json('1234test-common-api-user')
        self.assertIsNone(href)
        
        """ Test unknown host """
        href = smc.actions.search.element_info_as_json(None)
        self.assertIsNone(href)
    
    #@unittest.skip("good")        
    def test_element_href_use_wildcard(self):
        """ Should return list of at least two elements (name=test*) """
        result = smc.actions.search.element_href_use_wildcard('test')
        self.assertTrue(result)
        
        """ Test unknown host """
        result = smc.actions.search.element_href_use_wildcard('1234test-common-api-user')
        self.assertFalse(result)
        
        """ Test unknown host """
        result = smc.actions.search.element_href_use_wildcard(None)
        self.assertFalse(result)
    
    #@unittest.skip("good")  
    def test_element_href_use_filter(self):
        """ Test object filter, any element will do but use 'host' """
        href = smc.actions.search.element_href_use_filter('test-common-api-user', 'host')
        self.util_check_for_href(href)
        
        """ Test invalid user, valid filter """
        href = smc.actions.search.element_href_use_filter('1234test-common-api-user', 'host')
        self.assertIsNone(href)
        
        """ Test invalid filter """
        href = smc.actions.search.element_href_use_filter('1234test-common-api-user', 'host2')
        self.assertIsNone(href)
        
        """ Test unknown host """
        href = smc.actions.search.element_href_use_filter(None, None)
        self.assertIsNone(href)
    
    def test_element_as_json_with_filter(self):
        result = smc.actions.search.element_as_json_with_filter('test-common-api-user', 'host')
        self.assertEqual(result.get('name'), 'test-common-api-user')

    #@unittest.skip("good")        
    def test_element_href_by_batch(self):
        """ Test element batch, should return dict with elements """
        
        keys = ['test-common-api-user','test']
        elements = smc.actions.search.element_href_by_batch(keys)
        for e in elements:
            for k, _ in e.items():
                self.assertIn(k, keys)

        
        """ Enter non-iterable object, should catch TypeError and return None """
        elements = smc.actions.search.element_href_by_batch(None)
        self.assertIsNone(elements)
    
    def test_element_href_by_batch_with_filter(self):
        elements = smc.actions.search.element_href_by_batch(['test-common-api-user'], 'host')
        for x in elements:
            if x.get('test-common-api-user'):
                self.assertRegexpMatches(x.get('test-common-api-user'), r'^http')
                                                             
    #@unittest.skip("good")
    def test_element_by_href_as_json(self):
        """ Already have ref, get json """
        href = smc.actions.search.element_href('test-common-api-user')
        element = smc.actions.search.element_by_href_as_json(href)
        self.assertEqual(element.get('name'), 'test-common-api-user')
        
        """ Bad href """
        self.assertRaises(SMCConnectionError, lambda: smc.actions.search.element_by_href_as_json('http://wegwegwegw'))
    
    #@unittest.skip("good")    
    def test_element_by_href_as_smcresult(self):
        """ Return SMCResult object """
        href = smc.actions.search.element_href('test-common-api-user')
        element = smc.actions.search.element_by_href_as_smcresult(href)
        self.assertIsInstance(element, SMCResult)
        self.verify_attr_success(element)
        self.assertEqual(element.json.get('name'), 'test-common-api-user') #check name field in json, should match
    
    def test_element_as_smcresult_use_filter(self):
        """
        Valid filter
        """
        result = smc.actions.search.element_as_smcresult_use_filter('test-common-api-user', 'host')
        self.assertIsNotNone(result.json)
        
        #Invalid filter
        result = smc.actions.search.element_as_smcresult_use_filter('test-common-api-user', 'blah')
        if session.api_version >= 6.1:
            self.assertIsNotNone(result.msg)
        else:
            #Filter is ignored in <v6.1
            self.assertIsNotNone(result.json)
    
    #@unittest.skip("good")    
    def test_element_entry_point(self):
        """ Test retrieve of entry points; valid entry point """
        elements = smc.actions.search.all_elements_by_type('host')
        self.assertIsNotNone(elements)
        
        """ Test invalid entry point through search layer """
        self.assertIsNone(smc.actions.search.all_elements_by_type('host1'))
            
    def test_fetch_filter_context(self):
        """ Test filter context directly, in v6.1 400 is returned if the filter_context is
        not a valid type. Can be of valid entry point types or other documented filter_context
        types
        """
        result = fetch_href_by_name(name='123test123', filter_context='bogus')
        self.assertIsNotNone(result.msg)
    
    def test_element_name_by_href(self):
        result = smc.actions.search.element_info_as_json_with_filter('test-common-api-user', 'host')
        href = result[0].get('href')
        element = smc.actions.search.element_name_by_href(href)
        self.assertEqual(element, 'test-common-api-user')
        
    def test_element_name_and_type_by_href(self):
        result = smc.actions.search.element_info_as_json_with_filter('test-common-api-user', 'host')
        href = result[0].get('href')
        element = smc.actions.search.element_name_and_type_by_href(href)
        self.assertEqual(element[0], 'test-common-api-user')
        self.assertEqual(element[1], 'host')
        
    def test_element_attribute_by_href(self):
        result = smc.actions.search.element_info_as_json_with_filter('test-common-api-user', 'host')
        href = result[0].get('href')
        element = smc.actions.search.element_attribute_by_href(href, 'system')
        self.assertEqual(False, element)
    
    def test_get_entry_points(self):
        filters = session.cache.entry_points
        self.assertIsNotNone(filters)
        
    def test_entry_points_full(self):
        self.assertIsInstance(session.cache.get_entry_points(), list)
        
    def test_get_all_entry_points(self):
        self.assertIsNotNone(session.cache.get_all_entry_points())
    
    def test_search_unused(self):
        self.assertIsInstance(smc.actions.search.search_unused(), list)
    
    def test_search_duplicates(self):
        self.assertIsInstance(smc.actions.search.search_duplicate(), list)
    
    def test_entry_points(self):
        a = smc.actions.search.all_entry_points()
        self.assertIsInstance(a, list)
        self.assertIsNotNone(a)
    
    def test_element_references(self):
        for x in describe_log_server():
            # Dependent on Management Server
            result = smc.actions.search.element_references(x.href)
            self.assertTrue(len(result)>0)
        
                  
    def util_check_for_href(self, href):
        self.assertRegexpMatches(href,r'^http|https://')
            
    def verify_attr_success(self, element):
        self.assertIsNotNone(element.etag)
        self.assertIsNotNone(element.json)
        self.assertIsNone(element.msg)
        
    

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()