#!/usr/bin/python
# -*- coding: utf-8 -*- 

import unittest
from constants import url, api_key, verify
from smc import session
import smc.actions.search
from smc.elements.network import Host
from smc.elements.collection import describe_host, describe_single_fw
from smc.core.engines import Layer3Firewall
from smc.base.util import bytes_to_unicode
from smc.compat import PY3
from smc.api.exceptions import ElementNotFound, CreateElementFailed

class Test(unittest.TestCase):
    tmp = {}
    def setUp(self):
        session.login(url=url, api_key=api_key, verify=verify)
        
    def tearDown(self):
        try:
            session.logout()
        except SystemExit:
            pass
    
    def test_string_convertors_by_py_version(self):
        #Byte string to UNICODE; <str> for PY3
        #For Py2, it will be <str> to >unicode>
        if PY3:
            bstring = b'testbytestring'
            self.assertIsInstance(bstring, bytes)
            self.assertIsInstance(bytes_to_unicode(bstring), str)
        else: #PY2
            bstring = 'testbytestring'
            self.assertIsInstance(bstring, str)
            self.assertIsInstance(bytes_to_unicode(bstring), unicode)  # @UndefinedVariable
        
    def test_search_known(self):
        result = Host.create('Réunion30', '30.30.30.30')
        self.assertTrue(result.startswith('http'))
        
        result = smc.actions.search.element_as_json('Réunion30')
        self.assertEqual(u'Réunion30', result.get('name'), result)
        
        for host in describe_host(name=['Réunion30']):
            host.delete()
    
    def test_search_unknown(self):
        result = smc.actions.search.element_href('Réunion31')
        self.assertIsNone(result)
        
    def test_search_unknown_as_smcresult(self):
        result = smc.actions.search.element_as_smcresult('Réunion32')
        uni = result.msg.endswith('Réunion32')
        self.assertTrue(uni, 'unicode didnt match on unfound search')
        
    def test_create_host_with_unicode(self):
        result = Host.create('Réunion33', '30.30.30.30')
        self.assertTrue(result.startswith('http'))
        
        for host in describe_host(name=['Réunion33']):
            host.delete()
            
    def test_create_error_with_unicode(self):
        result = Host.create('Curaçao34', '22.22.22.22')
        self.assertTrue(result.startswith('http'))
        
        #fail because it already exists
        with self.assertRaises(CreateElementFailed):
            err = Host.create('Curaçao34', '22.22.22.22')
            import re
            myre = re.compile(r'.*Curaçao+')
            self.assertRegexpMatches(err, myre)
        
        Host('Curaçao34').delete()
        
    def test_change_host_name_in_unicode(self):
        result = Host.create('Curaçao35', '12.12.12.12')
        self.assertTrue(result.startswith('http'))
        
        for host in describe_host(name=['Curaçao35']):
            modified = host.modify_attribute(name='São Tomé Host35')
            self.assertIsNone(modified)
            
        for host in describe_host(name=['São Tomé Host35']):
            host.delete()
            
    def test_create_unicode_name_firewall(self):
        result = Layer3Firewall.create(name='ĂĂĂĂrdvark36', 
                                       mgmt_ip='1.1.1.1', 
                                       mgmt_network='1.1.1.0/24')
        fw = result.load() #reload
        self.assertEquals(fw.name, u'ĂĂĂĂrdvark36', 'unicode fw names do not match')
        for fw in describe_single_fw():
            if fw.name == u'ĂĂĂĂrdvark36': #Required b/c non-ascii. Otherwise use from futures import literals
                fw.delete()
                
    def test_load_invalid_SMCElement(self):
        element = Host('Curaçao221234563234')
        self.assertRaises(ElementNotFound, lambda: element.describe())
    
    def test_str_and_unicode_conversion(self):
        element = Host('绝对路径加载/相对路径加载都')
        self.assertTrue(element.name == u'绝对路径加载/相对路径加载都')
        
    def test_util_bytes_to_unicode(self):
        if PY3:
            result = bytes_to_unicode(b'teststring')
            self.assertIsInstance(result, str)
        else:
            result = bytes_to_unicode('teststring')
            self.assertIsInstance(result, unicode)  # @UndefinedVariable
    
    def test_util_unicode_to_bytes(self):
        if PY3:
            result = unicode_to_bytes('teststring')
            self.assertIsInstance(result, str)
        else:
            result = unicode_to_bytes(u'teststring')
            self.assertIsInstance(result, str)
        
if __name__ == "__main__":
    unittest.main()