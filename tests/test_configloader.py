'''
Created on Nov 11, 2016

@author: davidlepage
'''
import unittest
import os
import tempfile
from constants import url, api_key, verify
from smc.compat import PY3
from smc import session
from smc.api.configloader import load_from_file
from smc.api.exceptions import ConfigLoadError, SMCConnectionError
from smc.api.web import SMCAPIConnection

class Test(unittest.TestCase):
    def setUp(self):
        session.login(url=url, api_key=api_key, timeout=120, verify=verify)
        
    def tearDown(self):
        try:
            session.logout()
        except SystemExit:
            pass
    
    def test_missing_cfg_during_login(self):
        self.assertRaises(ConfigLoadError, lambda: session.login(alt_filepath='blahblah'))
    
    def test_login_failed(self):
        self.assertRaises(SMCConnectionError, lambda: session.login(url=url, api_key='somebogus', timeout=5))
    
    def test_login_bad_api_version(self):
        self.assertRaises(SMCConnectionError, lambda: session.login(url=url, api_key='nothing', api_version='6.3'))
              
    def test_missing_config(self):
        # Missing file
        self.assertRaises(ConfigLoadError, lambda: load_from_file(alt_filepath='mock-smcrc'))
    
    #@unittest.skip("good")
    def test_missing_section(self):
        fd, temp_path = tempfile.mkstemp(suffix='.mock')
        os.write(fd, b"\
[somethingbesidessmc]\n\
")
        os.close(fd)
        self.assertRaises(ConfigLoadError, lambda: load_from_file(alt_filepath=temp_path))
        os.remove(temp_path)
    
    def test_run_from_home_dir(self):
        # Test reading from users home dir. Try to read an existing file first in case
        # there is a valid one. Don't want to overwrite one that might be used. Otherwise
        # write a new one, then delete it after. Not concerned with the contents, just that
        # it can be read and triggers read from users home dir
        path = '~/.smcrc'
        ex_path = os.path.expandvars(path)
        full_path = os.path.expanduser(ex_path)
        had_to_create = False
        if not os.path.isfile(full_path):
            with open(full_path, 'w') as f:
                f.write("\
[smc]\n\
smc_address=172.18.1.150\n\
smc_apikey=EiGpKD4QxlLJ25dbBEp20001\n\
")
            had_to_create = True
            #print("Created file in home dir: %s" % full_path)
        
        # Load it from the users home dir now
        cfg = load_from_file()
        self.assertIsNotNone(cfg)
        
        if os.path.isfile(full_path) and had_to_create:
            print("Delete file that was manufactured")
            os.remove(full_path)
        
        
    def test_mock_bogus_entries(self):
        fd, temp_path = tempfile.mkstemp(suffix='.mock')
        os.write(fd, b"\
[smc]\n\
smc_address=172.18.1.150\n\
smc_apikey=EiGpKD4QxlLJ25dbBEp20001\n\
somesetting=bogus\n\
timeout=60\n\
ssl_on\n\
")
        os.close(fd)
        data = load_from_file(alt_filepath=temp_path)
        self.assertIsNone(data.get('somesetting')) #Drops unknown settings
        self.assertEqual('http://172.18.1.150:8082', data.get('url'))
        self.assertTrue(data.get('verify'))
        self.assertEqual(60, data.get('timeout'))
        self.assertIsNone(data.get('ssl_on')) #Drops unknown flags or settings
        os.remove(temp_path)
              
    def test_mock_missing_smc_api_key(self):
        fd, temp_path = tempfile.mkstemp(suffix='.mock')
        os.write(fd, b"\
[smc]\n\
smc_address=172.18.1.150\n\
")
        #Missing smc api key
        os.close(fd)
        self.assertRaises(ConfigLoadError, lambda: load_from_file(alt_filepath=temp_path))
        os.remove(temp_path)
        
    def test_mock_missing_smc_address(self):
        fd, temp_path = tempfile.mkstemp(suffix='.mock')
        os.write(fd, b"\
[smc]\n\
smc_apikey=EiGpKD4QxlLJ25dbBEp20001\n\
")
        #Missing smc address
        os.close(fd)
        self.assertRaises(ConfigLoadError, lambda: load_from_file(alt_filepath=temp_path))
        os.remove(temp_path)
        
    def test_mock_good_config(self):
        fd, temp_path = tempfile.mkstemp(suffix='.mock')
        os.write(fd, b"\
[smc]\n\
smc_address=172.18.1.150\n\
smc_apikey=EiGpKD4QxlLJ25dbBEp20001\n\
smc_ssl=True\n\
verify_ssl=False\n\
")
        os.close(fd)
        load_from_file(alt_filepath=temp_path)
        os.remove(temp_path)
    
    def test_bad_api_version(self):
        fd, temp_path = tempfile.mkstemp(suffix='.mock')
        os.write(fd, b"\
[smc]\n\
smc_address=172.18.1.150\n\
smc_apikey=EiGpKD4QxlLJ25dbBEp20001\n\
api_version=6a\n\
")
        os.close(fd)
        cfg = load_from_file(alt_filepath=temp_path)
        self.assertIsNone(cfg.get('api_version'))
        os.remove(temp_path)
        
    def test_invalid_timeout_value(self):
        # Timeout is not a valid integer, will catch ValueError and set to None
        fd, temp_path = tempfile.mkstemp(suffix='.mock')
        os.write(fd, b"\
[smc]\n\
smc_address=172.18.1.150\n\
smc_apikey=EiGpKD4QxlLJ25dbBEp20001\n\
smc_ssl=True\n\
verify_ssl=True\n\
timeout=2a\n\
")
        os.close(fd)
        data = load_from_file(alt_filepath=temp_path)
        self.assertIsNone(data.get('timeout')) #Catch value error and sets to None
        # When ssl is enabled and verify SSL is true but certificate file is not
        # given, verify should be reset to False
        self.assertTrue(data.get('verify') == False)
        os.remove(temp_path)
             
    def test_good_config_loaded_from_disk(self):
        fd, temp_path = tempfile.mkstemp(suffix='.mock')
        urlstr = url.split('//')[1].split(':')[0]
        cfg = \
"\
[smc]\n\
smc_address=%s\n\
smc_apikey=%s\n\
smc_ssl=False\n\
verify_ssl=False\n"\
 % (urlstr, api_key)
        print(cfg)
        if PY3:
            os.write(fd, bytes(cfg, 'utf-8'))
        else:
            os.write(fd, cfg)
        session.login(alt_filepath=temp_path)
        self.assertIsInstance(session.connection, SMCAPIConnection)  
        
        
        