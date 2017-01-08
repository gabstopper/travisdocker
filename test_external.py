'''
Created on Dec 1, 2016

@author: davidlepage
'''
from smc import session

if __name__ == "__main__":
    import logging
    logging.getLogger()
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s %(name)s.%(funcName)s: %(message)s')
    
    session.login(url='http://172.18.1.26:8082', api_key='123kKphtsbQKjjfHR7amodA0001', timeout=45)
    print("Logged in!")
    session.logout()
