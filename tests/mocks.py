import requests
import requests_mock
from smc import session as mysession
from smc.api.web import SMCAPIConnection
from constants import url
from smc.elements.helpers import location_helper, logical_intf_helper,\
    zone_helper
from smc.actions import search

def inject_mock_for_smc():
    """
    Attach the request_mock to the SMC Session. Return the SMC session
    in case it's needed
    """
    adapter = requests_mock.Adapter()
    session = requests.Session()
    session.mount('mock', adapter)
    mysession._session = session
    mysession._cache.api_entry = mock_entry_point()
    mysession._connection = SMCAPIConnection(mysession)
    return mysession
    
def mock_entry_point():
        """
        Entry points are used by create methods to either retrieve a resource,
        such as log server reference, locations, etc, or to POST data to the
        proper entry point. Populate session cache with needed links.
        """
        return [{'rel': 'location', 
                 'href': '{}/location'.format(url), 
                 'method': 'GET'},
                {'rel': 'logical_interface',
                 'href': '{}/logical_interface'.format(url),
                 'method': 'GET'},
                {'rel': 'interface_zone',
                 'href': '{}/interface_zone'.format(url),
                 'method': 'GET'},
                {'rel': 'log_server',
                 'href': '{}/log_server'.format(url),
                 'method': 'GET'},
                {'rel': 'elements', 
                 'href': '{}/elements'.format(url), 
                 'method': 'GET'},
                {'rel': 'single_fw', 
                 'href': '{}/single_fw'.format(url), 
                 'method': 'GET'},
                {'rel': 'single_layer2',
                 'href': '{}/single_layer2'.format(url),
                 'method': 'GET'},
                {'rel': 'single_ips',
                 'href': '{}/single_ips'.format(url),
                 'method': 'GET'},
                {'rel': 'master_engine',
                 'href': '{}/master_engine'.format(url),
                 'method': 'GET'},
                {'rel': 'fw_cluster',
                 'href': '{}/fw_cluster'.format(url),
                 'method': 'GET'},
                {'rel': 'virtual_fw',
                 'href': '{}/virtual_fw'.format(url),
                 'method': 'GET'},
                {'rel': 'ospfv2_profile',
                 'href': '{}/ospfv2_profile'.format(url),
                 'method': 'GET'}]

def register_request(m, uri, 
                     status_code=200,
                     json=None, 
                     method='GET',
                     headers={'content-type': 'application/json'}):
    """
    Wrapper for mocker calls
    """
    json = {} if json is None else json
    
    m.register_uri(method, '{}'.format(uri),
                   json=json,
                   status_code=status_code,
                   headers=headers)

def mock_location_helper(m, location):
    """
    Mocks the real smc.elements.helpers.location_helper
    :param str location: name
    """
    register_request(m, '/elements?filter_context=location',
                     json={'result': [{'href': '{}/location/1'.format(url),
                                       'name': location,
                                       'type':'location'}]})
    #m.get('/elements?filter_context=location',
    #      headers={'content-type': 'application/json'},
    #      json={'result': [{'href': '{}/location/1'.format(url),
    #                                   'name': location,
    #                                   'type':'location'}]})
    
    return location_helper(location)

def mock_zone_helper(m, zone):
    """
    Mocks the real smc.elements.helpers.zone_helper
    :param str zone: name
    """
    m.get('/elements?filter_context=interface_zone',
          headers={'content-type': 'application/json'},
          json={'result': [{'href': '{}/interface_zone/1'.format(url),
                                       'name': zone,
                                       'type':'interface_zone'}]})
    
    return zone_helper(zone)

def mock_logical_intf_helper(m, logical_if):
    """
    Mocks the real smc.elements.helpers.logical_intf_helper
    :param str logical_if: name
    """
    m.get('/elements?filter_context=logical_interface',
          headers={'content-type': 'application/json'},
          json={'result': [{'href': '{}/logical_interface/1'.format(url),
                                       'name': logical_if,
                                       'type':'logical_interface'}]})
    
    return logical_intf_helper(logical_if)

def mock_search_get_first_log_server(m):
    """
    If log_server_ref is ommitted from engine create constructor
    the smc.actions.get_first_log_server() method will be run within
    smc.core.engine.Engine.create to find the default log server href
    """
    m.get('/log_server', headers={'content-type': 'application/json'},
          json={'result':[{'href':'{}/log_server/1'.format(url),
                           'name':'LogServer 1.1.1.1',
                           'type':'log_server'}]})
    
    return search.get_first_log_server()

def mock_get_ospf_default_profile(m):
    m.get('/ospfv2_profile',
          json=[{'name': 'Default OSPFv2 Profile', 
                 'href': '{}/ospf'.format(url), 
                 'type': 'ospfv2_profile'}],
          headers={'content-type': 'application/json'})
    
    m.get('/ospf', json={'system': True, 'href': url},
          headers={'content-type': 'application/json'})
