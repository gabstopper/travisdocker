import unittest
import mock
from smc.tests.constants import url, api_key, verify
from smc import session
from smc.base.model import Element
from smc.base.collection import Search, ElementCollection, CollectionManager
from smc.elements.network import Host, Router
from smc.api.exceptions import UnsupportedEntryPoint, InvalidSearchFilter
from smc.elements.service import TCPService


class Test(unittest.TestCase):

    tmp = {}

    def setUp(self):
        session.login(url=url, api_key=api_key, timeout=45, verify=verify)

    def tearDown(self):
        try:
            session.logout()
        except SystemExit:
            pass

    def test_search_collections(self):
        entry_points = Search.object_types()
        self.assertIsInstance(entry_points, list)
        self.assertTrue(len(entry_points) > 0)

        # Object type with defined class
        results = list(Search('host').objects.all())
        self.assertIsInstance(results, list)
        for result in results:
            self.assertIsInstance(result, Host)

        # Object type without defined class
        results = list(Search('ids_alert').objects.all())
        self.assertIsInstance(results, list)
        for result in results:
            self.assertIsInstance(result, Element)

        with self.assertRaises(UnsupportedEntryPoint):
            Search('foo').objects.all()

        self.assertIsInstance(Search('host').objects, CollectionManager)

        # Access collection through element directly
        results = list(TCPService.objects.all())  # @UndefinedVariable
        self.assertIsInstance(results, list)
        for result in results:
            self.assertIsInstance(result, TCPService)

        filtered = list(TCPService.objects.filter(
            'HTTP'))  # @UndefinedVariable
        self.assertIsInstance(filtered, list)
        for result in filtered:
            self.assertIsInstance(result, TCPService)

        # No results
        result = list(Search('host').objects.filter('blahblah'))
        self.assertFalse(result)

        # Test limit
        result = list(TCPService.objects.all().limit(5))  # @UndefinedVariable
        self.assertTrue(len(result) == 5)

        # Get iterator and test collection
        iterator = TCPService.objects.iterator()  # @UndefinedVariable
        results = list(iterator.all())
        self.assertTrue(results)
        self.assertTrue(len(results) == iterator.count())

        results = list(iterator.all().limit(5))
        self.assertTrue(len(result) == 5)
        
        self.assertIsNotNone(iterator.first())
        self.assertIsNotNone(iterator.last())
        
        self.assertIsNotNone(iterator.first())
        self.assertIsNotNone(iterator.last())
        self.assertTrue(iterator.count() > 0)

        results = iterator.filter('HTTP')
        self.assertIsInstance(results, ElementCollection)
        self.assertTrue(list(results))

        #limit in manager
        result = Host.objects.limit(3)  # @UndefinedVariable
        self.assertTrue(len(list(result)) == 3)

        # Filter based on multiple entry points at once
        for x in list(Search('router,host').objects.all()):
            self.assertTrue(isinstance(x, (Host, Router)))

        iterator = Host.objects
        self.assertIsInstance(iterator, CollectionManager)
        
        Router.create('R1', address='10.10.10.1')
        Router.create('R2', address='110.10.10.1')
        router = Router.objects.iterator()
        results = list(router.filter('10.10.10.1'))
        self.assertTrue(len(results) == 2)
        query1 = router.filter(address='10.10.10.1')
        self.assertTrue(query1.count() == 2) # Not filtered until iterating
        results = list(query1)
        self.assertTrue(len(results) == 1)
        self.assertEqual(query1.first().name, 'R1')
        
        h1 = Host.create(name='host1', address='1.1.1.1', comment='host1comment')
        h2 = Host.create(name='host2', address='1.1.1.1')
        results = list(Host.objects.filter(address='1.1.1.1', comment='host1comment'))
        self.assertTrue(len(results) == 1)
        self.assertEqual(results[0].name, 'host1')
        
        results = list(Host.objects.filter(address='1.1.1.1', comment='foo'))
        self.assertFalse(results)
        
        h1.delete()
        h2.delete()
            
        # Test batch function
        it = TCPService.objects.batch(4)
        for _ in range(1, 5):
            self.assertTrue(len(next(it)) == 4)
        
        # Test batch running out
        it = Host.objects.batch(20)
        for x in it:
            self.assertTrue(len(x) <= 20)
            
        # Test cloning when using filter_key
        it = Router.objects.iterator()
        query1 = it.filter(address='10.10.10.1').limit(1)
        element = query1.first()
        self.assertEqual(element.name, 'R1')
        
        result = Router.objects.first()
        self.assertIsNotNone(result)
        
        for router in ['R1', 'R2']:
            Router(router).delete()
        
    def test_fail_iterator_query_returns_empty_list(self):
        with mock.patch('smc.base.collection.Search._validate', return_value='foo') as validate_function:
            assert validate_function() == 'foo'
            result = list(Search('foo').objects.all())
            self.assertTrue(len(result) == 0)
    
    def test_collection_params(self):
        it = Router.objects.iterator()
        query1 = it.filter('10.10.10.1')
        self.assertFalse(query1._iexact)
        self.assertEqual(query1._params.get('filter_context'), 'router')
        self.assertEqual(query1._params.get('filter'), '10.10.10.1')
        self.assertFalse(query1._params.get('exact_match'))
        
        query2 = query1.filter(address='10.10.10.1')
        self.assertEqual(query2._iexact, {'address': '10.10.10.1'})
        self.assertEqual(query2._params.get('filter_context'), 'router')
        self.assertEqual(query2._params.get('filter'), '10.10.10.1')
        self.assertFalse(query2._params.get('exact_match'))
        
        query3 = query2.limit(2)
        self.assertEqual(query3._iexact, {'address': '10.10.10.1'})
        self.assertEqual(query3._params.get('filter_context'), 'router')
        self.assertEqual(query3._params.get('filter'), '10.10.10.1')
        self.assertFalse(query3._params.get('exact_match'))
        self.assertEqual(query3._params.get('limit'), 2)
        
if __name__ == "__main__":
    unittest.main()
