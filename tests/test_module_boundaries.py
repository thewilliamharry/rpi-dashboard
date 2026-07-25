import ast
import tempfile
import unittest
from pathlib import Path


class ModuleBoundaryTests(unittest.TestCase):
    def test_factory_isolation_and_dependency_direction(self):
        from dashboard.beacon.config import Settings
        from dashboard.beacon.web import create_app

        first = create_app(Settings(db_path='/tmp/first-beacon.db'))
        second = create_app(Settings(db_path='/tmp/second-beacon.db'))

        self.assertIsNot(first, second)
        self.assertEqual(first.extensions['beacon']['settings'].db_path, '/tmp/first-beacon.db')
        self.assertEqual(second.extensions['beacon']['settings'].db_path, '/tmp/second-beacon.db')
        self.assertEqual(len([rule for rule in first.url_map.iter_rules() if rule.rule == '/healthz']), 1)

        package = Path('dashboard/beacon')
        for source_path in package.glob('*.py'):
            tree = ast.parse(source_path.read_text(encoding='utf-8'))
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom):
                    self.assertNotEqual(node.module, 'dashboard.app', source_path)
                elif isinstance(node, ast.Import):
                    self.assertNotIn('dashboard.app', [name.name for name in node.names], source_path)

    def test_settings_are_immutable_and_container_copies_package(self):
        from dashboard.beacon.config import load_settings

        settings = load_settings({'DB_PATH': '/tmp/beacon.db', 'EXTRA_SCAN_PORTS': '8100, 9000'})
        self.assertEqual(settings.db_path, '/tmp/beacon.db')
        self.assertEqual(settings.extra_scan_ports, frozenset({8100, 9000}))
        with self.assertRaises(Exception):
            settings.db_path = '/tmp/other.db'

        dockerfile = Path('dashboard/Dockerfile').read_text(encoding='utf-8')
        self.assertIn('beacon/', dockerfile)
        self.assertIn('"app:app"', dockerfile)


if __name__ == '__main__':
    unittest.main()
