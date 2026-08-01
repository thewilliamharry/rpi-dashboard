import ast
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


def _legacy_app_imports(tree, module_name):
    """Return every import form that makes a package module depend on app."""
    package = module_name.rsplit('.', 1)[0]
    findings = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for imported in node.names:
                if imported.name in {'app', 'dashboard.app'}:
                    findings.append(imported.name)
            continue
        if not isinstance(node, ast.ImportFrom):
            continue

        if node.level:
            components = package.split('.')[:1 - node.level or None]
            if node.module:
                components.extend(node.module.split('.'))
            imported_module = '.'.join(components)
        else:
            imported_module = node.module or ''
        imported_names = {item.name for item in node.names}
        if imported_module in {'app', 'dashboard.app'}:
            findings.append(imported_module)
        elif imported_module == 'dashboard' and 'app' in imported_names:
            findings.append('dashboard.app')
        elif not imported_module and node.level == 2 and 'app' in imported_names:
            findings.append('dashboard.app')
    return findings


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
            module_name = f"dashboard.beacon.{source_path.stem}"
            self.assertEqual(_legacy_app_imports(tree, module_name), [], source_path)

    def test_ast_rule_rejects_absolute_aliased_and_relative_legacy_app_imports(self):
        cases = (
            'import dashboard.app',
            'import dashboard.app as legacy_app',
            'from dashboard import app',
            'from dashboard import app as legacy_app',
            'from dashboard.app import collect_system_stats',
            'import app',
            'from app import collect_system_stats',
            'from .. import app',
            'from .. import app as legacy_app',
            'from ..app import collect_system_stats',
        )
        for source in cases:
            with self.subTest(source=source):
                self.assertTrue(
                    _legacy_app_imports(ast.parse(source), 'dashboard.beacon.worker_main'),
                    source,
                )

    def test_package_worker_import_isolated_from_legacy_application(self):
        project_root = Path(__file__).resolve().parents[1]
        result = subprocess.run(
            [
                sys.executable,
                '-c',
                'import sys; import dashboard.beacon.worker_main; '
                'print("dashboard.app" in sys.modules or "app" in sys.modules)',
            ],
            cwd=project_root,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), 'False')

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

    def test_sqlite_connection_entrypoints_use_the_managed_database_seam(self):
        app_source = Path('dashboard/app.py').read_text(encoding='utf-8')
        queue_source = Path('dashboard/beacon/queues.py').read_text(encoding='utf-8')
        db_source = Path('dashboard/beacon/db.py').read_text(encoding='utf-8')

        self.assertIn('connect_db', app_source)
        self.assertIn('connect_db', queue_source)
        self.assertNotIn('sqlite3.connect(', app_source)
        self.assertNotIn('sqlite3.connect(', queue_source)
        self.assertIn('exclusive_database_maintenance', db_source)

    def test_thumbnail_sql_stays_in_the_repository_boundary(self):
        repository_source = Path('dashboard/beacon/repositories.py').read_text(encoding='utf-8')
        preview_source = Path('dashboard/beacon/previews.py').read_text(encoding='utf-8')
        app_source = Path('dashboard/app.py').read_text(encoding='utf-8')

        self.assertIn('UPDATE services SET thumb_data=', repository_source)
        self.assertIn('ThumbnailResultRepository', preview_source)
        self.assertIn('thumbnail_repository', preview_source)
        self.assertNotIn('UPDATE services SET thumb_data=', preview_source)
        self.assertNotIn('UPDATE services SET thumb_data=', app_source)
        self.assertNotIn('_legacy_store_thumbnail_result', app_source)


if __name__ == '__main__':
    unittest.main()
