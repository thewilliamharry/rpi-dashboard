"""End-to-end regressions for the one-shot migration command and the compose
startup ordering that guarantees it runs alone before any long-running
Beacon process starts (G-03.1-2)."""

import ast
import json
import os
import re
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from shutil import copy2

from dashboard.beacon.migrations import MIGRATIONS


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DASHBOARD_ROOT = PROJECT_ROOT / 'dashboard'
FIXTURE_DIR = PROJECT_ROOT / 'tests' / 'fixtures' / 'legacy'
CURRENT_V6_FIXTURE = 'current-v6.db'


class MigrateCommandTests(unittest.TestCase):
    """`python -m beacon.migrate` run as a genuine child process."""

    def _run_migrate_cli(self, db_path):
        env = dict(os.environ)
        env['DB_PATH'] = str(db_path)
        return subprocess.run(
            [sys.executable, '-m', 'beacon.migrate'],
            cwd=str(DASHBOARD_ROOT),
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_migrate_command_brings_a_real_legacy_database_fully_current(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / CURRENT_V6_FIXTURE
            copy2(FIXTURE_DIR / CURRENT_V6_FIXTURE, target)
            result = self._run_migrate_cli(target)
            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(payload['applied_versions'][-1], MIGRATIONS[-1].version)

    def test_migrate_command_is_a_no_op_on_repeat(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / CURRENT_V6_FIXTURE
            copy2(FIXTURE_DIR / CURRENT_V6_FIXTURE, target)
            first = self._run_migrate_cli(target)
            self.assertEqual(first.returncode, 0, first.stderr)
            second = self._run_migrate_cli(target)
            self.assertEqual(second.returncode, 0, second.stderr)
            payload = json.loads(second.stdout)
            self.assertEqual(payload['applied_versions'], [])

    def test_migrate_command_refuses_an_unsupported_schema_legibly(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / CURRENT_V6_FIXTURE
            copy2(FIXTURE_DIR / CURRENT_V6_FIXTURE, target)
            with sqlite3.connect(target) as conn:
                conn.execute('CREATE TABLE startup_ordering_probe (id INTEGER PRIMARY KEY)')
            result = self._run_migrate_cli(target)
            self.assertEqual(result.returncode, 1, result.stdout)
            self.assertIn('UnsupportedSchemaError', result.stderr)
            self.assertIn('python -m beacon.inventory', result.stderr)
            self.assertNotIn('lock timeout', result.stderr.lower())

    def test_migrate_module_has_no_exception_handling(self):
        """The traceback path is the contract -- confirmed by parsing, not grepping."""
        tree = ast.parse((DASHBOARD_ROOT / 'beacon' / 'migrate.py').read_text(encoding='utf-8'))
        has_try = any(isinstance(node, ast.Try) for node in ast.walk(tree))
        self.assertFalse(has_try)


class ComposeStartupOrderingTests(unittest.TestCase):
    """Structural regressions for the compose startup-order contract.

    Both helpers below extract structure rather than substring-searching the
    whole file: a service block is terminated on the *next* two-space header
    (not a hard-coded sibling name), and depends_on is walked by indentation
    rather than matched as a flat token, so a dependency declared under a
    different service cannot be mistaken for one declared under the block
    being examined.
    """

    def _compose_text(self):
        return (PROJECT_ROOT / 'docker-compose.yml').read_text(encoding='utf-8')

    def _service_block(self, compose_text, service_name):
        header = '\n  {}:\n'.format(service_name)
        self.assertIn(header, compose_text, 'service {!r} not found in compose file'.format(service_name))
        remainder = compose_text.split(header, 1)[1]
        end_match = re.search(r'\n  [A-Za-z0-9_-]+:\n|\nvolumes:', remainder)
        return remainder[:end_match.start()] if end_match else remainder

    def _dependency_map(self, block):
        """Return {service_name: condition} declared under this block's own depends_on."""
        if 'depends_on:' not in block:
            return {}
        depends_text = block.split('depends_on:', 1)[1]
        entries = {}
        current_name = None
        for line in depends_text.split('\n')[1:]:
            if not line.strip():
                continue
            indent = len(line) - len(line.lstrip(' '))
            if indent <= 4:
                break
            stripped = line.strip()
            if stripped.endswith(':') and indent == 6:
                current_name = stripped[:-1]
            elif stripped.startswith('condition:') and current_name is not None:
                entries[current_name] = stripped.split('condition:', 1)[1].strip()
        return entries

    def test_worker_depends_on_the_migration_service_completing(self):
        deps = self._dependency_map(self._service_block(self._compose_text(), 'worker'))
        self.assertEqual(deps.get('migrate'), 'service_completed_successfully')

    def test_web_depends_on_the_migration_service_completing(self):
        deps = self._dependency_map(self._service_block(self._compose_text(), 'web'))
        self.assertEqual(deps.get('migrate'), 'service_completed_successfully')

    def test_migration_service_runs_the_module_and_does_not_restart(self):
        block = self._service_block(self._compose_text(), 'migrate')
        self.assertIn('beacon.migrate', block)
        self.assertIn('restart: "no"', block)

    def test_recovery_service_is_behind_a_profile(self):
        block = self._service_block(self._compose_text(), 'recovery')
        self.assertIn('profiles:', block)

    def test_migration_service_depends_on_the_data_ownership_initializer(self):
        deps = self._dependency_map(self._service_block(self._compose_text(), 'migrate'))
        self.assertEqual(deps.get('data-init'), 'service_completed_successfully')

    def test_block_extractor_does_not_leak_a_dependency_from_another_service(self):
        """The recovery service declares no depends_on of its own; the migration
        service's dependency on data-init must not be attributed to it."""
        deps = self._dependency_map(self._service_block(self._compose_text(), 'recovery'))
        self.assertNotIn('migrate', deps)


if __name__ == '__main__':
    unittest.main()
