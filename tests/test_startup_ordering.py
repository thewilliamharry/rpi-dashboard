"""End-to-end regressions for the one-shot migration command and the compose
startup ordering that guarantees it runs alone before any long-running
Beacon process starts (G-03.1-2)."""

import ast
import json
import os
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


if __name__ == '__main__':
    unittest.main()
