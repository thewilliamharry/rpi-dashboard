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

    def test_production_image_manifest_includes_the_advanced_document_bundle(self):
        """Keep every Flask-served Advanced asset in the production image."""
        dockerfile = Path('dashboard/Dockerfile').read_text(encoding='utf-8')
        copied_assets = set()
        for line in dockerfile.splitlines():
            if not line.startswith('COPY '):
                continue
            source_and_destination = line.split()
            copied_assets.update(
                item for item in source_and_destination[1:-1]
                if not item.startswith('--')
            )

        self.assertTrue(
            {'advanced.html', 'advanced.js', 'advanced.css'} <= copied_assets,
            'the production image must include the complete Advanced document bundle',
        )

    def test_the_deployment_pins_its_gunicorn_concurrency_model(self):
        """dashboard/Dockerfile's gunicorn --workers/--threads values are the
        deployment's concurrency model, load-bearing for every latency number
        06-workload-resilience-pi-acceptance produced (06-VERIFICATION.md
        flagged the unpinned CMD line as a warning-level anti-pattern for
        exactly this reason). The process/thread topology decides whether
        dashboard/app.py's _db_lock serializes ALL database access (one
        interpreter, --workers 1) or only SOME of it (several interpreters,
        each with its own independent _db_lock instance) -- so a change to
        either number is a change to the database-access boundary
        06-SECURITY.md's T-06-24 is closed on, and per PROH-OPS-04-05 it must
        go through the same decision and prerequisites D-DEBT-06-01 names,
        not through an unremarked edit to this file. If this test fails
        because you changed --workers or --threads: that is the point --
        read D-DEBT-06-01 in 06-DEBT.md and PROH-OPS-04-05 in
        06-13-PLAN.md's frontmatter before changing the constant to make
        this test pass.
        """
        dockerfile = Path('dashboard/Dockerfile').read_text(encoding='utf-8')
        cmd_lines = [line for line in dockerfile.splitlines() if line.startswith('CMD ')]
        self.assertEqual(
            len(cmd_lines), 1,
            f'expected exactly one CMD line in dashboard/Dockerfile, found {len(cmd_lines)}',
        )
        cmd_argv = ast.literal_eval(cmd_lines[0][len('CMD '):].strip())

        def _flag_value(flag):
            self.assertIn(
                flag, cmd_argv,
                f'{flag} missing from the gunicorn CMD -- the deployment concurrency model '
                f'pinned by D-DEBT-06-01 / PROH-OPS-04-05 has changed shape, not just value',
            )
            return cmd_argv[cmd_argv.index(flag) + 1]

        self.assertEqual(
            _flag_value('--workers'), '1',
            'dashboard/Dockerfile --workers changed. Raising gunicorn worker count grants a '
            'second OS process unserialized concurrent write access to the same SQLite file '
            'with no line of _db_lock changing (PROH-OPS-04-05) -- this requires the decision '
            'and prerequisites D-DEBT-06-01 names (06-DEBT.md), not an unremarked edit here.',
        )
        self.assertEqual(
            _flag_value('--threads'), '8',
            'dashboard/Dockerfile --threads changed. The thread count is part of the same '
            'pinned concurrency model D-DEBT-06-01 (06-DEBT.md) and PROH-OPS-04-05 protect -- '
            'every latency figure this phase measured was gathered at this value.',
        )
        self.assertEqual(
            cmd_argv[-1], 'app:app',
            'dashboard/Dockerfile\'s gunicorn CMD must still target app:app',
        )

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

        self.assertIn(
            'INSERT INTO thumbnails(port, data, mime, captured_ts, source, expires_ts)',
            repository_source,
        )
        self.assertIn('ThumbnailResultRepository', preview_source)
        self.assertIn('thumbnail_repository', preview_source)
        self.assertNotIn(
            'INSERT INTO thumbnails(port, data, mime, captured_ts, source, expires_ts)',
            preview_source,
        )
        self.assertNotIn(
            'INSERT INTO thumbnails(port, data, mime, captured_ts, source, expires_ts)',
            app_source,
        )
        self.assertNotIn('_legacy_store_thumbnail_result', app_source)


# ---------------------------------------------------------------------------
# Class-exhaustive connection-ownership gate (G-03.1-2 gap closure, round 3).
#
# The round-2 gate (test_no_web_handler_binds_a_connection_outside_a_context_manager
# above) walks ast.Assign only, matches the callee name ``get_db`` only, and scans
# ``dashboard/app.py`` only.  Its own docstring records that it "deliberately does
# not flag every connection binding."  That carve-out is the mechanism that let
# ``dashboard/app.py:2231`` -- an ast.With over the callee ``connect_db`` -- leak a
# shared maintenance lease across a browser preview capture, invisible to the
# round-2 gate.
#
# Everything below derives its seam set, its module scope, and its cross-module
# factory resolution from the ``dashboard/`` tree itself, rather than listing any
# of them by name, so the next new connection site cannot slip past the same way.
# ---------------------------------------------------------------------------

DB_MODULE_PATH = Path('dashboard/beacon/db.py')


def _dashboard_python_files():
    """Every real source file under dashboard/, excluding vendored/build dirs."""
    root = Path('dashboard')
    files = []
    for path in root.rglob('*.py'):
        if any(part.startswith('.') or part == '__pycache__' for part in path.parts):
            continue
        files.append(path)
    return sorted(files)


def _walk_excluding_nested_functions(node):
    """Yield descendants of ``node`` without crossing into a nested def's body.

    A binding inside a nested function must be attributed to that nested
    function, not to its enclosing one -- the outer walk in
    ``_unguarded_connection_bindings`` visits every FunctionDef/AsyncFunctionDef
    node independently, so crossing this boundary here would double-count and
    misattribute findings.
    """
    for child in ast.iter_child_nodes(node):
        yield child
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            continue
        yield from _walk_excluding_nested_functions(child)


def _is_sqlite_connect_attribute_call(call_node):
    func = call_node.func
    return (
        isinstance(func, ast.Attribute)
        and func.attr == 'connect'
        and isinstance(func.value, ast.Name)
        and func.value.id == 'sqlite3'
    )


def _callee_text(call_node):
    func = call_node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        return f'{func.value.id}.{func.attr}'
    if isinstance(func, ast.Attribute):
        return func.attr
    return ast.dump(func)


def _closes_name_in_finally(func_node, var_name):
    """True if ``func_node`` closes ``var_name`` in a ``finally`` suite of its own."""
    for node in _walk_excluding_nested_functions(func_node):
        if not isinstance(node, ast.Try):
            continue
        for stmt in node.finalbody:
            for sub in ast.walk(stmt):
                if (
                    isinstance(sub, ast.Call)
                    and isinstance(sub.func, ast.Attribute)
                    and sub.func.attr == 'close'
                    and isinstance(sub.func.value, ast.Name)
                    and sub.func.value.id == var_name
                ):
                    return True
    return False


def _is_contextmanager_decorated(node):
    for dec in node.decorator_list:
        name = None
        if isinstance(dec, ast.Name):
            name = dec.id
        elif isinstance(dec, ast.Attribute):
            name = dec.attr
        if name == 'contextmanager':
            return True
    return False


def _local_opening_assignments(node, known_opening_names):
    """Names bound, anywhere in ``node``, from a bare ``sqlite3.connect`` call or
    from a call to a locally-known OPENING function (by simple ``ast.Name`` callee)."""
    assigned = set()
    for stmt in _walk_excluding_nested_functions(node):
        if not (isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name)):
            continue
        value = stmt.value
        if not isinstance(value, ast.Call):
            continue
        if _is_sqlite_connect_attribute_call(value):
            assigned.add(stmt.targets[0].id)
        elif isinstance(value.func, ast.Name) and known_opening_names.get(value.func.id) == 'OPENING':
            assigned.add(stmt.targets[0].id)
    return assigned


def _classify_plain_seam_function(node, known):
    """OPENING when the function returns a bound connection it does not close itself."""
    assigned_opening_vars = _local_opening_assignments(node, known)
    if not assigned_opening_vars:
        return None
    for stmt in _walk_excluding_nested_functions(node):
        if isinstance(stmt, ast.Return) and isinstance(stmt.value, ast.Name) and stmt.value.id in assigned_opening_vars:
            if not _closes_name_in_finally(node, stmt.value.id):
                return 'OPENING'
    return None


def _classify_contextmanager_seam(node, known):
    """CLOSING when a @contextmanager both owns a close and yields the connection,
    directly or by delegating to an already-CLOSING contextmanager."""
    assigned_opening_vars = _local_opening_assignments(node, known)
    for var_name in assigned_opening_vars:
        yields_var = any(
            isinstance(n, ast.Yield) and isinstance(n.value, ast.Name) and n.value.id == var_name
            for n in _walk_excluding_nested_functions(node)
        )
        if yields_var and _closes_name_in_finally(node, var_name):
            return 'CLOSING'

    for stmt in _walk_excluding_nested_functions(node):
        if not isinstance(stmt, (ast.With, ast.AsyncWith)):
            continue
        for item in stmt.items:
            call = item.context_expr
            if not (isinstance(call, ast.Call) and isinstance(call.func, ast.Name)):
                continue
            if known.get(call.func.id) != 'CLOSING':
                continue
            bound_name = item.optional_vars.id if isinstance(item.optional_vars, ast.Name) else None
            if not bound_name:
                continue
            yields_bound = any(
                isinstance(n, ast.Yield) and isinstance(n.value, ast.Name) and n.value.id == bound_name
                for body_stmt in stmt.body
                for n in ast.walk(body_stmt)
            )
            if yields_bound:
                return 'CLOSING'
    return None


def _classify_seam_function(node, known):
    if _is_contextmanager_decorated(node):
        return _classify_contextmanager_seam(node, known)
    return _classify_plain_seam_function(node, known)


def _derived_database_seams():
    """Classify every module-level function in db.py as OPENING or CLOSING.

    OPENING: returns a connection whose close it does not itself own
    (``connect_db``). CLOSING: closes what it opens in its own ``finally``, or
    delegates to an already-CLOSING function (``database_access``,
    ``read_transaction``, ``write_transaction``). A lease-holding context
    manager that binds no connection at all -- ``exclusive_database_maintenance``
    -- is recognised by being classified as neither, deliberately.
    """
    tree = ast.parse(DB_MODULE_PATH.read_text(encoding='utf-8'))
    functions = {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}
    classification = {}
    remaining = dict(functions)
    changed = True
    while remaining and changed:
        changed = False
        for name in list(remaining):
            result = _classify_seam_function(remaining[name], classification)
            if result is not None:
                classification[name] = result
                del remaining[name]
                changed = True
    return classification


EXPECTED_DATABASE_SEAMS = {
    'connect_db': 'OPENING',
    'database_access': 'CLOSING',
    'read_transaction': 'CLOSING',
    'write_transaction': 'CLOSING',
}


def _resolve_absolute_module(dotted_name):
    candidate = Path(dotted_name.replace('.', '/') + '.py')
    for root in (Path('.'), Path('dashboard'), Path('dashboard/beacon')):
        resolved = root / candidate
        if resolved.is_file():
            return resolved
    return None


def _module_local_import_map(tree, module_path):
    """Map every locally-imported name in this module to (target_module, defined_name).

    ``defined_name`` is None for a whole-module import (``import x`` / a bare
    ``from .. import x`` submodule import), since those are resolved through
    attribute access rather than through a bound function name.
    """
    package_dir = module_path.parent
    mapping = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.level:
                base = package_dir
                for _ in range(node.level - 1):
                    base = base.parent
                if node.module:
                    target_module = base / Path(node.module.replace('.', '/') + '.py')
                    for alias in node.names:
                        local_name = alias.asname or alias.name
                        mapping[local_name] = (target_module, alias.name)
                else:
                    for alias in node.names:
                        local_name = alias.asname or alias.name
                        target_module = base / Path(alias.name.replace('.', '/') + '.py')
                        mapping[local_name] = (target_module, None)
            elif node.module:
                target_module = _resolve_absolute_module(node.module)
                if target_module is not None:
                    for alias in node.names:
                        local_name = alias.asname or alias.name
                        mapping[local_name] = (target_module, alias.name)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                target_module = _resolve_absolute_module(alias.name)
                if target_module is not None:
                    local_name = alias.asname or alias.name.split('.')[0]
                    mapping[local_name] = (target_module, None)
    return mapping


def _call_target(call_node):
    func = call_node.func
    if isinstance(func, ast.Name):
        return func.id, None
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        return func.value.id, func.attr
    return None, None


def _resolves_to_opening_call(call_node, import_map, is_known_opening):
    """True if ``call_node`` is a bare ``sqlite3.connect`` call, or resolves --
    through this module's own imports, including ``as`` aliases -- to a
    function already known to be OPENING (a db.py seam or a package factory)."""
    if _is_sqlite_connect_attribute_call(call_node):
        return True
    base_name, attr_name = _call_target(call_node)
    if base_name is None:
        return False
    if attr_name is None:
        if base_name in import_map:
            target_module, target_func = import_map[base_name]
            if target_func is None:
                return False
            return is_known_opening(target_module, target_func)
        return None  # resolved by the caller against same-module definitions
    if base_name in import_map:
        target_module, target_func = import_map[base_name]
        if target_func is not None:
            return False
        return is_known_opening(target_module, attr_name)
    return False


def _resolves_to_opening_call_in_module(call_node, module_path, import_map, is_known_opening, factories):
    """Same as ``_resolves_to_opening_call`` (clauses 1-3: bare sqlite3.connect,
    a db.py-derived import, a cross-module imported factory), plus clause 4:
    a bare Name callee resolving to a factory DEFINED in ``module_path`` itself.

    Clause 4 is kept as its own direct ``factories`` lookup here -- deliberately
    NOT folded into ``is_known_opening`` -- so it stays independently deletable
    from clause 3's cross-module import resolution inside
    ``_resolves_to_opening_call``. Collapsing them into one shared lookup would
    let one deletion silently take out both clauses at once, which is exactly
    the kind of narrowing this gate exists to make impossible to hide.
    """
    result = _resolves_to_opening_call(call_node, import_map, is_known_opening)
    if result is not None:
        return result
    base_name, attr_name = _call_target(call_node)
    if base_name is None or attr_name is not None:
        return False
    return f'{module_path.as_posix()}::{base_name}' in factories


def _function_returns_opening(node, module_path, import_map, is_known_opening, factories):
    """True if ``node`` returns -- directly, or via a same-function bound name --
    a call that resolves to an opening seam. This is the FACTORY predicate:
    ownership transfers to the caller through a ``return``."""
    assigned = set()
    for stmt in _walk_excluding_nested_functions(node):
        if not (isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name)):
            continue
        value = stmt.value
        if isinstance(value, ast.Call) and _resolves_to_opening_call_in_module(
            value, module_path, import_map, is_known_opening, factories,
        ):
            assigned.add(stmt.targets[0].id)
    for stmt in _walk_excluding_nested_functions(node):
        if not isinstance(stmt, ast.Return) or stmt.value is None:
            continue
        value = stmt.value
        if isinstance(value, ast.Call) and _resolves_to_opening_call_in_module(
            value, module_path, import_map, is_known_opening, factories,
        ):
            return True
        if isinstance(value, ast.Name) and value.id in assigned:
            return True
    return False


def _function_binds_or_returns_opening(node, module_path, import_map, is_known_opening, factories):
    """Broader than ``_function_returns_opening``: also true when the function
    merely BINDS a connection from an opening seam without returning it (the
    authority-path shape of ``_worker_write_transaction``, which owns its own
    close). Used by the RECORDED allowlist's rot predicate."""
    for stmt in _walk_excluding_nested_functions(node):
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
            value = stmt.value
            if isinstance(value, ast.Call) and _resolves_to_opening_call_in_module(
                value, module_path, import_map, is_known_opening, factories,
            ):
                return True
        if isinstance(stmt, ast.Return) and isinstance(stmt.value, ast.Call):
            if _resolves_to_opening_call_in_module(stmt.value, module_path, import_map, is_known_opening, factories):
                return True
    return False


def _make_opening_lookup(db_seams, factories):
    def is_known_opening(module_path, func_name):
        if module_path == DB_MODULE_PATH and db_seams.get(func_name) == 'OPENING':
            return True
        return f'{module_path.as_posix()}::{func_name}' in factories
    return is_known_opening


def _package_connection_factories(module_trees=None):
    """Package-wide, fixed-point factory derivation: every module-level function
    anywhere under dashboard/ that returns -- directly or through another
    collected factory -- a call to an opening seam. Keyed ``module::function``.

    This closes the cross-module hole a db.py-only derivation would leave: a
    factory imported from a sibling module under a new or aliased local name is
    a new call NAME inside a covered module -- the exact shape that defeated the
    round-2 gate.
    """
    if module_trees is None:
        module_trees = {path: ast.parse(path.read_text(encoding='utf-8')) for path in _dashboard_python_files()}
    db_seams = _derived_database_seams()
    factories = {
        f'{DB_MODULE_PATH.as_posix()}::{name}': True
        for name, classification in db_seams.items()
        if classification == 'OPENING'
    }
    is_known_opening = _make_opening_lookup(db_seams, factories)
    import_maps = {path: _module_local_import_map(tree, path) for path, tree in module_trees.items()}

    changed = True
    while changed:
        changed = False
        for module_path, tree in module_trees.items():
            import_map = import_maps[module_path]
            for node in tree.body:
                if not isinstance(node, ast.FunctionDef):
                    continue
                key = f'{module_path.as_posix()}::{node.name}'
                if key in factories:
                    continue
                if _function_returns_opening(node, module_path, import_map, is_known_opening, factories):
                    factories[key] = True
                    changed = True
    return factories


def _module_opening_seams(module_path, tree, db_seams=None, factories=None):
    """Local names that, IN THIS MODULE, hand back a connection the caller must
    close: the union of (1) a bare ``sqlite3.connect`` attribute call anywhere in
    the module, (2) every OPENING db.py name it imports, (3) every package
    factory it imports -- including under an ``as`` alias, and (4) every
    factory it defines itself."""
    if db_seams is None:
        db_seams = _derived_database_seams()
    if factories is None:
        factories = _package_connection_factories()
    import_map = _module_local_import_map(tree, module_path)
    seams = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _is_sqlite_connect_attribute_call(node):
            seams.add('sqlite3.connect')
            break

    for local_name, (target_module, target_func) in import_map.items():
        if target_func is None:
            continue
        if target_module == DB_MODULE_PATH and db_seams.get(target_func) == 'OPENING':
            seams.add(local_name)
            continue
        key = f'{target_module.as_posix()}::{target_func}'
        if key in factories:
            seams.add(local_name)

    module_prefix = f'{module_path.as_posix()}::'
    for key in factories:
        if key.startswith(module_prefix):
            seams.add(key[len(module_prefix):])

    return seams


def _derived_module_scope(module_trees=None):
    """Every module under dashboard/ whose ``_module_opening_seams`` is non-empty.
    Computed by glob, never listed -- a module that starts opening a connection
    enters this scope the moment it exists."""
    if module_trees is None:
        module_trees = {path: ast.parse(path.read_text(encoding='utf-8')) for path in _dashboard_python_files()}
    db_seams = _derived_database_seams()
    factories = _package_connection_factories(module_trees=module_trees)
    scope = set()
    for module_path, tree in module_trees.items():
        if _module_opening_seams(module_path, tree, db_seams=db_seams, factories=factories):
            scope.add(module_path)
    return scope


def _unguarded_connection_bindings(module_path, tree, db_seams=None, factories=None):
    """One finding per unguarded connection binding in ``tree``: an ``ast.Assign``,
    ``ast.With``, or ``ast.AsyncWith`` whose value/context_expr is a call
    resolving to an opening seam, that is neither a call to a CLOSING seam (never
    even a candidate -- see below) nor closed in a ``finally`` in the same
    enclosing function.

    A call to a CLOSING seam, to ``contextlib.closing``, or to
    ``exclusive_database_maintenance`` never resolves as "opening" in the first
    place, so it is silently accepted without special-casing: none of those
    names are ever classified OPENING or collected as a factory.
    """
    if db_seams is None:
        db_seams = _derived_database_seams()
    if factories is None:
        factories = _package_connection_factories()
    import_map = _module_local_import_map(tree, module_path)
    is_known_opening = _make_opening_lookup(db_seams, factories)

    findings = []
    for func_node in ast.walk(tree):
        if not isinstance(func_node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for node in _walk_excluding_nested_functions(func_node):
            candidates = []
            if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                candidates.append((node.targets[0].id, node.value, node.lineno))
            elif isinstance(node, (ast.With, ast.AsyncWith)):
                for item in node.items:
                    name = item.optional_vars.id if isinstance(item.optional_vars, ast.Name) else None
                    candidates.append((name, item.context_expr, node.lineno))
            for name, value, lineno in candidates:
                if not isinstance(value, ast.Call):
                    continue
                if not _resolves_to_opening_call_in_module(value, module_path, import_map, is_known_opening, factories):
                    continue
                if name and _closes_name_in_finally(func_node, name):
                    continue
                findings.append({
                    'module': module_path.as_posix(),
                    'function': func_node.name,
                    'line': lineno,
                    'callee': _callee_text(value),
                })
    return findings


def _unguarded_bindings_in_scope():
    """Run the detector over the entire derived module scope of the real tree."""
    module_trees = {path: ast.parse(path.read_text(encoding='utf-8')) for path in _dashboard_python_files()}
    db_seams = _derived_database_seams()
    factories = _package_connection_factories(module_trees=module_trees)
    scope = _derived_module_scope(module_trees=module_trees)
    findings = []
    for module_path in sorted(scope):
        findings.extend(
            _unguarded_connection_bindings(module_path, module_trees[module_path], db_seams=db_seams, factories=factories),
        )
    return findings


def _drop_suppressed(findings):
    suppressed_pairs = {(entry['module'], entry['function']) for entry in SUPPRESSING_CONNECTION_SITES}
    return [finding for finding in findings if (finding['module'], finding['function']) not in suppressed_pairs]


def _findings_for_sources(module_sources, target_module_path):
    """Run the detector against one or more synthetic in-memory sources, keyed by
    a (never-written-to-disk) module path used purely for import resolution."""
    trees = {path: ast.parse(text) for path, text in module_sources.items()}
    db_seams = _derived_database_seams()
    factories = _package_connection_factories(module_trees=trees)
    return _unguarded_connection_bindings(
        target_module_path, trees[target_module_path], db_seams=db_seams, factories=factories,
    )


# Two allowlist kinds with distinct, both-enforced staleness predicates. One
# predicate cannot work here: two of the four RECORDED sites are `return`
# factories the detector walk never reports at all, so a single "the finding
# still exists" predicate would be false for them from the day it is written.
SUPPRESSING_CONNECTION_SITES = (
    {
        'module': 'dashboard/beacon/db.py',
        'function': 'connect_db',
        'reason': (
            'the opening seam itself; binds at line 78 and returns, transferring '
            'ownership to its caller, whose binding this gate checks'
        ),
    },
)

RECORDED_CONNECTION_SITES = (
    {
        'module': 'dashboard/beacon/queues.py',
        'function': '_connect',
        'reason': (
            'a connection-returning factory; all seventeen callers close in a '
            'finally, which this gate verifies at each caller'
        ),
    },
    {
        'module': 'dashboard/beacon/inventory.py',
        'function': '_readonly_connection',
        'reason': (
            'a connection-returning factory; its sole caller collect_inventory '
            'closes in a finally, which this gate verifies there'
        ),
    },
    {
        'module': 'dashboard/app.py',
        'function': '_worker_write_transaction',
        'reason': (
            'binds through the opening seam on the worker authority path and owns '
            'its close in its own finally, so the general rule already accepts it; '
            'recorded so it is visible rather than invisible'
        ),
    },
)


# Synthetic fixture sources for the shape self-tests. Parsed from string
# literals only -- no file is ever written to disk for these.
_LEAK_ATTRIBUTE_WITH_SOURCE = '''
import sqlite3


def do_work(path):
    with sqlite3.connect(path) as conn:
        conn.execute('SELECT 1')
'''

_LEAK_NAME_ASSIGN_SOURCE = '''
from dashboard.beacon.db import connect_db


def do_work(path):
    conn = connect_db(path)
    conn.execute('SELECT 1')
'''

_LEAK_ASYNC_WITH_SOURCE = '''
from dashboard.beacon.db import connect_db


async def do_work(path):
    async with connect_db(path) as conn:
        conn.execute('SELECT 1')
'''

_LEAK_SIBLING_FACTORY_SOURCE = '''
import sqlite3


def factory_fn(path):
    return sqlite3.connect(path)
'''

_LEAK_ALIAS_IMPORTER_SOURCE = '''
from ._fixture_sibling_factory import factory_fn as make_connection


def do_work(path):
    conn = make_connection(path)
    conn.execute('SELECT 1')
'''

_LEAK_MODULE_LOCAL_FACTORY_SOURCE = '''
import sqlite3


def _open_local(path):
    return sqlite3.connect(path)


def consumer(path):
    conn = _open_local(path)
    conn.execute('SELECT 1')
'''

_GUARD_CLOSING_SEAM_SOURCE = '''
from dashboard.beacon.db import database_access


def do_work(path):
    with database_access(path) as conn:
        conn.execute('SELECT 1')
'''

_GUARD_NAME_FINALLY_SOURCE = '''
from dashboard.beacon.db import connect_db


def do_work(path):
    conn = connect_db(path)
    try:
        conn.execute('SELECT 1')
    finally:
        conn.close()
'''

_GUARD_ATTRIBUTE_FINALLY_SOURCE = '''
import sqlite3


def do_work(path):
    conn = sqlite3.connect(path)
    try:
        conn.execute('SELECT 1')
    finally:
        conn.close()
'''


class ConnectionOwnershipGateTests(unittest.TestCase):
    """The class-exhaustive connection-ownership gate: package-wide derived seam
    resolution, derived module coverage, two reasoned allowlist kinds with
    distinct rot predicates, and self-tests observing the detector firing."""

    def test_the_derived_seam_set_matches_the_database_module(self):
        derived = _derived_database_seams()
        self.assertEqual(
            derived, EXPECTED_DATABASE_SEAMS,
            f'db.py seam classification drifted: derived={derived} expected={EXPECTED_DATABASE_SEAMS}',
        )

    def test_the_package_wide_factory_set_contains_every_known_connection_factory(self):
        factories = _package_connection_factories()
        required = {
            'dashboard/beacon/queues.py::_connect',
            'dashboard/app.py::get_db',
            'dashboard/beacon/inventory.py::_readonly_connection',
            'dashboard/beacon/db.py::connect_db',
        }
        self.assertTrue(required <= set(factories), sorted(factories))
        self.assertFalse(
            any(key.startswith('dashboard/beacon/outbound.py::') for key in factories),
            sorted(factories),
        )

    def test_the_gate_covers_every_module_that_opens_a_connection(self):
        scope = _derived_module_scope()
        required = {
            Path('dashboard/app.py'),
            Path('dashboard/beacon/queues.py'),
            Path('dashboard/beacon/migrations.py'),
            Path('dashboard/beacon/db.py'),
            Path('dashboard/beacon/recovery.py'),
            Path('dashboard/beacon/inventory.py'),
        }
        self.assertTrue(required <= scope, sorted(p.as_posix() for p in scope))
        self.assertNotIn(Path('dashboard/beacon/outbound.py'), scope, sorted(p.as_posix() for p in scope))

        # Computed-scope assertion: a module created and removed under dashboard/
        # enters and leaves the scope, proving the scope is globbed rather than a
        # hardcoded list of today's in-scope modules.
        probe_path = Path('dashboard/beacon/_gsd_scope_probe_9c2f7a.py')
        self.assertFalse(probe_path.exists(), 'stray probe module from a prior failed run')
        try:
            probe_path.write_text(
                'import sqlite3\n\n\ndef _probe(path):\n    return sqlite3.connect(path)\n',
                encoding='utf-8',
            )
            recomputed = _derived_module_scope()
            self.assertIn(probe_path, recomputed, sorted(p.as_posix() for p in recomputed))
        finally:
            probe_path.unlink(missing_ok=True)
        after_removal = _derived_module_scope()
        self.assertNotIn(probe_path, after_removal, sorted(p.as_posix() for p in after_removal))

    def test_the_connection_detector_flags_every_leaking_shape(self):
        single_module_fixtures = {
            'attribute_with': (_LEAK_ATTRIBUTE_WITH_SOURCE, "sqlite3.connect(path) as conn", 'With', 'Attribute', 'bare_sqlite3_connect'),
            'name_assign': (_LEAK_NAME_ASSIGN_SOURCE, 'conn = connect_db(path)', 'Assign', 'Name', 'db_py_import'),
            'async_with': (_LEAK_ASYNC_WITH_SOURCE, 'connect_db(path) as conn', 'AsyncWith', 'Name', 'db_py_import'),
            'module_local_factory': (
                _LEAK_MODULE_LOCAL_FACTORY_SOURCE, 'conn = _open_local(path)', 'Assign', 'Name', 'module_local_factory',
            ),
        }
        covered_nodes = set()
        covered_callees = set()
        covered_clauses = set()

        for label, (source, marker, node_kind, callee_kind, clause) in single_module_fixtures.items():
            with self.subTest(shape=label):
                module_path = Path(f'dashboard/beacon/_fixture_{label}.py')
                findings = _findings_for_sources({module_path: source}, module_path)
                self.assertEqual(len(findings), 1, findings)
                expected_line = next(
                    i for i, line in enumerate(source.splitlines(), start=1) if marker in line
                )
                self.assertEqual(findings[0]['line'], expected_line, findings)
                covered_nodes.add(node_kind)
                covered_callees.add(callee_kind)
                covered_clauses.add(clause)

        with self.subTest(shape='aliased_cross_module_factory'):
            sibling_path = Path('dashboard/beacon/_fixture_sibling_factory.py')
            importer_path = Path('dashboard/beacon/_fixture_alias_importer.py')
            findings = _findings_for_sources(
                {sibling_path: _LEAK_SIBLING_FACTORY_SOURCE, importer_path: _LEAK_ALIAS_IMPORTER_SOURCE},
                importer_path,
            )
            self.assertEqual(len(findings), 1, findings)
            expected_line = next(
                i for i, line in enumerate(_LEAK_ALIAS_IMPORTER_SOURCE.splitlines(), start=1)
                if 'conn = make_connection(path)' in line
            )
            self.assertEqual(findings[0]['line'], expected_line, findings)
            covered_nodes.add('Assign')
            covered_callees.add('Name')
            covered_clauses.add('cross_module_factory')

        self.assertEqual(covered_nodes, {'Assign', 'With', 'AsyncWith'})
        self.assertEqual(covered_callees, {'Name', 'Attribute'})
        self.assertEqual(
            covered_clauses,
            {'bare_sqlite3_connect', 'db_py_import', 'cross_module_factory', 'module_local_factory'},
        )

    def test_the_connection_detector_accepts_every_guarded_shape(self):
        guarded_fixtures = {
            'closing_seam': _GUARD_CLOSING_SEAM_SOURCE,
            'name_finally': _GUARD_NAME_FINALLY_SOURCE,
            'attribute_finally': _GUARD_ATTRIBUTE_FINALLY_SOURCE,
        }
        for label, source in guarded_fixtures.items():
            with self.subTest(shape=label):
                module_path = Path(f'dashboard/beacon/_fixture_guard_{label}.py')
                findings = _findings_for_sources({module_path: source}, module_path)
                self.assertEqual(findings, [], findings)

    def test_the_suppressing_allowlist_has_no_stale_entry(self):
        for entry in SUPPRESSING_CONNECTION_SITES:
            with self.subTest(module=entry['module'], function=entry['function']):
                self.assertTrue(entry['reason'].strip())
                module_path = Path(entry['module'])
                tree = ast.parse(module_path.read_text(encoding='utf-8'))
                raw_findings = _unguarded_connection_bindings(module_path, tree)
                matching = [f for f in raw_findings if f['function'] == entry['function']]
                self.assertTrue(
                    matching,
                    f"stale SUPPRESSING entry: {entry['module']}/{entry['function']} "
                    'no longer produces a finding to suppress',
                )

    def test_the_recorded_allowlist_has_no_stale_entry(self):
        db_seams = _derived_database_seams()
        factories = _package_connection_factories()
        is_known_opening = _make_opening_lookup(db_seams, factories)
        for entry in RECORDED_CONNECTION_SITES:
            with self.subTest(module=entry['module'], function=entry['function']):
                self.assertTrue(entry['reason'].strip())
                module_path = Path(entry['module'])
                tree = ast.parse(module_path.read_text(encoding='utf-8'))
                function_node = next(
                    (n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == entry['function']),
                    None,
                )
                self.assertIsNotNone(
                    function_node,
                    f"stale RECORDED entry: {entry['function']} no longer defined in {entry['module']}",
                )
                import_map = _module_local_import_map(tree, module_path)
                self.assertTrue(
                    _function_binds_or_returns_opening(function_node, module_path, import_map, is_known_opening, factories),
                    f"stale RECORDED entry: {entry['function']} no longer returns or binds an opening seam",
                )

    def test_every_module_that_opens_a_sqlite_connection_guarantees_its_close(self):
        """The standing class gate: successor to the retired shape-specific and
        enumeration tests. Runs the same, unmodified helpers that reported nine
        findings against the unfixed tree and asserts the remainder -- after
        dropping the one reasoned SUPPRESSING entry -- is empty."""
        findings = _unguarded_bindings_in_scope()
        remainder = _drop_suppressed(findings)
        self.assertEqual(
            remainder, [],
            'unguarded connection binding(s) found:\n' + '\n'.join(
                f"  {f['module']} :: {f['function']} :: line {f['line']} :: callee={f['callee']}"
                for f in remainder
            ),
        )

    def test_the_connection_gate_flags_the_defect_it_was_written_for(self):
        """Sub-class A real-site proof (NAME callee). Reverts app.py's fixed
        preview-request site to the exact defect shape this plan closed and
        confirms the detector still catches it, entirely in memory -- this is
        what keeps sub-class A permanently gated after the temporary
        enumeration test above is retired."""
        module_path = Path('dashboard/app.py')
        source = module_path.read_text(encoding='utf-8')
        marker = 'with database_access(authority.db_path) as conn:'
        self.assertIn(marker, source)
        reverted = source.replace(marker, 'with connect_db(authority.db_path) as conn:', 1)
        self.assertNotEqual(reverted, source)
        findings = _findings_for_sources({module_path: reverted}, module_path)
        matching = [f for f in findings if f['function'] == 'worker_process_preview_requests']
        self.assertTrue(matching, findings)

    def test_the_connection_gate_flags_the_plain_handle_shape_it_was_written_for(self):
        """Sub-class B real-site proof (ATTRIBUTE callee) -- the shape that is
        eight of this round's nine sites. Reverts recovery.py's
        _checkpoint_and_remove_sidecars site to the plain
        ``with sqlite3.connect(...) as conn:`` shape and confirms the detector
        still catches it, entirely in memory."""
        module_path = Path('dashboard/beacon/recovery.py')
        source = module_path.read_text(encoding='utf-8')
        marker = 'with closing(sqlite3.connect(database)) as conn:'
        self.assertIn(marker, source)
        reverted = source.replace(marker, 'with sqlite3.connect(database) as conn:', 1)
        self.assertNotEqual(reverted, source)
        findings = _findings_for_sources({module_path: reverted}, module_path)
        matching = [f for f in findings if f['function'] == '_checkpoint_and_remove_sidecars']
        self.assertTrue(matching, findings)


if __name__ == '__main__':
    unittest.main()
