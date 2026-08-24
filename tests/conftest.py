"""Pin the working directory so the suite is invocation-independent.

Most of this suite reads project files through bare relative paths
(``pathlib.Path('dashboard/app.js')``, ``'docker-compose.yml'``,
``'README.md'``), which only resolve when pytest is invoked from the
repository root. But ``dashboard/pyproject.toml`` carries the pytest
config and sets ``testpaths = ["../tests"]``, so running ``pytest`` from
``dashboard/`` — the natural place, next to the config — collects the
whole suite and then fails 39 of its tests on missing files.

Those failures are false alarms about paths, not real defects, and a
sampling contract that goes red for the wrong reason is worse than no
signal at all. Pinning the working directory once here makes every
existing relative path correct by construction, from any invocation
directory.

No test changes its own working directory, and every subprocess in the
suite passes an explicit ``cwd=``, so nothing here is contended.
"""

import os
import pathlib

import pytest

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]


@pytest.fixture(scope="session", autouse=True)
def _run_from_project_root():
    previous = os.getcwd()
    os.chdir(PROJECT_ROOT)
    try:
        yield PROJECT_ROOT
    finally:
        os.chdir(previous)
