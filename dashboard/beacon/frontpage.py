"""Pure server-side removal of the front page's advanced-diagnostics entry point.

07-02 Task 2: with ``ENABLE_ADVANCED_DIAGNOSTICS`` off, the front page must
never send a document that carries a link to a route the deployment has
closed -- criterion 2's "absent, not hidden" requirement. This module is the
one place that transform lives.

``without_advanced_entry_point`` is coupled to ``dashboard/index.html``'s
top-bar markup: it matches the entry-point anchor by its element id together
with its immediately-following separator element. This coupling is
deliberate. The alternatives considered by ``07-02-PLAN.md``'s objective --
a client-side fetch-then-remove, or a server-toggled wrapper element added to
``index.html`` itself -- were both rejected because they would either leave
the link in the served bytes (the first) or move the enabled path's bytes
away from the raw file (the second), which is exactly what criterion 4 and
07-01's captured golden forbid. Keeping the enabled ``send_file`` call in
``dashboard/app.py`` textually untouched, and doing the excision only on the
disabled branch, is what keeps criterion 4 a property of the code rather
than only of a test.

The coupling this creates -- a regular expression that depends on markup it
does not own -- is held safe by two things, not by hope: this function
raises rather than silently no-oping the moment the pattern's match count is
anything other than exactly one, and ``tests/test_optional_advanced_diagnostics.py``
pins a "markup invariant" test asserting the real ``dashboard/index.html``
yields exactly one match today. That test is what converts a future edit to
the anchor's markup into a failing test instead of a failing deployment.

Stdlib-only (``re``) and imports nothing from ``dashboard.app`` or any other
``beacon`` module, so it is a pure string-to-string function with no I/O --
``tests/test_module_boundaries.py``'s AST rule and the package's dependency
direction are both satisfied by construction.
"""

import re


class AdvancedEntryPointNotFound(ValueError):
    """Raised when a document does not contain exactly one advanced-diagnosis
    entry-point span.

    Never returning the input unchanged is the contract: a silent no-op
    would serve the link on a deployment that turned the feature off, which
    is the exact failure criterion 2 forbids. Zero matches (the markup moved
    or was removed) and more than one match (a duplicated anchor, where
    removing only one would be a silent half-failure) both raise.
    """


# The anchor's element id, together with its immediately-following
# separator `div` -- both removed together, or a stray divider is left at
# the left edge of the top bar's right-hand group (dashboard/index.html:24).
ADVANCED_ENTRY_POINT_ID = 'advanced-diagnosis-link'

_ENTRY_POINT_PATTERN = re.compile(
    r'<a\b[^>]*\bid="' + re.escape(ADVANCED_ENTRY_POINT_ID) + r'"[^>]*>.*?</a>'
    r'<div class="tb-sep"></div>'
)


def without_advanced_entry_point(document):
    """Return ``document`` with its advanced-diagnosis entry point excised.

    Requires exactly one match of the anchor-plus-separator span across the
    whole document; any other match count raises ``AdvancedEntryPointNotFound``
    carrying the observed match count.
    """
    matches = _ENTRY_POINT_PATTERN.findall(document)
    if len(matches) != 1:
        raise AdvancedEntryPointNotFound(
            f'expected exactly one advanced-diagnosis entry point span '
            f'(id={ADVANCED_ENTRY_POINT_ID!r}), found {len(matches)}'
        )
    return _ENTRY_POINT_PATTERN.sub('', document, count=1)
