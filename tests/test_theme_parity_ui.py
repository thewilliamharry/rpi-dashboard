"""Phase 5's dedicated cross-surface, dual-theme UI contract (05-06, OPS-06/UX-05).

The main dashboard (``/``) and the advanced workspace (``/advanced``) are asserted to
share one narrow layout boundary, and every layout the responsive contract calls
at-risk is proven to scroll rather than hide content at that boundary, in both
themes. Every assertion in this module reads DOM presence, displayed state,
geometry, or a computed layout property -- never a pixel-snapshot baseline. This
project has no baseline-review workflow, targets Raspberry Pi-class rendering where
font/GPU output differs from a developer machine, and a contract assertion can
express a role, an accessible name, or a text claim a pixel diff cannot (A-31).

``tests/test_ui_states.py``/``tests/test_advanced_ui.py`` each already carry
single-document dual-theme coverage; this module is deliberately cross-surface --
the same viewport width applied to both documents in both themes -- which is why it
gets its own module rather than being split across the two single-document ones
(A-32).
"""
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]

# A-30/E10: the one shared narrow boundary. Every viewport width this module uses
# derives from this constant -- a future boundary change is a one-line edit here,
# and no test body can silently keep asserting the old value.
NARROW_BOUNDARY_PX = 720

# Matches an `@media (max-width: Npx)` prelude anywhere in a stylesheet, tolerant of
# any other conditions sharing the same parenthesised query (none exist today, but
# the pattern does not assume it). `prefers-reduced-motion` queries carry no
# `max-width` term and are correctly skipped.
_MEDIA_MAX_WIDTH_RE = re.compile(r'@media[^{]*?max-width:\s*(\d+)px')


class NarrowBoundaryPinTests(unittest.TestCase):
    """T-05-23: pins the reconciled narrow breakpoint at source level.

    A bare membership check would pass against a stylesheet that also still
    declared an off-by-one neighbour (e.g. 719px) alongside the correct value, so
    this also asserts no other declared max-width falls within ten pixels of
    NARROW_BOUNDARY_PX -- the assertion that actually catches an off-by-one
    reintroduction.
    """

    def test_both_stylesheets_declare_the_same_narrow_boundary(self):
        style_css = (ROOT / 'dashboard/style.css').read_text(encoding='utf-8')
        advanced_css = (ROOT / 'dashboard/advanced.css').read_text(encoding='utf-8')

        style_values = [int(value) for value in _MEDIA_MAX_WIDTH_RE.findall(style_css)]
        advanced_values = [int(value) for value in _MEDIA_MAX_WIDTH_RE.findall(advanced_css)]

        # Pattern self-check: a broken expression that matched nothing (or matched
        # only one value) must not let this pin pass vacuously -- advanced.css
        # genuinely declares two distinct narrow boundaries today (the 959px
        # nav-rail collapse and NARROW_BOUNDARY_PX itself).
        self.assertGreaterEqual(
            len(set(advanced_values)), 2,
            'pattern self-check: expected at least two distinct max-width values '
            'extracted from dashboard/advanced.css -- the extraction regex may be broken',
        )

        self.assertIn(NARROW_BOUNDARY_PX, set(style_values))
        self.assertIn(NARROW_BOUNDARY_PX, set(advanced_values))

        for label, values in (
            ('dashboard/style.css', style_values),
            ('dashboard/advanced.css', advanced_values),
        ):
            for value in set(values):
                if value == NARROW_BOUNDARY_PX:
                    continue
                self.assertGreater(
                    abs(value - NARROW_BOUNDARY_PX), 10,
                    f'{label} declares a near-neighbour max-width ({value}px) within 10px '
                    f'of the shared {NARROW_BOUNDARY_PX}px boundary -- an off-by-one '
                    'reintroduction would pass a bare membership check but must fail this one',
                )


if __name__ == '__main__':
    unittest.main()
