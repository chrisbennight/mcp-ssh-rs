# Visual identity

The name is **mcp-ssh-rs**. Its identity is warm, precise, and approachable:
an open terminal frame, a command chevron, and a copper connection point.
It shares Waygate's restrained line work and warm surfaces, with its own mark.

This guide covers visual decisions. [Design](../design.md) remains the sole
normative product architecture and security document; consult it before changing
what an interface means or permits.

## Reference and authority

The maintainer selected the revised **01 / Warm & Precise** concept on
2026-09-21. [The approved board](reference/approved-concept.png) and
[its image-generation prompts](reference/prompts.json) preserve that decision.
The board was generated with OpenAI's built-in image generation tool. It is
inspiration, not a product screenshot or an exact font, color, or geometry specification.

Use this written guide and the editable production assets for new work. The
board's incidental slogans, approximate typography, and incorrectly labeled
two-color “one-color” sample are not requirements. Production monochrome marks
use one ink. If the application drifts from this guide, reconcile the discrepancy
explicitly; do not silently treat the current CSS as a new design decision.
Material changes to the selected identity need maintainer agreement.

## Color and appearance

| Color | Reference | Role |
| --- | --- | --- |
| Ivory | `#F7F5F0` | Main light surface; primary text on dark surfaces |
| Ink | `#23201B` | Primary text and mark; main dark surface |
| Copper | `#B66A45` | Connection point and restrained decorative accents |
| Forest | `#1E5F46` | Supporting illustration and light-theme positive controls |

Copper is an accent, not a default text color or warning meaning. Use darker
copper for small text on ivory and lighter copper on ink; verify contrast in
context. Use separate, labeled success, warning, error, and unavailable states.
A green brand accent must not imply that an operation succeeded.

Light mode uses ivory surroundings, white cards, ink text, and warm borders.
Dark mode uses ink surroundings, slightly raised warm charcoal cards, ivory
text, and lighter copper/forest accents. Follow the system color preference.
Keep hierarchy and information identical between appearances. Avoid gradients,
glows, large shadows, and ornamental textures.

## Typography and technical content

Use **Manrope** for interface copy, headings, and the wordmark; use **IBM Plex
Mono** for commands, paths, identifiers, and output. The original font files and
their SIL Open Font License notices are stored under
[static/fonts](../../crates/ssh-server/static/fonts). Exact upstream revisions
and SHA-256 checksums are in [sources.json](../../crates/ssh-server/static/fonts/sources.json).
These files are unmodified. Do not redistribute them without their notices.

Use local fonts with system sans-serif and monospace fallbacks. The application
must remain usable without a font download or any external font service.
Prefer ordinary sentence case, short labels, and modest heading weights.
Do not turn long identifiers into decorative small print. Preserve whitespace
and argument boundaries in technical content; wrap long values or provide a
clearly accessible scroll region rather than clipping them.

## Mark and iconography

The editable mark is [brand.svg](../../crates/ssh-server/static/brand.svg).
It adapts to the system appearance. Explicit light, dark, and monochrome
exports live in [assets](assets). Use the symbol alone for browser identity;
pair it with the exact name for headers. Leave at least a connection-circle
diameter of clear space. Keep proportions and stroke weights consistent.
Check the actual raster at small sizes rather than only enlarging the SVG.

[icons.svg](../../crates/ssh-server/static/icons.svg) defines hosts, commands,
files, review, sessions, and history on the same rounded outline grid. Use icons
beside meaningful text; hide decorative SVGs from assistive technology. If an
icon is the only control content, provide its accessible name. Do not use a
padlock, shield, or color as a substitute for describing an observed state.

## Layout and interaction

Use a restrained spacing rhythm, generous separation between tasks, rounded
cards, and thin borders. Group a request's purpose, technical details, context,
and actions so that the decision can be understood without hunting across the
page. Use clear primary, secondary, and destructive controls; never make a
broader action look like the safest default.

Every interactive element needs visible keyboard focus and a useful accessible
name. Include a skip link and identify the current navigation destination.
Check contrast, keyboard operation, touch targets, increased text size, and
320 CSS-pixel layouts. Long account names, commands, paths, and translated
browser controls must not hide information or force the entire page sideways.
Keep text labels for state, not just icons or color. Empty, unavailable, and
failed states need different explanations. Apply the same care to feedback
after decisions as to the main queue.

| Do | Avoid |
| --- | --- |
| Use the approved SVG and outlined wordmark | Trace screenshots or regenerate the logo for each page |
| Keep copper accents small and purposeful | Make every control copper or use low-contrast copper text |
| Preserve full technical values | Ellipsize the operation a person is deciding on |
| Label an unavailable source explicitly | Show an empty success-looking panel for missing evidence |
| Capture the real disposable demo | Present concept art as the running application |

## Assets and reproduction

Use the [visual verification workflow](verification.md) to check application
changes, populated history fixtures, and public presentation together.

Run `python docs/branding/export.py` with Python 3.10+ and FontTools 4.65.0
installed in an isolated development environment. The exporter reads the
checked-in mark and font, and writes outlined SVGs with no external font
dependency. FontTools is a development tool, not an application dependency.

The social-preview source is `assets/social-preview.svg`; render it at its
native 1280 × 640 size to `assets/social-preview.png` with no page margins.
Browser-tab raster exports use `symbol-light.svg` at 16 and 32 pixels. Inspect
light and dark symbol samples at actual size. Keep generated exports with their
source changes. The repository's Apache-2.0 license covers original artwork;
the font files retain their accompanying licenses.

## Surface inventory

| Surface | Source or destination |
| --- | --- |
| README header | `assets/header-light.svg`, `assets/header-dark.svg`; compact wordmarks on mobile |
| Documentation entry point | [Documentation guide](../README.md) |
| GitHub social preview | `assets/social-preview.png`, uploaded through repository settings |
| Application/browser mark and icons | [Server static assets](../../crates/ssh-server/static) |
| Review queue and standing agreements | [Approval template](../../crates/ssh-server/templates/approvals.html) |
| Inventory, sessions, transcripts, output, audit, evaluations | [Operations template](../../crates/ssh-server/templates/operations.html) |
| Product screenshots | [Capture guidance](../images/README.md) |

Historical releases retain their original artifacts. CLI protocol identifiers,
package names, and machine-readable interfaces are not typography surfaces.
An image checked into `assets` is not proof that GitHub's separate social-preview
setting has been updated; verify that setting and the public preview separately.
