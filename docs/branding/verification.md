# Check the visual identity

Use the [visual guide](README.md) when changing assets, templates, or screenshots.
Check the actual running service before publishing product images. Synthetic
fixtures help exercise long values and optional history without a live log store;
they are not product demonstration screenshots.

## Application checks

Start the disposable [quickstart](../quickstart.md), request a command, and open
the dashboard with its generated operator login. Keep credentials out of images,
logs, and shared browser profiles.

Check the review queue, inventory, sessions, audit, and evaluations in light and
dark system appearance at desktop and narrow widths. Include a 320 CSS-pixel
viewport and increased browser zoom or text size. Tab through navigation and
controls: the skip link must reach the main content, focus must remain visible,
and each form control must have a useful name. The active destination and
operator should remain readable. Check without font loading as well.

Approve a request and collect its result. Check refusal, an expired or already
answered request, invalid input, session approval, and revocation. For configured
file transfers, check the complete path, direction, and other review details
before deciding. Use only disposable targets. Verify status and operation effects,
not just the appearance of the resulting page.

The local fonts and their license notices are served from the authenticated
`/dashboard/assets/` surface and are embedded in the service. The container also
carries the font notices under `/usr/share/doc/mcp-ssh-rs/fonts/`.

## Optional-history and long-content fixtures

From the repository root, explicitly run the development fixture exporter:

```sh
cargo test -p ssh-server export_visual_review_fixtures --locked -- --ignored
python3 -m http.server 8765 --bind 127.0.0.1 --directory target/branding-fixtures
```

Open the generated HTML files from the local directory listing. These use the
same templates and existing fake audit readers as the regression suite. They
cover populated audit, evaluations, transcript, retained output, empty sessions,
a long command, and conflict feedback. Bundled assets let them render without
an external font service. Links and forms are examples; this file server cannot
perform application operations. Stop the server when finished.

Check that complete values wrap, especially command arguments, digests, output,
and evaluation rationale. Check visible filter labels, advisory labels, observed
outcomes, pagination, and unavailable-source wording against the actual service.
The exporter is skipped by the ordinary test suite because it writes review
artifacts; run it explicitly when reviewing visual changes.

## Public presentation

Inspect the README header and current screenshots on wide and narrow screens in
both appearances. Inspect the symbol at browser-tab size. Product screenshots
follow [capture guidance](../images/README.md); retain meaningful alternative text.
The social preview is a separate GitHub setting: upload the checked-in
[PNG](assets/social-preview.png) in repository settings and confirm the public
preview. A committed image alone does not update that setting.

Record any remaining issue and its disposition in the PR. Preserve failed or
unavailable states in evidence; do not replace them with invented successful data.
