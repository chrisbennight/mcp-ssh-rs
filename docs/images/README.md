# Refresh the demonstration image

`approval.png` shows the service's actual review queue after the local tutorial
requests `touch /home/demo/tutorial-marker`, before the operator answers.
It uses only the generated demo host and account. Request and session
identifiers vary on each run.

To recreate it:

1. Follow [the quickstart](../quickstart.md) through **Request approval**.
2. Open the printed dashboard URL in a browser and sign in locally with the
   generated operator credentials. Do not capture the login prompt or password.
3. Set the browser viewport to 1280 × 860 CSS pixels and capture the review
   queue, including the command, context, and decision controls. Check that the
   page fits; use a full-page capture if the current layout needs more height.
4. Save the PNG as `approval.png` in this directory. For `approval-mobile.png`,
   set a 390-pixel viewport and capture the pending request's `article` element
   in full. The README selects that closer view on narrow screens. Keep the
   actual UI and sample text; do not draw extra controls or fabricate history.
   Repeat in dark system appearance for `approval-dark.png` and
   `approval-mobile-dark.png`. Clear incidental keyboard focus before capturing;
   verify focus separately during the interaction checks.
5. Review the image at README width and a narrow viewport. Keep the README's
   caption, descriptive alternative text, and full-size link aligned with it.
6. Approve once, collect the result, and stop the demo as the tutorial describes.

The current images were captured from the running tutorial with
Chromium, without changing the HTML or CSS. The local setup used Linux x86_64,
Docker 29.7.2, Compose 5.4.0, and Python 3.11.2. The request, approval,
successful collection, and teardown were checked on 22 September 2026.

Use the [visual verification workflow](../branding/verification.md) for the
other application views, keyboard checks, and enlarged text. Synthetic history
fixtures are review aids and must not replace the real demo screenshots.

The README's small JSON result is a labeled excerpt from successful collection,
not a second dashboard view. Optional durable history is not configured in the
demo and is not depicted.
