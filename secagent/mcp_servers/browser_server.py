"""
Browser Control MCP Server

A FastMCP server that exposes Playwright-based Chrome browser control tools.
Run as a standalone process:

    python -m secagent.mcp_servers.browser_server

Or via the CLI helper:

    secagent browser-server
"""

from __future__ import annotations

import asyncio
import base64
import json
from typing import Optional

from fastmcp import FastMCP
from playwright.async_api import (
    Browser,
    BrowserContext,
    Page,
    Playwright,
    async_playwright,
)

mcp = FastMCP(
    name="secagent-browser",
    instructions=(
        "Chrome browser control tools for web security testing and automation. "
        "Always call browser_launch before any other tool. "
        "Call browser_close when finished."
    ),
)

# ---------------------------------------------------------------------------
# Global browser state (one shared context per server process)
# ---------------------------------------------------------------------------

_pw: Optional[Playwright] = None
_browser: Optional[Browser] = None
_context: Optional[BrowserContext] = None
_page: Optional[Page] = None
_dialogs: list[dict] = []  # captured dialog events (alert/confirm/prompt)
_DIALOG_OVERLAY_ID = "__secagent_dialog_overlay__"


async def _ensure_page() -> Page:
    global _pw, _browser, _context, _page
    if _page is None or _page.is_closed():
        raise RuntimeError("Browser is not launched. Call browser_launch first.")
    return _page


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


@mcp.tool()
async def browser_launch(
    headless: bool = False,
    proxy: str = "",
) -> str:
    """Launch a Chrome browser instance.

    Args:
        headless: Run Chrome in headless mode (no visible window). Default False.
        proxy: Optional HTTP proxy URL, e.g. 'http://127.0.0.1:8080'.

    Returns:
        Confirmation message with browser version.
    """
    global _pw, _browser, _context, _page

    if _browser and _browser.is_connected():
        return json.dumps({"status": "already_running", "message": "Browser already launched."})

    launch_opts: dict = {"headless": headless, "channel": "chrome"}
    if proxy:
        launch_opts["proxy"] = {"server": proxy}

    _pw = await async_playwright().start()
    _browser = await _pw.chromium.launch(**launch_opts)
    _context = await _browser.new_context(
        viewport={"width": 1280, "height": 900},
        user_agent=(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        ),
    )
    _page = await _context.new_page()

    # Auto-accept dialogs but record them so the LLM can check for XSS alerts
    async def _on_dialog(dialog) -> None:
        _dialogs.append({
            "type": dialog.type,
            "message": dialog.message,
            "default_value": dialog.default_value,
        })
        await dialog.accept()

    _page.on("dialog", _on_dialog)
    _dialogs.clear()

    version = _browser.version
    return json.dumps({"status": "launched", "version": version, "headless": headless})


@mcp.tool()
async def browser_navigate(url: str, wait_until: str = "domcontentloaded") -> str:
    """Navigate the browser to a URL.

    Args:
        url: Full URL to navigate to (e.g. 'https://example.com').
        wait_until: When to consider navigation complete.
            Options: 'load', 'domcontentloaded', 'networkidle', 'commit'.

    Returns:
        JSON with final URL, title, and HTTP status code.
    """
    page = await _ensure_page()
    response = await page.goto(url, wait_until=wait_until, timeout=30000)
    return json.dumps(
        {
            "url": page.url,
            "title": await page.title(),
            "status": response.status if response else None,
        }
    )


@mcp.tool()
async def browser_screenshot(
    full_page: bool = False,
    include_dialog_overlay: bool = True,
) -> str:
    """Take a screenshot of the current page.

    Args:
        full_page: Capture the full scrollable page. Default False (viewport only).
        include_dialog_overlay: If recent alert/confirm/prompt dialogs were captured,
            draw a temporary evidence overlay into the screenshot. This does not
            recreate the native browser chrome, but preserves the dialog message
            visually in the image. Default True.

    Returns:
        JSON with base64-encoded PNG and current URL.
    """
    page = await _ensure_page()
    dialogs = list(_dialogs)
    overlay_applied = False
    try:
        if include_dialog_overlay and dialogs:
            await page.evaluate(
                """(payload) => {
                    const overlayId = payload.overlayId;
                    const existing = document.getElementById(overlayId);
                    if (existing) existing.remove();

                    const root = document.createElement('div');
                    root.id = overlayId;
                    root.style.position = 'fixed';
                    root.style.top = '24px';
                    root.style.left = '50%';
                    root.style.transform = 'translateX(-50%)';
                    root.style.zIndex = '2147483647';
                    root.style.maxWidth = 'min(720px, calc(100vw - 48px))';
                    root.style.minWidth = '360px';
                    root.style.background = '#ffffff';
                    root.style.border = '2px solid #111827';
                    root.style.borderRadius = '14px';
                    root.style.boxShadow = '0 24px 60px rgba(15, 23, 42, 0.35)';
                    root.style.fontFamily = 'ui-sans-serif, -apple-system, BlinkMacSystemFont, sans-serif';
                    root.style.color = '#111827';
                    root.style.overflow = 'hidden';

                    const title = document.createElement('div');
                    title.style.padding = '12px 16px';
                    title.style.fontWeight = '700';
                    title.style.fontSize = '14px';
                    title.style.background = '#f3f4f6';
                    title.style.borderBottom = '1px solid #d1d5db';
                    title.textContent = 'secAgent Dialog Evidence';
                    root.appendChild(title);

                    payload.dialogs.forEach((dialog, index) => {
                        const block = document.createElement('div');
                        block.style.padding = '14px 16px';
                        if (index > 0) block.style.borderTop = '1px solid #e5e7eb';

                        const meta = document.createElement('div');
                        meta.style.fontSize = '12px';
                        meta.style.fontWeight = '600';
                        meta.style.color = '#4b5563';
                        meta.style.marginBottom = '8px';
                        meta.textContent = `${dialog.type || 'dialog'} dialog`;
                        block.appendChild(meta);

                        const body = document.createElement('pre');
                        body.style.margin = '0';
                        body.style.whiteSpace = 'pre-wrap';
                        body.style.wordBreak = 'break-word';
                        body.style.fontSize = '15px';
                        body.style.lineHeight = '1.45';
                        body.style.fontFamily = 'ui-monospace, SFMono-Regular, Menlo, monospace';
                        body.textContent = dialog.message || '(empty dialog message)';
                        block.appendChild(body);

                        root.appendChild(block);
                    });

                    document.documentElement.appendChild(root);
                }""",
                {"overlayId": _DIALOG_OVERLAY_ID, "dialogs": dialogs},
            )
            overlay_applied = True

        png = await page.screenshot(full_page=full_page, type="png")
    finally:
        if overlay_applied:
            try:
                await page.evaluate(
                    """(overlayId) => {
                        document.getElementById(overlayId)?.remove();
                    }""",
                    _DIALOG_OVERLAY_ID,
                )
            except Exception:
                pass

    return json.dumps(
        {
            "url": page.url,
            "title": await page.title(),
            "image_base64": base64.b64encode(png).decode(),
            "format": "png",
            "dialogs": dialogs,
            "dialog_overlay_applied": overlay_applied,
        }
    )


@mcp.tool()
async def browser_get_dialogs(clear: bool = True) -> str:
    """Return all JavaScript dialogs (alert/confirm/prompt) that fired since the last call.

    This is the primary way to detect successful XSS that uses alert() or confirm().
    Each dialog entry contains: type, message, default_value.

    Args:
        clear: Clear the captured list after returning. Default True.

    Returns:
        JSON list of dialog objects. Empty list means no dialogs fired.
    """
    result = list(_dialogs)
    if clear:
        _dialogs.clear()
    return json.dumps({"dialogs": result, "count": len(result)})


@mcp.tool()
async def browser_get_text(selector: str = "body") -> str:
    """Extract visible text content from the page or a specific element.

    Args:
        selector: CSS selector to target. Default 'body' for full page text.

    Returns:
        JSON with extracted text (truncated at 20 KB).
    """
    MAX = 20 * 1024
    page = await _ensure_page()
    try:
        text = await page.inner_text(selector, timeout=5000)
    except Exception as exc:
        return json.dumps({"error": str(exc)})
    truncated = len(text) > MAX
    return json.dumps(
        {
            "url": page.url,
            "selector": selector,
            "text": text[:MAX],
            "truncated": truncated,
        }
    )


@mcp.tool()
async def browser_get_html(selector: str = "html", outer: bool = True) -> str:
    """Get the HTML source of the page or a specific element.

    Args:
        selector: CSS selector. Default 'html' for full page.
        outer: If True return outer HTML (including tag itself). Default True.

    Returns:
        JSON with HTML content (truncated at 50 KB).
    """
    MAX = 50 * 1024
    page = await _ensure_page()
    try:
        fn = page.evaluate
        html = await fn(
            f"""(sel, outer) => {{
                const el = document.querySelector(sel);
                return el ? (outer ? el.outerHTML : el.innerHTML) : null;
            }}""",
            [selector, outer],
        )
    except Exception as exc:
        return json.dumps({"error": str(exc)})

    if html is None:
        return json.dumps({"error": f"No element matched selector: {selector}"})

    truncated = len(html) > MAX
    return json.dumps({"url": page.url, "html": html[:MAX], "truncated": truncated})


@mcp.tool()
async def browser_click(
    selector: str,
    button: str = "left",
    click_count: int = 1,
) -> str:
    """Click an element on the page.

    Args:
        selector: CSS selector or text locator (e.g. 'button#submit', 'text=Login').
        button: Mouse button: 'left', 'middle', or 'right'. Default 'left'.
        click_count: Number of clicks (2 for double-click). Default 1.

    Returns:
        JSON with status and current URL after click.
    """
    page = await _ensure_page()
    try:
        await page.click(selector, button=button, click_count=click_count, timeout=10000)
        await page.wait_for_load_state("domcontentloaded", timeout=10000)
    except Exception as exc:
        return json.dumps({"error": str(exc)})
    return json.dumps({"status": "clicked", "url": page.url, "title": await page.title()})


@mcp.tool()
async def browser_type(
    selector: str,
    text: str,
    clear_first: bool = True,
    press_enter: bool = False,
) -> str:
    """Type text into an input field.

    Args:
        selector: CSS selector of the input element.
        text: Text to type.
        clear_first: Clear the field before typing. Default True.
        press_enter: Press Enter key after typing. Default False.

    Returns:
        JSON with status.
    """
    page = await _ensure_page()
    try:
        if clear_first:
            await page.fill(selector, "", timeout=5000)
        await page.type(selector, text, timeout=5000)
        if press_enter:
            await page.press(selector, "Enter")
            await page.wait_for_load_state("domcontentloaded", timeout=10000)
    except Exception as exc:
        return json.dumps({"error": str(exc)})
    return json.dumps({"status": "typed", "url": page.url})


@mcp.tool()
async def browser_select(selector: str, value: str) -> str:
    """Select an option in a <select> dropdown.

    Args:
        selector: CSS selector of the <select> element.
        value: The option value or label to select.

    Returns:
        JSON with status and selected values.
    """
    page = await _ensure_page()
    try:
        selected = await page.select_option(selector, value, timeout=5000)
    except Exception as exc:
        return json.dumps({"error": str(exc)})
    return json.dumps({"status": "selected", "values": selected})


@mcp.tool()
async def browser_scroll(
    x: int = 0,
    y: int = 500,
    selector: str = "",
) -> str:
    """Scroll the page or a specific element.

    Args:
        x: Horizontal scroll delta in pixels. Default 0.
        y: Vertical scroll delta in pixels. Default 500 (scroll down).
        selector: If provided, scroll this element instead of the page.

    Returns:
        JSON with status.
    """
    page = await _ensure_page()
    try:
        if selector:
            await page.evaluate(
                "(args) => { document.querySelector(args[0]).scrollBy(args[1], args[2]); }",
                [selector, x, y],
            )
        else:
            await page.evaluate(f"window.scrollBy({x}, {y})")
    except Exception as exc:
        return json.dumps({"error": str(exc)})
    return json.dumps({"status": "scrolled", "dx": x, "dy": y})


@mcp.tool()
async def browser_execute_js(script: str) -> str:
    """Execute JavaScript in the current page context.

    Args:
        script: JavaScript expression or statement to execute.
            Return value is serialized to JSON.

    Returns:
        JSON with the script's return value (if any).

    **Security note: Only use on authorised targets.**
    """
    page = await _ensure_page()
    try:
        result = await page.evaluate(script)
    except Exception as exc:
        return json.dumps({"error": str(exc)})
    return json.dumps({"result": result})


@mcp.tool()
async def browser_find_elements(selector: str, attribute: str = "") -> str:
    """Find all elements matching a CSS selector and return their properties.

    Args:
        selector: CSS selector string.
        attribute: Optional attribute to read from each element (e.g. 'href', 'src').

    Returns:
        JSON list of matching elements with tag, text, and optional attribute.
    """
    page = await _ensure_page()
    try:
        elements = await page.query_selector_all(selector)
        results = []
        for el in elements[:100]:  # cap at 100
            tag = await el.evaluate("e => e.tagName.toLowerCase()")
            text = (await el.inner_text()).strip()[:200]
            entry: dict = {"tag": tag, "text": text}
            if attribute:
                entry["attribute"] = await el.get_attribute(attribute)
            results.append(entry)
    except Exception as exc:
        return json.dumps({"error": str(exc)})
    return json.dumps({"selector": selector, "count": len(results), "elements": results})


@mcp.tool()
async def browser_wait_for(
    selector: str = "",
    url_contains: str = "",
    timeout_ms: int = 10000,
) -> str:
    """Wait for an element to appear or URL to change.

    Args:
        selector: Wait for this CSS selector to appear. Takes priority.
        url_contains: Wait until the current URL contains this string.
        timeout_ms: Timeout in milliseconds. Default 10000.

    Returns:
        JSON with status.
    """
    page = await _ensure_page()
    try:
        if selector:
            await page.wait_for_selector(selector, timeout=timeout_ms)
        elif url_contains:
            await page.wait_for_url(f"**{url_contains}**", timeout=timeout_ms)
        else:
            await asyncio.sleep(timeout_ms / 1000)
    except Exception as exc:
        return json.dumps({"error": str(exc)})
    return json.dumps({"status": "ready", "url": page.url})


@mcp.tool()
async def browser_get_cookies() -> str:
    """Retrieve all cookies from the current browser context.

    Returns:
        JSON list of cookie objects (name, value, domain, path, etc.).
    """
    if _context is None:
        return json.dumps({"error": "Browser not launched."})
    cookies = await _context.cookies()
    return json.dumps({"cookies": cookies})


@mcp.tool()
async def browser_set_headers(headers: dict[str, str]) -> str:
    """Set extra HTTP headers to be sent with every request.

    Args:
        headers: Dictionary of header name → value pairs.
            Example: {'Authorization': 'Bearer token123'}

    Returns:
        JSON with status.
    """
    if _context is None:
        return json.dumps({"error": "Browser not launched."})
    await _context.set_extra_http_headers(headers)
    return json.dumps({"status": "headers_set", "headers": list(headers.keys())})


@mcp.tool()
async def browser_intercept_requests(url_pattern: str = "**") -> str:
    """Enable request interception and log matching network requests.

    Captured requests are stored in memory; call browser_get_requests to retrieve them.

    Args:
        url_pattern: Glob pattern to match request URLs. Default '**' (all).

    Returns:
        JSON with status.
    """
    page = await _ensure_page()
    _intercepted: list[dict] = []

    async def _handler(request: object) -> None:  # type: ignore[type-arg]
        _intercepted.append(
            {
                "url": request.url,  # type: ignore[attr-defined]
                "method": request.method,  # type: ignore[attr-defined]
                "headers": dict(request.headers),  # type: ignore[attr-defined]
            }
        )

    page.on("request", _handler)
    # Store reference so browser_get_requests can access it
    page._secagent_intercepted = _intercepted  # type: ignore[attr-defined]
    return json.dumps({"status": "interception_enabled", "pattern": url_pattern})


@mcp.tool()
async def browser_get_requests() -> str:
    """Retrieve all intercepted network requests (requires browser_intercept_requests first).

    Returns:
        JSON list of captured requests.
    """
    page = await _ensure_page()
    intercepted = getattr(page, "_secagent_intercepted", [])
    return json.dumps({"count": len(intercepted), "requests": intercepted})


@mcp.tool()
async def browser_new_tab(url: str = "") -> str:
    """Open a new browser tab (and optionally navigate to a URL).

    Args:
        url: URL to navigate the new tab to. Leave empty for blank tab.

    Returns:
        JSON with status.
    """
    global _page
    if _context is None:
        return json.dumps({"error": "Browser not launched."})
    _page = await _context.new_page()
    if url:
        await _page.goto(url, wait_until="domcontentloaded", timeout=30000)
    return json.dumps({"status": "new_tab", "url": _page.url})


@mcp.tool()
async def browser_get_interactive_elements() -> str:
    """Extract all interactive elements from the current page in a compact format.

    Returns buttons, links, inputs, textareas, selects, and other clickable/fillable
    elements with their CSS selectors, types, labels, and current values.
    This is much cheaper than browser_get_html for understanding page structure.

    Use this tool instead of browser_get_html when you need to figure out how to
    interact with a page (e.g. find the login form, find navigation links, etc.).

    Returns:
        JSON with categorised interactive elements and suggested CSS selectors.
    """
    page = await _ensure_page()
    try:
        elements = await page.evaluate("""() => {
            const result = { forms: [], links: [], buttons: [], inputs: [], selects: [], textareas: [], other_clickable: [] };

            // Helper: build a unique CSS selector for an element
            function getSelector(el) {
                if (el.id) return '#' + CSS.escape(el.id);
                if (el.name) {
                    const tag = el.tagName.toLowerCase();
                    const sel = tag + '[name="' + el.name.replace(/"/g, '\\\\"') + '"]';
                    if (document.querySelectorAll(sel).length === 1) return sel;
                }
                if (el.getAttribute('data-testid')) return '[data-testid="' + el.getAttribute('data-testid') + '"]';
                if (el.getAttribute('aria-label')) return '[aria-label="' + el.getAttribute('aria-label').replace(/"/g, '\\\\"') + '"]';
                // fallback: tag + nth-of-type
                const tag = el.tagName.toLowerCase();
                const parent = el.parentElement;
                if (!parent) return tag;
                const siblings = Array.from(parent.children).filter(c => c.tagName === el.tagName);
                if (siblings.length === 1) return tag;
                const idx = siblings.indexOf(el) + 1;
                return tag + ':nth-of-type(' + idx + ')';
            }

            // Helper: get label text for an input
            function getLabel(el) {
                // Check for associated <label>
                if (el.id) {
                    const label = document.querySelector('label[for="' + CSS.escape(el.id) + '"]');
                    if (label) return label.textContent.trim().substring(0, 80);
                }
                // Check parent label
                const parentLabel = el.closest('label');
                if (parentLabel) return parentLabel.textContent.trim().substring(0, 80);
                // Check aria-label
                if (el.getAttribute('aria-label')) return el.getAttribute('aria-label').substring(0, 80);
                // Check placeholder
                if (el.placeholder) return el.placeholder.substring(0, 80);
                return '';
            }

            // Forms
            document.querySelectorAll('form').forEach(form => {
                result.forms.push({
                    selector: getSelector(form),
                    action: form.action || '',
                    method: form.method || 'get',
                    id: form.id || '',
                    name: form.name || ''
                });
            });

            // Inputs
            document.querySelectorAll('input:not([type="hidden"])').forEach(el => {
                if (!el.offsetParent && el.type !== 'hidden') return; // skip invisible
                result.inputs.push({
                    selector: getSelector(el),
                    type: el.type || 'text',
                    name: el.name || '',
                    value: (el.type === 'password' ? '***' : (el.value || '').substring(0, 100)),
                    placeholder: (el.placeholder || '').substring(0, 80),
                    label: getLabel(el),
                    required: el.required,
                    disabled: el.disabled
                });
            });

            // Textareas
            document.querySelectorAll('textarea').forEach(el => {
                if (!el.offsetParent) return;
                result.textareas.push({
                    selector: getSelector(el),
                    name: el.name || '',
                    value: (el.value || '').substring(0, 100),
                    label: getLabel(el),
                    placeholder: (el.placeholder || '').substring(0, 80)
                });
            });

            // Selects
            document.querySelectorAll('select').forEach(el => {
                if (!el.offsetParent) return;
                const options = Array.from(el.options).slice(0, 10).map(o => ({
                    value: o.value,
                    text: o.textContent.trim().substring(0, 60),
                    selected: o.selected
                }));
                result.selects.push({
                    selector: getSelector(el),
                    name: el.name || '',
                    label: getLabel(el),
                    options: options,
                    total_options: el.options.length
                });
            });

            // Buttons (button tags + input[type=submit/button/reset])
            document.querySelectorAll('button, input[type="submit"], input[type="button"], input[type="reset"]').forEach(el => {
                if (!el.offsetParent) return;
                result.buttons.push({
                    selector: getSelector(el),
                    text: (el.textContent || el.value || '').trim().substring(0, 80),
                    type: el.type || '',
                    disabled: el.disabled
                });
            });

            // Links (only visible, with href)
            document.querySelectorAll('a[href]').forEach(el => {
                if (!el.offsetParent) return;
                const text = el.textContent.trim().substring(0, 80);
                if (!text && !el.querySelector('img')) return; // skip empty links
                result.links.push({
                    selector: getSelector(el),
                    href: el.href || '',
                    text: text || '[image link]',
                    target: el.target || ''
                });
            });
            // Cap links at 50
            result.links = result.links.slice(0, 50);

            // Other clickable: [role="button"], [onclick], etc.
            document.querySelectorAll('[role="button"], [onclick], [tabindex="0"]').forEach(el => {
                if (!el.offsetParent) return;
                if (el.tagName === 'BUTTON' || el.tagName === 'A' || el.tagName === 'INPUT') return;
                result.other_clickable.push({
                    selector: getSelector(el),
                    tag: el.tagName.toLowerCase(),
                    text: el.textContent.trim().substring(0, 80),
                    role: el.getAttribute('role') || ''
                });
            });
            result.other_clickable = result.other_clickable.slice(0, 30);

            return result;
        }""")
    except Exception as exc:
        return json.dumps({"error": str(exc)})

    # Add summary
    summary = (
        f"Forms: {len(elements.get('forms', []))}, "
        f"Inputs: {len(elements.get('inputs', []))}, "
        f"Buttons: {len(elements.get('buttons', []))}, "
        f"Links: {len(elements.get('links', []))}, "
        f"Selects: {len(elements.get('selects', []))}, "
        f"Textareas: {len(elements.get('textareas', []))}"
    )
    return json.dumps({
        "url": page.url,
        "title": await page.title(),
        "summary": summary,
        **elements
    })


@mcp.tool()
async def browser_close() -> str:
    """Close the browser and release all resources.

    Returns:
        JSON with status.
    """
    global _pw, _browser, _context, _page
    try:
        if _browser:
            await _browser.close()
        if _pw:
            await _pw.stop()
    finally:
        _browser = _context = _page = _pw = None
    return json.dumps({"status": "closed"})


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    mcp.run()
