# Hugo Reverse Shell Generator Design

## Goal

Build an interactive reverse shell generator in the Hugo LAIR section at `content/lair/revshells/`, similar in workflow to `revshells.com`, while keeping it local to the site and styled for the existing theme.

## Scope

The page will provide a browser-side generator for authorized labs and assessments. It will include live payload rendering, listener rendering, payload filtering, encoding, copy/download controls, port incrementing, and localStorage persistence. It will not call external services or require a JavaScript build pipeline.

## Architecture

The Hugo content page remains the canonical route. A dedicated `layouts/lair/revshells.html` template renders the tool inside the existing `project-docs` shell. Page-specific assets are served from `static/css/revshells.css` and `static/js/revshells.js`, loaded only by the revshells template.

The JavaScript owns the payload catalog, state management, template rendering, encoding, copy/download behavior, and tests. Payload templates use placeholders such as `{ip}`, `{port}`, `{shell}`, `{name}`, and `{base64}`. The catalog is intentionally data-driven so new payloads can be added without changing UI logic.

## Interface

The workflow is platform-first and payload-driven. Target controls collect only connection values such as IP and port. Payload controls first choose Linux, Windows, or macOS, then choose a payload category, search query, and selected payload available for that platform. Payload-specific options, such as shell, file name, and session, appear only when the selected payload actually uses those variables. Output controls handle transformations such as encoding. Output panels show generated payload, listener, and raw command. Buttons copy each output, increment the port, reset settings, and download the selected payload.

## Testing

Generator functions are exposed through a small `window.RevShells` test API. A local Node test file validates placeholder rendering, URL encoding, double URL encoding, base64 encoding, payload filtering, and listener generation. Hugo build verification confirms templates and assets render.

## Risks

This is dual-use security content. The page will include concise authorization copy and will not hide intent. Browser clipboard support varies, so copy buttons will fall back to text selection when the Clipboard API is unavailable.
