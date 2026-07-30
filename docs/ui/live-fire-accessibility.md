# Live Fire Accessibility

Implemented accessibility controls:

- semantic header, nav, main, sections, headings, tables and captions;
- skip link to operational content;
- visible keyboard focus on links, inputs, selects, textareas and buttons;
- Ctrl/Cmd+K command palette and Ctrl/Cmd+Enter flag submission;
- `aria-live` for submission/event results and `role=status/alert` for
  connection and error states;
- status text and symbols in addition to color;
- meter semantics for availability;
- descriptive round countdown and connection labels;
- modal `role=dialog`, `aria-modal`, Escape handling and focus wrapping;
- no tooltip-only critical information;
- tabular headers and a scrollable table alternative rather than a compressed
  unreadable matrix;
- browser zoom-compatible relative layout and responsive reflow;
- `prefers-reduced-motion` support.

WCAG AA intent is reflected in token contrast, but formal contrast and
screen-reader audits still require production font/browser combinations and
automated plus manual testing. A production follow-up should add axe-core,
Playwright keyboard journeys and NVDA/VoiceOver verification.

Dangerous actions are not executed from the command palette; the palette opens
the same confirmation flow. Observer presentation mode removes sensitive
controls rather than disabling them.
