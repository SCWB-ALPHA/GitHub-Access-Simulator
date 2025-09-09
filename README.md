# GitHub Access Simulator — Vibe Edition (v1.1)

Bold gradients, confetti 🎉 on success, shake on denials, and colorblind-aware palette options (Ocean / Sunset / Emerald). Still fully accessible with text-size and high-contrast modes.

> **Disclaimer:** Training only. No real repos or secrets are touched.

## Quick Start
```bash
pip install flask
python app.py
# open http://127.0.0.1:5000

What’s New vs 1.0

🎨 Multi-palette gradient hero (Ocean/Sunset/Emerald)

🟩 Confetti on Approved, 🟥 shake on Denied

🔎 Larger default text, better spacing and contrast

♿ High-contrast toggle + text size S/M/L

🧭 Cleaner panels, badges, and legend

Customize

Rules: ACCESS_RULES

Resources: RESOURCE_TYPES

Actions: ALLOWED_ACTIONS & ACTION_CLASS

Overlays: constants like SENSITIVE_TYPES, PROTECTED_BRANCH_RESOURCE

Scenarios: TRAINING_SCENARIOS

Quiz: QUIZ_BANK

Data

audit_log.csv — appended on each test

quiz_results.csv — appended on quiz submit

Troubleshooting

Avoid f-strings for templates; this file uses plain triple-quoted strings.

If CSV export errors on Windows, close the CSV in Excel and retry.

Creation Date: 2025-09-08