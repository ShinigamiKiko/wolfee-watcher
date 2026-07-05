# Kvisior8 — Security Dashboard (React)

A StackRox-inspired Kubernetes security dashboard built with Vite + React 18.

## Quick Start

```bash
npm install
npm run dev
```

Then open http://localhost:5173

## Project Structure

```
src/
  context/AppContext.jsx      # Global state (page, toasts, modals)
  components/
    Topbar.jsx                # Top navigation bar
    Sidebar.jsx               # Left sidebar navigation
    Toast.jsx                 # Toast notification stack
    Modal.jsx                 # Modal overlay
    DetailPanel.jsx           # Reusable right-side split panel
    ui.jsx                    # Shared UI atoms (SevBadge, StatCard, etc.)
  data/
    violations.js             # Violations data
    imageData.js              # Image CVE data
    vulnData.js               # Vulnerability detail data
    riskData.js               # Risk scoring data
    cfgData.js                # Configuration management data
  pages/
    Dashboard.jsx             # Overview page
    Violations.jsx            # Policy violations (split panel)
    Compliance.jsx            # Compliance frameworks
    ImageScan.jsx             # Image vulnerability scanner
    VulnMgmt.jsx              # Vulnerability management (split panel)
    ConfigMgmt.jsx            # Kubernetes config mgmt (split panel)
    Risk.jsx                  # Risk prioritization (split panel)
    PolicyMgmt.jsx            # Security policies
    SystemHealth.jsx          # Platform health
    MyProfile.jsx             # User profile + API tokens
  styles/
    layout.css                # Variables, topbar, sidebar, layout
    components.css            # Cards, tables, badges, tabs, charts
    overlays.css              # Toasts, modals, dropdowns, panels
```

All files are ≤ 300 lines.
