# 🌐 CyberSentinel: Real-Time Global Threat Intelligence & 3D Vulnerability Radar

[![WebGL](https://img.shields.io/badge/Graphics-WebGL%20%2F%20Three.js-orange.svg)](https://threejs.org/)
[![JavaScript](https://img.shields.io/badge/Language-ES6%2B%20JavaScript-yellow.svg)](https://developer.mozilla.org/en-US/docs/Web/JavaScript)
[![CSS3](https://img.shields.io/badge/Design-Glassmorphism%20UI-blue.svg)](https://www.w3.org/Style/CSS/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**CyberSentinel** is an interactive, browser-based cybersecurity threat radar and 3D geospatial attack visualizer. It renders live CVE vulnerability streams, threat actor origin vectors, and targeted infrastructure on an interactive 3D globe with real-time particle trajectories and SOC dashboard telemetry.

---

## 🛡️ Key Capabilities

* **3D Spherical Geospatial Projection**: Interactive 3D globe with smooth orbit, pan, and zoom controls.
* **Attack Vector Trajectory Arcs**: Real-time parabolic Bézier arcs displaying cyber-attack vectors from origin to destination coordinates.
* **CVE Severity HUD**: Heads-Up Display categorizing threats by CVSS score, protocol (`SSH`, `HTTPS`, `DDoS`, `Ransomware`), and target region.
* **Filterable Threat Stream**: Live feed enabling SOC analysts to filter by severity (`Critical`, `High`, `Medium`).
* **Zero Dependencies**: Lightweight, performant, and runs directly in any modern browser without heavy build tooling.

---

## 🚀 Live Demo & Launch

Simply clone and open `index.html` in your browser:
```bash
git clone https://github.com/rishwebb/CyberSentinel-Global-Threat-Map.git
cd CyberSentinel-Global-Threat-Map
# Open in browser directly or with any local server:
npx serve .
```

---

## 📄 License
Licensed under the [MIT License](LICENSE).
