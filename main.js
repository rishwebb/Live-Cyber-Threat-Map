(() => {
  "use strict";

  const REFRESH_INTERVAL_MS = 5000;
  const MIN_ATTACKS_FOR_VISUAL_DENSITY = 28;
  const MAX_EVENT_LOG_ENTRIES = 48;
  const FEED_CACHE_TTL_MS = 60_000;
  const GEO_LOOKUP_BUDGET_PER_CYCLE = 12;

  const LIVE_FEEDS = [
    {
      name: "URLHaus Recent",
      kind: "json",
      url: "https://urlhaus.abuse.ch/downloads/json_recent/"
    },
    {
      name: "Feodo Tracker",
      kind: "json",
      url: "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json"
    },
    {
      name: "IPsum L4",
      kind: "text",
      url: "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/4.txt"
    }
  ];

  const ATTACK_TYPE_POOL = [
    "SSH Brute Force",
    "Malware C2",
    "Botnet Activity",
    "RDP Brute Force",
    "Credential Stuffing",
    "DDoS Probe",
    "Exploit Scan",
    "Phishing Host",
    "Web Injection"
  ];

  const THREAT_LEVEL_STYLE = {
    LOW: {
      color: "#64ff98",
      fade: "rgba(100, 255, 152, 0.18)",
      weight: 1.2,
      pointRadius: 0.11
    },
    ELEVATED: {
      color: "#ffc146",
      fade: "rgba(255, 193, 70, 0.2)",
      weight: 1.45,
      pointRadius: 0.13
    },
    HIGH: {
      color: "#ff7a3d",
      fade: "rgba(255, 122, 61, 0.22)",
      weight: 1.7,
      pointRadius: 0.15
    },
    CRITICAL: {
      color: "#ff2d2d",
      fade: "rgba(255, 45, 45, 0.25)",
      weight: 1.95,
      pointRadius: 0.17
    }
  };

  const ATTACK_LEVEL_BY_TYPE = {
    "Phishing Host": "LOW",
    "Credential Stuffing": "ELEVATED",
    "SSH Brute Force": "ELEVATED",
    "Exploit Scan": "ELEVATED",
    "Web Injection": "HIGH",
    "RDP Brute Force": "HIGH",
    "DDoS Probe": "HIGH",
    "Botnet Activity": "CRITICAL",
    "Malware C2": "CRITICAL"
  };

  const PROTECTED_TARGETS = [
    { label: "New York SOC", lat: 40.7128, lng: -74.006 },
    { label: "London Exchange", lat: 51.5072, lng: -0.1276 },
    { label: "Frankfurt Node", lat: 50.1109, lng: 8.6821 },
    { label: "São Paulo Hub", lat: -23.5505, lng: -46.6333 },
    { label: "Mumbai Gateway", lat: 19.076, lng: 72.8777 },
    { label: "Singapore Core", lat: 1.3521, lng: 103.8198 },
    { label: "Tokyo Edge", lat: 35.6762, lng: 139.6503 },
    { label: "Sydney Relay", lat: -33.8688, lng: 151.2093 },
    { label: "Toronto Datacenter", lat: 43.6532, lng: -79.3832 },
    { label: "Dubai Transit", lat: 25.2048, lng: 55.2708 }
  ];

  const COUNTRY_CENTROIDS = [
    { code: "US", country: "United States", lat: 39.7837, lng: -100.4459 },
    { code: "CN", country: "China", lat: 35.8617, lng: 104.1954 },
    { code: "RU", country: "Russia", lat: 61.524, lng: 105.3188 },
    { code: "DE", country: "Germany", lat: 51.1657, lng: 10.4515 },
    { code: "NL", country: "Netherlands", lat: 52.1326, lng: 5.2913 },
    { code: "FR", country: "France", lat: 46.2276, lng: 2.2137 },
    { code: "GB", country: "United Kingdom", lat: 55.3781, lng: -3.436 },
    { code: "BR", country: "Brazil", lat: -14.235, lng: -51.9253 },
    { code: "IN", country: "India", lat: 20.5937, lng: 78.9629 },
    { code: "JP", country: "Japan", lat: 36.2048, lng: 138.2529 },
    { code: "KR", country: "South Korea", lat: 35.9078, lng: 127.7669 },
    { code: "VN", country: "Vietnam", lat: 14.0583, lng: 108.2772 },
    { code: "ID", country: "Indonesia", lat: -0.7893, lng: 113.9213 },
    { code: "TR", country: "Turkey", lat: 38.9637, lng: 35.2433 },
    { code: "IR", country: "Iran", lat: 32.4279, lng: 53.688 },
    { code: "ZA", country: "South Africa", lat: -30.5595, lng: 22.9375 },
    { code: "AU", country: "Australia", lat: -25.2744, lng: 133.7751 },
    { code: "CA", country: "Canada", lat: 56.1304, lng: -106.3468 },
    { code: "MX", country: "Mexico", lat: 23.6345, lng: -102.5528 },
    { code: "AR", country: "Argentina", lat: -38.4161, lng: -63.6167 },
    { code: "PL", country: "Poland", lat: 51.9194, lng: 19.1451 },
    { code: "RO", country: "Romania", lat: 45.9432, lng: 24.9668 },
    { code: "UA", country: "Ukraine", lat: 48.3794, lng: 31.1656 },
    { code: "SE", country: "Sweden", lat: 60.1282, lng: 18.6435 },
    { code: "NO", country: "Norway", lat: 60.472, lng: 8.4689 },
    { code: "ES", country: "Spain", lat: 40.4637, lng: -3.7492 },
    { code: "IT", country: "Italy", lat: 41.8719, lng: 12.5674 },
    { code: "TH", country: "Thailand", lat: 15.87, lng: 100.9925 },
    { code: "PH", country: "Philippines", lat: 12.8797, lng: 121.774 },
    { code: "EG", country: "Egypt", lat: 26.8206, lng: 30.8025 }
  ];

  const EMBEDDED_FALLBACK_DATA = [
    {
      ip: "185.220.101.4",
      country_code: "DE",
      country: "Germany",
      lat: 52.52,
      lng: 13.405,
      attack_type: "Botnet Activity",
      source: "Fallback Snapshot",
      last_seen: "2026-03-03T08:11:00Z"
    },
    {
      ip: "45.95.147.27",
      country_code: "NL",
      country: "Netherlands",
      lat: 52.3676,
      lng: 4.9041,
      attack_type: "SSH Brute Force",
      source: "Fallback Snapshot",
      last_seen: "2026-03-03T08:12:00Z"
    },
    {
      ip: "103.114.105.214",
      country_code: "VN",
      country: "Vietnam",
      lat: 21.0285,
      lng: 105.8542,
      attack_type: "Malware C2",
      source: "Fallback Snapshot",
      last_seen: "2026-03-03T08:13:00Z"
    },
    {
      ip: "176.65.148.18",
      country_code: "RU",
      country: "Russia",
      lat: 55.7558,
      lng: 37.6173,
      attack_type: "RDP Brute Force",
      source: "Fallback Snapshot",
      last_seen: "2026-03-03T08:14:00Z"
    },
    {
      ip: "91.92.240.111",
      country_code: "PL",
      country: "Poland",
      lat: 52.2297,
      lng: 21.0122,
      attack_type: "Exploit Scan",
      source: "Fallback Snapshot",
      last_seen: "2026-03-03T08:14:30Z"
    },
    {
      ip: "194.147.32.46",
      country_code: "RO",
      country: "Romania",
      lat: 44.4268,
      lng: 26.1025,
      attack_type: "Credential Stuffing",
      source: "Fallback Snapshot",
      last_seen: "2026-03-03T08:15:10Z"
    },
    {
      ip: "89.248.172.16",
      country_code: "FR",
      country: "France",
      lat: 48.8566,
      lng: 2.3522,
      attack_type: "Web Injection",
      source: "Fallback Snapshot",
      last_seen: "2026-03-03T08:16:05Z"
    },
    {
      ip: "5.188.206.6",
      country_code: "RU",
      country: "Russia",
      lat: 59.9343,
      lng: 30.3351,
      attack_type: "SSH Brute Force",
      source: "Fallback Snapshot",
      last_seen: "2026-03-03T08:16:40Z"
    },
    {
      ip: "118.193.32.180",
      country_code: "HK",
      country: "Hong Kong",
      lat: 22.3193,
      lng: 114.1694,
      attack_type: "Malware C2",
      source: "Fallback Snapshot",
      last_seen: "2026-03-03T08:17:00Z"
    },
    {
      ip: "103.13.29.77",
      country_code: "ID",
      country: "Indonesia",
      lat: -6.2088,
      lng: 106.8456,
      attack_type: "Botnet Activity",
      source: "Fallback Snapshot",
      last_seen: "2026-03-03T08:17:35Z"
    },
    {
      ip: "181.214.87.203",
      country_code: "BR",
      country: "Brazil",
      lat: -23.5505,
      lng: -46.6333,
      attack_type: "Phishing Host",
      source: "Fallback Snapshot",
      last_seen: "2026-03-03T08:18:15Z"
    },
    {
      ip: "190.115.18.204",
      country_code: "AR",
      country: "Argentina",
      lat: -34.6037,
      lng: -58.3816,
      attack_type: "DDoS Probe",
      source: "Fallback Snapshot",
      last_seen: "2026-03-03T08:18:48Z"
    },
    {
      ip: "45.134.26.79",
      country_code: "GB",
      country: "United Kingdom",
      lat: 51.5074,
      lng: -0.1278,
      attack_type: "Exploit Scan",
      source: "Fallback Snapshot",
      last_seen: "2026-03-03T08:19:11Z"
    },
    {
      ip: "185.156.73.54",
      country_code: "TR",
      country: "Turkey",
      lat: 39.9334,
      lng: 32.8597,
      attack_type: "Web Injection",
      source: "Fallback Snapshot",
      last_seen: "2026-03-03T08:20:03Z"
    },
    {
      ip: "154.92.12.92",
      country_code: "ZA",
      country: "South Africa",
      lat: -26.2041,
      lng: 28.0473,
      attack_type: "Credential Stuffing",
      source: "Fallback Snapshot",
      last_seen: "2026-03-03T08:20:40Z"
    },
    {
      ip: "102.130.113.206",
      country_code: "EG",
      country: "Egypt",
      lat: 30.0444,
      lng: 31.2357,
      attack_type: "Malware C2",
      source: "Fallback Snapshot",
      last_seen: "2026-03-03T08:21:10Z"
    },
    {
      ip: "14.241.39.121",
      country_code: "VN",
      country: "Vietnam",
      lat: 10.8231,
      lng: 106.6297,
      attack_type: "SSH Brute Force",
      source: "Fallback Snapshot",
      last_seen: "2026-03-03T08:21:45Z"
    },
    {
      ip: "43.159.139.57",
      country_code: "CN",
      country: "China",
      lat: 31.2304,
      lng: 121.4737,
      attack_type: "Botnet Activity",
      source: "Fallback Snapshot",
      last_seen: "2026-03-03T08:22:15Z"
    },
    {
      ip: "61.177.172.18",
      country_code: "CN",
      country: "China",
      lat: 32.0603,
      lng: 118.7969,
      attack_type: "RDP Brute Force",
      source: "Fallback Snapshot",
      last_seen: "2026-03-03T08:22:51Z"
    },
    {
      ip: "77.247.181.163",
      country_code: "SE",
      country: "Sweden",
      lat: 59.3293,
      lng: 18.0686,
      attack_type: "Phishing Host",
      source: "Fallback Snapshot",
      last_seen: "2026-03-03T08:23:10Z"
    },
    {
      ip: "31.13.71.36",
      country_code: "NO",
      country: "Norway",
      lat: 59.9139,
      lng: 10.7522,
      attack_type: "Exploit Scan",
      source: "Fallback Snapshot",
      last_seen: "2026-03-03T08:23:44Z"
    },
    {
      ip: "200.25.71.33",
      country_code: "MX",
      country: "Mexico",
      lat: 19.4326,
      lng: -99.1332,
      attack_type: "DDoS Probe",
      source: "Fallback Snapshot",
      last_seen: "2026-03-03T08:24:10Z"
    },
    {
      ip: "45.61.136.40",
      country_code: "US",
      country: "United States",
      lat: 34.0522,
      lng: -118.2437,
      attack_type: "Web Injection",
      source: "Fallback Snapshot",
      last_seen: "2026-03-03T08:24:38Z"
    },
    {
      ip: "142.147.89.16",
      country_code: "CA",
      country: "Canada",
      lat: 45.5019,
      lng: -73.5674,
      attack_type: "Credential Stuffing",
      source: "Fallback Snapshot",
      last_seen: "2026-03-03T08:25:01Z"
    },
    {
      ip: "103.252.114.17",
      country_code: "IN",
      country: "India",
      lat: 28.6139,
      lng: 77.209,
      attack_type: "SSH Brute Force",
      source: "Fallback Snapshot",
      last_seen: "2026-03-03T08:25:32Z"
    },
    {
      ip: "180.163.220.28",
      country_code: "CN",
      country: "China",
      lat: 39.9042,
      lng: 116.4074,
      attack_type: "Malware C2",
      source: "Fallback Snapshot",
      last_seen: "2026-03-03T08:26:08Z"
    },
    {
      ip: "165.154.32.141",
      country_code: "JP",
      country: "Japan",
      lat: 35.6895,
      lng: 139.6917,
      attack_type: "Exploit Scan",
      source: "Fallback Snapshot",
      last_seen: "2026-03-03T08:26:42Z"
    },
    {
      ip: "43.155.87.88",
      country_code: "SG",
      country: "Singapore",
      lat: 1.3521,
      lng: 103.8198,
      attack_type: "Botnet Activity",
      source: "Fallback Snapshot",
      last_seen: "2026-03-03T08:27:12Z"
    },
    {
      ip: "171.22.28.15",
      country_code: "UA",
      country: "Ukraine",
      lat: 50.4501,
      lng: 30.5234,
      attack_type: "RDP Brute Force",
      source: "Fallback Snapshot",
      last_seen: "2026-03-03T08:27:49Z"
    },
    {
      ip: "95.217.116.32",
      country_code: "FI",
      country: "Finland",
      lat: 60.1699,
      lng: 24.9384,
      attack_type: "Phishing Host",
      source: "Fallback Snapshot",
      last_seen: "2026-03-03T08:28:10Z"
    },
    {
      ip: "194.26.29.15",
      country_code: "ES",
      country: "Spain",
      lat: 40.4168,
      lng: -3.7038,
      attack_type: "Credential Stuffing",
      source: "Fallback Snapshot",
      last_seen: "2026-03-03T08:28:38Z"
    },
    {
      ip: "82.115.223.44",
      country_code: "IT",
      country: "Italy",
      lat: 41.9028,
      lng: 12.4964,
      attack_type: "Web Injection",
      source: "Fallback Snapshot",
      last_seen: "2026-03-03T08:29:04Z"
    },
    {
      ip: "202.29.233.149",
      country_code: "TH",
      country: "Thailand",
      lat: 13.7563,
      lng: 100.5018,
      attack_type: "DDoS Probe",
      source: "Fallback Snapshot",
      last_seen: "2026-03-03T08:29:43Z"
    },
    {
      ip: "49.231.15.82",
      country_code: "PH",
      country: "Philippines",
      lat: 14.5995,
      lng: 120.9842,
      attack_type: "Malware C2",
      source: "Fallback Snapshot",
      last_seen: "2026-03-03T08:30:12Z"
    }
  ];

  const state = {
    map2D: null,
    globe3D: null,
    is3DMode: false,
    isRefreshing: false,
    geoLookupsUsed: 0,
    totalAttackCount: 0,
    eventLog: [],
    attackHistory: [],
    geoCache: new Map(),
    feedCache: new Map(),
    localFallbackCache: null
  };

  class Map2DRenderer {
    constructor(containerId) {
      this.containerId = containerId;
      this.map = null;
      this.layers = [];
      this.renderQueue = [];
      this.renderFrame = null;
    }

    init() {
      const container = document.getElementById(this.containerId);
      if (!container) {
        return;
      }
      if (typeof window.L === "undefined") {
        container.innerHTML = '<div class="map-fallback">Leaflet CDN unavailable.</div>';
        return;
      }

      this.map = L.map(container, {
        zoomControl: false,
        worldCopyJump: true,
        preferCanvas: true,
        maxBoundsViscosity: 0.2,
        attributionControl: true
      }).setView([18, 6], 2);

      L.tileLayer("https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png", {
        attribution: "&copy; OpenStreetMap contributors &copy; CARTO",
        maxZoom: 7,
        minZoom: 2,
        noWrap: false
      }).addTo(this.map);

      L.control
        .zoom({ position: "bottomright" })
        .addTo(this.map);

      setTimeout(() => {
        this.map.invalidateSize();
      }, 120);
    }

    renderAttacks(attacks) {
      if (!this.map || !Array.isArray(attacks)) {
        return;
      }
      if (!attacks.length) {
        return;
      }
      this.renderQueue.push(...attacks);
      if (!this.renderFrame) {
        this.processRenderQueue();
      }
    }

    processRenderQueue() {
      if (!this.map) {
        this.renderQueue = [];
        this.renderFrame = null;
        return;
      }

      const chunkSize = 120;
      const batch = this.renderQueue.splice(0, chunkSize);
      batch.forEach((attack, idx) => {
        this.drawAttack(attack, idx);
      });

      if (this.renderQueue.length > 0) {
        this.renderFrame = window.requestAnimationFrame(() => this.processRenderQueue());
      } else {
        this.renderFrame = null;
      }
    }

    drawAttack(attack, index) {
      const origin = [attack.fromLat, attack.fromLng];
      const target = [attack.toLat, attack.toLng];
      const curvePoints = this.buildCurvePoints(origin, target, 56);
      const threatColor = attack.threatColor || "#ff3c3c";
      const threatWeight = attack.threatWeight || 1.5;

      const line = L.polyline([curvePoints[0]], {
        color: threatColor,
        opacity: 0.9,
        weight: threatWeight,
        className: "attack-line"
      }).addTo(this.map);

      const originMarker = L.circleMarker(origin, {
        radius: 3,
        color: threatColor,
        fillColor: threatColor,
        fillOpacity: 0.95,
        opacity: 0.95,
        weight: 1,
        interactive: false,
        keyboard: false
      }).addTo(this.map);

      const originHalo = L.circleMarker(origin, {
        radius: 6.2,
        color: threatColor,
        fillColor: threatColor,
        fillOpacity: 0,
        opacity: 0.24,
        weight: 1.1,
        interactive: false
      }).addTo(this.map);

      const destinationMarker = L.circleMarker(target, {
        radius: 2,
        color: threatColor,
        fillColor: threatColor,
        fillOpacity: 0.15,
        opacity: 0.4,
        weight: 1,
        interactive: false
      }).addTo(this.map);

      const packetMarker = L.circleMarker(origin, {
        radius: 2.2,
        color: threatColor,
        fillColor: threatColor,
        fillOpacity: 0.95,
        weight: 0,
        interactive: false
      }).addTo(this.map);

      const bundle = {
        line,
        originMarker,
        originHalo,
        destinationMarker,
        packetMarker,
        threatColor,
        animFrame: null,
        active: true,
        timer: null
      };

      const durationMs = 1700 + (index % 7) * 130;
      this.animateCurvedAttack(bundle, curvePoints, durationMs);
      bundle.timer = window.setTimeout(() => this.removeBundle(bundle), 4600);

      this.layers.push(bundle);
    }

    buildCurvePoints(origin, target, segments = 56) {
      const startLat = origin[0];
      const startLng = origin[1];
      const endLat = target[0];
      let endLng = target[1];

      const lngDelta = endLng - startLng;
      if (lngDelta > 180) {
        endLng -= 360;
      } else if (lngDelta < -180) {
        endLng += 360;
      }

      const dx = endLng - startLng;
      const dy = endLat - startLat;
      const distance = Math.hypot(dx, dy);
      if (distance < 0.001) {
        return [origin, target];
      }

      const midLat = (startLat + endLat) / 2;
      const midLng = (startLng + endLng) / 2;
      const normalLat = -dx / distance;
      const normalLng = dy / distance;
      const curvature = clamp(0.18 + distance / 220, 0.16, 0.34);
      const offset = distance * curvature;
      const controlLat = clamp(midLat + normalLat * offset, -80, 80);
      const controlLng = midLng + normalLng * offset;

      const points = [];
      for (let i = 0; i <= segments; i += 1) {
        const t = i / segments;
        const inv = 1 - t;
        const lat = inv * inv * startLat + 2 * inv * t * controlLat + t * t * endLat;
        const lng = inv * inv * startLng + 2 * inv * t * controlLng + t * t * endLng;
        points.push([lat, lng]);
      }

      return points;
    }

    interpolatePoint(a, b, t) {
      return [a[0] + (b[0] - a[0]) * t, a[1] + (b[1] - a[1]) * t];
    }

    animateCurvedAttack(bundle, curvePoints, durationMs) {
      const start = performance.now();
      const tick = (now) => {
        if (!this.map || !bundle.active) {
          return;
        }
        if (!this.map.hasLayer(bundle.line) || !this.map.hasLayer(bundle.packetMarker)) {
          return;
        }

        const progress = Math.min((now - start) / durationMs, 1);
        const scaled = progress * (curvePoints.length - 1);
        const baseIndex = Math.floor(scaled);
        const nextIndex = Math.min(baseIndex + 1, curvePoints.length - 1);
        const interp = scaled - baseIndex;
        const packetPoint = this.interpolatePoint(curvePoints[baseIndex], curvePoints[nextIndex], interp);

        const visiblePoints = curvePoints.slice(0, Math.max(1, baseIndex + 1));
        visiblePoints.push(packetPoint);

        bundle.line.setLatLngs(visiblePoints);
        bundle.packetMarker.setLatLng(packetPoint);

        if (progress < 1) {
          bundle.animFrame = window.requestAnimationFrame(tick);
          return;
        }

        bundle.line.setLatLngs(curvePoints);
        bundle.packetMarker.setLatLng(curvePoints[curvePoints.length - 1]);
        bundle.destinationMarker.setStyle({
          opacity: 1,
          fillOpacity: 0.92,
          color: bundle.threatColor,
          fillColor: bundle.threatColor
        });
        bundle.destinationMarker.setRadius(2.4);
        bundle.originHalo.setStyle({
          color: bundle.threatColor,
          fillColor: bundle.threatColor,
          opacity: 0.4,
          fillOpacity: 0.05
        });
        bundle.animFrame = null;
      };
      bundle.animFrame = window.requestAnimationFrame(tick);
    }

    removeBundle(bundle) {
      if (!bundle || !this.map) {
        return;
      }
      bundle.active = false;
      if (bundle.animFrame) {
        window.cancelAnimationFrame(bundle.animFrame);
        bundle.animFrame = null;
      }
      window.clearTimeout(bundle.timer);
      [bundle.line, bundle.originMarker, bundle.originHalo, bundle.destinationMarker, bundle.packetMarker].forEach((layer) => {
        if (layer && this.map.hasLayer(layer)) {
          this.map.removeLayer(layer);
        }
      });
      const idx = this.layers.indexOf(bundle);
      if (idx !== -1) {
        this.layers.splice(idx, 1);
      }
    }

    resize() {
      if (this.map) {
        this.map.invalidateSize();
      }
    }
  }

  class GlobeRenderer {
    constructor(containerId) {
      this.containerId = containerId;
      this.container = null;
      this.globe = null;
      this.arcStore = [];
    }

    init() {
      this.container = document.getElementById(this.containerId);
      if (!this.container) {
        return;
      }
      if (typeof window.Globe === "undefined") {
        this.container.innerHTML = '<div class="map-fallback">Globe.gl CDN unavailable.</div>';
        return;
      }

      this.globe = Globe()(this.container)
        .backgroundColor("rgba(0,0,0,0)")
        .globeImageUrl("https://unpkg.com/three-globe/example/img/earth-night.jpg")
        .bumpImageUrl("https://unpkg.com/three-globe/example/img/earth-topology.png")
        .showAtmosphere(true)
        .atmosphereColor("#ff3838")
        .atmosphereAltitude(0.15)
        .arcColor((d) => [d.colorStrong, d.colorFade])
        .arcStroke((d) => d.stroke)
        .arcDashLength(0.34)
        .arcDashGap(0.2)
        .arcDashInitialGap(() => Math.random())
        .arcDashAnimateTime(2100)
        .pointColor((d) => d.color)
        .pointAltitude(0.012)
        .pointRadius((d) => d.radius)
        .pointsMerge(true);

      this.resize();
      const controls = this.globe.controls();
      controls.autoRotate = true;
      controls.autoRotateSpeed = 0.42;
      controls.enablePan = false;
      controls.minDistance = 180;
      controls.maxDistance = 340;
    }

    renderAttacks(attacks) {
      if (!this.globe) {
        return;
      }

      const freshArcs = attacks.map((attack) => ({
        startLat: attack.fromLat,
        startLng: attack.fromLng,
        endLat: attack.toLat,
        endLng: attack.toLng,
        label: `${attack.type} | ${attack.sourceCountryCode} -> ${attack.target.label}`,
        altitude: 0.12 + Math.random() * 0.18,
        colorStrong: attack.threatColor || "#ff3c3c",
        colorFade: attack.threatFade || "rgba(255, 60, 60, 0.15)",
        stroke: clamp((attack.threatWeight || 1.5) / 2.2, 0.5, 1.05),
        sourcePointRadius: attack.threatPointRadius || 0.14
      }));

      this.arcStore = freshArcs;

      const points = [];
      this.arcStore.forEach((arc) => {
        points.push({
          lat: arc.startLat,
          lng: arc.startLng,
          color: arc.colorStrong,
          radius: arc.sourcePointRadius
        });
        points.push({ lat: arc.endLat, lng: arc.endLng, color: "rgba(54,223,255,0.85)", radius: 0.1 });
      });

      this.globe.arcsData(this.arcStore).pointsData(points);
    }

    resize() {
      if (!this.globe || !this.container) {
        return;
      }
      const width = this.container.clientWidth;
      const height = this.container.clientHeight;
      this.globe.width(width).height(height);
    }
  }

  function randomChoice(items) {
    return items[Math.floor(Math.random() * items.length)];
  }

  function clamp(value, min, max) {
    return Math.max(min, Math.min(max, value));
  }

  function shuffleArray(items) {
    const clone = [...items];
    for (let i = clone.length - 1; i > 0; i -= 1) {
      const j = Math.floor(Math.random() * (i + 1));
      [clone[i], clone[j]] = [clone[j], clone[i]];
    }
    return clone;
  }

  function hashToInt(text) {
    let hash = 0;
    const value = String(text || "");
    for (let i = 0; i < value.length; i += 1) {
      hash = (hash << 5) - hash + value.charCodeAt(i);
      hash |= 0;
    }
    return Math.abs(hash);
  }

  function isValidIPv4(ip) {
    if (!ip || typeof ip !== "string") {
      return false;
    }
    const parts = ip.trim().split(".");
    if (parts.length !== 4) {
      return false;
    }
    return parts.every((part) => {
      if (!/^\d+$/.test(part)) {
        return false;
      }
      const num = Number(part);
      return num >= 0 && num <= 255;
    });
  }

  function extractIPv4(value) {
    if (typeof value !== "string") {
      return "";
    }
    const match = value.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);
    if (!match) {
      return "";
    }
    const ip = match[0];
    return isValidIPv4(ip) ? ip : "";
  }

  function extractHostFromUrl(url) {
    if (!url || typeof url !== "string") {
      return "";
    }
    try {
      const parsed = new URL(url);
      return parsed.hostname || "";
    } catch (_error) {
      return "";
    }
  }

  function formatClock(ts) {
    return new Date(ts).toLocaleTimeString("en-US", {
      hour12: false,
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit"
    });
  }

  function classifyAttackType(seedText, fallbackKey) {
    const txt = String(seedText || "").toLowerCase();
    if (txt.includes("ssh")) return "SSH Brute Force";
    if (txt.includes("rdp")) return "RDP Brute Force";
    if (txt.includes("bot") || txt.includes("c2") || txt.includes("command")) return "Botnet Activity";
    if (txt.includes("phish")) return "Phishing Host";
    if (txt.includes("inject") || txt.includes("xss") || txt.includes("sql")) return "Web Injection";
    if (txt.includes("ddos") || txt.includes("flood")) return "DDoS Probe";
    if (txt.includes("exploit") || txt.includes("scan")) return "Exploit Scan";
    if (txt.includes("credential") || txt.includes("stuff")) return "Credential Stuffing";
    if (txt.includes("malware") || txt.includes("trojan") || txt.includes("ransom")) return "Malware C2";
    const index = hashToInt(fallbackKey || seedText || "seed") % ATTACK_TYPE_POOL.length;
    return ATTACK_TYPE_POOL[index];
  }

  function getThreatStyle(attackType) {
    const level = ATTACK_LEVEL_BY_TYPE[attackType] || "ELEVATED";
    const style = THREAT_LEVEL_STYLE[level] || THREAT_LEVEL_STYLE.ELEVATED;
    return {
      level,
      color: style.color,
      fade: style.fade,
      weight: style.weight,
      pointRadius: style.pointRadius
    };
  }

  async function fetchWithTimeout(url, kind, timeoutMs = 4500) {
    const controller = new AbortController();
    const timer = window.setTimeout(() => controller.abort(), timeoutMs);

    try {
      const response = await fetch(url, {
        signal: controller.signal,
        cache: "no-store"
      });
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
      if (kind === "json") {
        return await response.json();
      }
      return await response.text();
    } finally {
      window.clearTimeout(timer);
    }
  }

  function normalizeThreatRecord(raw, sourceName) {
    if (!raw || typeof raw !== "object") {
      return null;
    }

    const ipCandidate =
      raw.ip ||
      raw.ip_address ||
      raw.dst_ip ||
      raw.src_ip ||
      raw.host ||
      raw.address ||
      extractHostFromUrl(raw.url || "");

    const ip = extractIPv4(String(ipCandidate || ""));
    if (!ip) {
      return null;
    }

    const typeText = raw.attack_type || raw.type || raw.threat || raw.malware || raw.tags || "";
    const attackType = classifyAttackType(typeText, ip);

    const lat = Number(raw.lat ?? raw.latitude);
    const lng = Number(raw.lng ?? raw.lon ?? raw.longitude);

    const countryCode = String(raw.country_code || raw.cc || "").toUpperCase() || null;
    const country = raw.country || raw.country_name || null;

    return {
      ip,
      source: sourceName || raw.source || "Unknown Feed",
      type: attackType,
      countryCode,
      country,
      lat: Number.isFinite(lat) ? lat : null,
      lng: Number.isFinite(lng) ? lng : null,
      timestamp: raw.last_seen || raw.timestamp || raw.dateadded || new Date().toISOString()
    };
  }

  function parseUrlHausFeed(payload) {
    const rows = Array.isArray(payload)
      ? payload
      : Array.isArray(payload.urls)
        ? payload.urls
        : Array.isArray(payload.data)
          ? payload.data
          : [];

    const records = [];
    rows.forEach((entry) => {
      const hostCandidate = entry.host || entry.ip || extractHostFromUrl(entry.url || "");
      const ip = extractIPv4(String(hostCandidate || ""));
      if (!ip) {
        return;
      }
      const normalized = normalizeThreatRecord(
        {
          ip,
          threat: [entry.threat, entry.tags].filter(Boolean).join(" "),
          timestamp: entry.dateadded,
          source: "URLHaus"
        },
        "URLHaus"
      );
      if (normalized) {
        records.push(normalized);
      }
    });

    return records;
  }

  function parseFeodoFeed(payload) {
    const rows = Array.isArray(payload)
      ? payload
      : Array.isArray(payload.data)
        ? payload.data
        : Array.isArray(payload.feeds)
          ? payload.feeds
          : [];

    const records = [];
    rows.forEach((entry) => {
      const normalized = normalizeThreatRecord(
        {
          ip: entry.dst_ip || entry.ip || entry.ip_address,
          threat: `${entry.malware || "botnet"} c2`,
          timestamp: entry.first_seen_utc || entry.dateadded,
          source: "Feodo Tracker"
        },
        "Feodo Tracker"
      );
      if (normalized) {
        records.push(normalized);
      }
    });

    return records;
  }

  function parseIpsumFeed(text, sourceName) {
    if (typeof text !== "string") {
      return [];
    }

    const lines = text.split(/\r?\n/);
    const records = [];

    lines.forEach((line) => {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#")) {
        return;
      }
      const parts = trimmed.split(/\s+/);
      const ip = extractIPv4(parts[0] || "");
      if (!ip) {
        return;
      }
      const score = Number(parts[1] || 0);
      const inferredType =
        score >= 10 ? "Botnet Activity" : score >= 7 ? "SSH Brute Force" : score >= 5 ? "Exploit Scan" : "Malware C2";

      const normalized = normalizeThreatRecord(
        {
          ip,
          attack_type: inferredType,
          source: sourceName
        },
        sourceName
      );
      if (normalized) {
        records.push(normalized);
      }
    });

    return records;
  }

  async function fetchFeedRecords(feed) {
    const now = Date.now();
    const cached = state.feedCache.get(feed.name);
    if (cached && now - cached.ts <= FEED_CACHE_TTL_MS) {
      return {
        mode: "cache",
        records: cached.records
      };
    }

    try {
      const payload = await fetchWithTimeout(feed.url, feed.kind, 4200);
      let records = [];

      if (feed.name.includes("URLHaus")) {
        records = parseUrlHausFeed(payload);
      } else if (feed.name.includes("Feodo")) {
        records = parseFeodoFeed(payload);
      } else {
        records = parseIpsumFeed(payload, feed.name);
      }

      if (records.length) {
        state.feedCache.set(feed.name, { ts: now, records });
      }

      return {
        mode: "live",
        records
      };
    } catch (_error) {
      if (cached && cached.records.length) {
        return {
          mode: "stale-cache",
          records: cached.records
        };
      }
      return {
        mode: "error",
        records: []
      };
    }
  }

  async function loadLiveThreatRecords() {
    const settled = await Promise.all(LIVE_FEEDS.map((feed) => fetchFeedRecords(feed)));
    const merged = [];
    let liveFeeds = 0;
    let cacheFeeds = 0;

    settled.forEach((result) => {
      if (result.mode === "live") {
        liveFeeds += 1;
      }
      if (result.mode === "cache" || result.mode === "stale-cache") {
        cacheFeeds += 1;
      }
      if (Array.isArray(result.records) && result.records.length) {
        merged.push(...result.records);
      }
    });

    return {
      records: merged,
      liveFeeds,
      cacheFeeds
    };
  }

  async function loadLocalFallbackData() {
    if (state.localFallbackCache) {
      return state.localFallbackCache;
    }
    try {
      const payload = await fetchWithTimeout("./sample-threat-data.json", "json", 1300);
      if (Array.isArray(payload)) {
        state.localFallbackCache = payload
          .map((entry) => normalizeThreatRecord(entry, "Local Sample JSON"))
          .filter(Boolean);
      }
    } catch (_error) {
      state.localFallbackCache = [];
    }
    return state.localFallbackCache;
  }

  async function loadThreatRecords() {
    const live = await loadLiveThreatRecords();

    if (live.records.length) {
      let records = [...live.records];
      let status = `FEEDS: LIVE ${live.liveFeeds}/${LIVE_FEEDS.length}`;

      if (live.cacheFeeds > 0) {
        status += ` | CACHE ${live.cacheFeeds}`;
      }

      if (records.length < MIN_ATTACKS_FOR_VISUAL_DENSITY) {
        const local = await loadLocalFallbackData();
        if (local.length) {
          records = records.concat(local);
          status += " | BOOSTED BY LOCAL JSON";
        } else {
          records = records.concat(EMBEDDED_FALLBACK_DATA.map((entry) => normalizeThreatRecord(entry, "Embedded Fallback")).filter(Boolean));
          status += " | BOOSTED BY EMBEDDED";
        }
      }

      return {
        records,
        status
      };
    }

    const local = await loadLocalFallbackData();
    if (local.length) {
      return {
        records: local,
        status: "FEEDS: FALLBACK sample-threat-data.json"
      };
    }

    return {
      records: EMBEDDED_FALLBACK_DATA.map((entry) => normalizeThreatRecord(entry, "Embedded Fallback")).filter(Boolean),
      status: "FEEDS: EMBEDDED OFFLINE FALLBACK"
    };
  }

  function centroidByCountryCode(code) {
    if (!code) {
      return null;
    }
    return COUNTRY_CENTROIDS.find((item) => item.code === code.toUpperCase()) || null;
  }

  function pseudoLocationFromIp(ip) {
    const hash = hashToInt(ip);
    const base = COUNTRY_CENTROIDS[hash % COUNTRY_CENTROIDS.length];
    const latOffset = ((hash % 1200) / 1200 - 0.5) * 7.2;
    const lngOffset = (((hash >> 2) % 1200) / 1200 - 0.5) * 9.4;

    return {
      countryCode: base.code,
      country: base.country,
      lat: clamp(base.lat + latOffset, -70, 78),
      lng: clamp(base.lng + lngOffset, -178, 178)
    };
  }

  async function lookupGeoFromApi(ip) {
    const url = `https://ipwho.is/${encodeURIComponent(ip)}`;
    const payload = await fetchWithTimeout(url, "json", 2000);
    if (!payload || payload.success !== true) {
      return null;
    }

    const lat = Number(payload.latitude);
    const lng = Number(payload.longitude);
    if (!Number.isFinite(lat) || !Number.isFinite(lng)) {
      return null;
    }

    const countryCode = String(payload.country_code || "").toUpperCase() || null;
    const country = payload.country || "Unknown";

    return {
      countryCode,
      country,
      lat,
      lng
    };
  }

  async function resolveLocation(record) {
    if (record.lat != null && record.lng != null) {
      const resolved = {
        countryCode: record.countryCode || centroidByCountryCode(record.countryCode)?.code || "--",
        country: record.country || centroidByCountryCode(record.countryCode)?.country || "Unknown",
        lat: record.lat,
        lng: record.lng
      };
      state.geoCache.set(record.ip, resolved);
      return resolved;
    }

    if (state.geoCache.has(record.ip)) {
      return state.geoCache.get(record.ip);
    }

    if (record.countryCode) {
      const centroid = centroidByCountryCode(record.countryCode);
      if (centroid) {
        const geo = {
          countryCode: centroid.code,
          country: centroid.country,
          lat: centroid.lat,
          lng: centroid.lng
        };
        state.geoCache.set(record.ip, geo);
        return geo;
      }
    }

    if (state.geoLookupsUsed < GEO_LOOKUP_BUDGET_PER_CYCLE) {
      state.geoLookupsUsed += 1;
      try {
        const geo = await lookupGeoFromApi(record.ip);
        if (geo) {
          state.geoCache.set(record.ip, geo);
          return geo;
        }
      } catch (_error) {
        // Fall through to deterministic fallback.
      }
    }

    const pseudo = pseudoLocationFromIp(record.ip);
    state.geoCache.set(record.ip, pseudo);
    return pseudo;
  }

  async function mapWithConcurrency(items, limit, mapper) {
    const output = new Array(items.length);
    let nextIndex = 0;

    async function worker() {
      while (nextIndex < items.length) {
        const current = nextIndex;
        nextIndex += 1;
        output[current] = await mapper(items[current], current);
      }
    }

    const workerCount = Math.min(limit, items.length);
    const jobs = [];
    for (let i = 0; i < workerCount; i += 1) {
      jobs.push(worker());
    }
    await Promise.all(jobs);
    return output;
  }

  function pickTarget(originLat, originLng, idx) {
    const shuffled = shuffleArray(PROTECTED_TARGETS);
    const chosen = shuffled.find((target) => {
      const delta = Math.abs(originLat - target.lat) + Math.abs(originLng - target.lng);
      return delta > 35;
    });

    if (chosen) {
      return chosen;
    }
    return PROTECTED_TARGETS[idx % PROTECTED_TARGETS.length];
  }

  async function buildAttackEvents(records) {
    const allRecords = shuffleArray(Array.isArray(records) ? records : []);

    const enriched = await mapWithConcurrency(allRecords, 12, async (record) => {
      const geo = await resolveLocation(record);
      return {
        ...record,
        ...geo
      };
    });

    const now = Date.now();

    return enriched
      .filter((record) => Number.isFinite(record.lat) && Number.isFinite(record.lng))
      .map((record, idx) => {
        const target = pickTarget(record.lat, record.lng, idx);
        const type = record.type || randomChoice(ATTACK_TYPE_POOL);
        const threat = getThreatStyle(type);
        return {
          id: `${now}-${idx}-${record.ip}`,
          ip: record.ip,
          type,
          source: record.source || "Threat Feed",
          sourceCountry: record.country || "Unknown",
          sourceCountryCode: record.countryCode || "--",
          fromLat: record.lat,
          fromLng: record.lng,
          toLat: target.lat,
          toLng: target.lng,
          target,
          threatLevel: threat.level,
          threatColor: threat.color,
          threatFade: threat.fade,
          threatWeight: threat.weight,
          threatPointRadius: threat.pointRadius,
          timestamp: now
        };
      });
  }

  function computeThreatLevel(attacksPerMinute) {
    if (attacksPerMinute < 40) {
      return { label: "LOW", color: "#64ff98", width: Math.max(8, Math.round((attacksPerMinute / 40) * 25)) };
    }
    if (attacksPerMinute < 90) {
      return { label: "ELEVATED", color: "#ffc146", width: Math.round(26 + ((attacksPerMinute - 40) / 50) * 24) };
    }
    if (attacksPerMinute < 160) {
      return { label: "HIGH", color: "#ff6b4a", width: Math.round(50 + ((attacksPerMinute - 90) / 70) * 28) };
    }
    return { label: "CRITICAL", color: "#ff2d2d", width: 100 };
  }

  function renderTopCountries() {
    const container = document.getElementById("topCountries");
    if (!container) {
      return;
    }

    const counts = new Map();
    state.attackHistory.forEach((attack) => {
      const code = attack.sourceCountryCode || "--";
      const country = attack.sourceCountry || "Unknown";
      const key = `${code}|${country}`;
      counts.set(key, (counts.get(key) || 0) + 1);
    });

    const top = Array.from(counts.entries())
      .map(([key, count]) => {
        const [code, country] = key.split("|");
        return { code, country, count };
      })
      .sort((a, b) => b.count - a.count)
      .slice(0, 7);

    container.innerHTML = "";

    if (!top.length) {
      const empty = document.createElement("li");
      empty.textContent = "No live country telemetry yet";
      container.appendChild(empty);
      return;
    }

    top.forEach((item) => {
      const li = document.createElement("li");

      const left = document.createElement("span");
      left.className = "country-name";
      left.textContent = `${item.code} ${item.country}`;

      const right = document.createElement("span");
      right.className = "country-count";
      right.textContent = String(item.count);

      li.appendChild(left);
      li.appendChild(right);
      container.appendChild(li);
    });
  }

  function renderAttackTypes() {
    const container = document.getElementById("attackTypes");
    if (!container) {
      return;
    }

    const counts = new Map();
    state.attackHistory.forEach((attack) => {
      counts.set(attack.type, (counts.get(attack.type) || 0) + 1);
    });

    const topTypes = Array.from(counts.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 6);

    container.innerHTML = "";

    if (!topTypes.length) {
      const span = document.createElement("span");
      span.className = "type-tag";
      span.textContent = "NO ACTIVE TYPES";
      container.appendChild(span);
      return;
    }

    topTypes.forEach(([type, count]) => {
      const span = document.createElement("span");
      span.className = "type-tag";
      span.textContent = `${type} ${count}`;
      container.appendChild(span);
    });
  }

  function renderEventLog() {
    const container = document.getElementById("eventLog");
    if (!container) {
      return;
    }

    container.innerHTML = "";

    state.eventLog.slice(0, MAX_EVENT_LOG_ENTRIES).forEach((event) => {
      const li = document.createElement("li");

      const time = document.createElement("span");
      time.className = "event-time";
      time.textContent = `[${formatClock(event.timestamp)}] `;

      const type = document.createElement("span");
      type.className = "event-type";
      type.textContent = `${event.type}`;

      const text = document.createElement("span");
      text.textContent = ` | ${event.sourceCountryCode} ${event.ip} -> ${event.target.label} (${event.source})`;

      li.appendChild(time);
      li.appendChild(type);
      li.appendChild(text);
      container.appendChild(li);
    });
  }

  function updateHud(statusText) {
    const attackCounter = document.getElementById("attackCounter");
    const threatLevelText = document.getElementById("threatLevelText");
    const meterFill = document.getElementById("threatMeterFill");
    const meterValue = document.getElementById("threatMeterValue");
    const feedStatus = document.getElementById("feedStatus");
    const lastUpdated = document.getElementById("lastUpdated");

    const now = Date.now();
    state.attackHistory = state.attackHistory.filter((entry) => now - entry.timestamp <= 5 * 60 * 1000);
    const oneMinute = state.attackHistory.filter((entry) => now - entry.timestamp <= 60 * 1000);
    const attacksPerMinute = oneMinute.length;

    const level = computeThreatLevel(attacksPerMinute);

    if (attackCounter) {
      attackCounter.textContent = state.totalAttackCount.toLocaleString("en-US");
    }

    if (threatLevelText) {
      threatLevelText.textContent = level.label;
      threatLevelText.style.color = level.color;
    }

    if (meterFill) {
      meterFill.style.width = `${clamp(level.width, 0, 100)}%`;
    }

    if (meterValue) {
      meterValue.textContent = `${attacksPerMinute} attacks/min`;
    }

    if (feedStatus) {
      feedStatus.textContent = statusText;
    }

    if (lastUpdated) {
      lastUpdated.textContent = `LAST UPDATE: ${formatClock(now)}`;
    }
  }

  function switchMode() {
    state.is3DMode = !state.is3DMode;

    const mapEl = document.getElementById("map2d");
    const globeEl = document.getElementById("globe3d");
    const button = document.getElementById("modeToggle");

    if (mapEl) {
      mapEl.classList.toggle("active", !state.is3DMode);
    }
    if (globeEl) {
      globeEl.classList.toggle("active", state.is3DMode);
    }
    if (button) {
      button.textContent = state.is3DMode ? "SWITCH TO 2D MAP" : "SWITCH TO 3D GLOBE";
    }

    if (state.is3DMode) {
      state.globe3D.resize();
    } else {
      state.map2D.resize();
    }
  }

  async function refreshCycle() {
    if (state.isRefreshing) {
      return;
    }
    state.isRefreshing = true;
    state.geoLookupsUsed = 0;

    try {
      const loaded = await loadThreatRecords();
      const attacks = await buildAttackEvents(loaded.records);

      state.totalAttackCount += attacks.length;
      state.attackHistory = [...attacks, ...state.attackHistory].slice(0, 1400);
      state.eventLog = [...attacks, ...state.eventLog].slice(0, MAX_EVENT_LOG_ENTRIES);

      state.map2D.renderAttacks(attacks);
      state.globe3D.renderAttacks(attacks);

      updateHud(loaded.status);
      renderTopCountries();
      renderAttackTypes();
      renderEventLog();
    } catch (_error) {
      updateHud("FEEDS: ERROR, USING LAST KNOWN STATE");
    } finally {
      state.isRefreshing = false;
    }
  }

  function init() {
    state.map2D = new Map2DRenderer("map2d");
    state.globe3D = new GlobeRenderer("globe3d");

    state.map2D.init();
    state.globe3D.init();

    const toggleButton = document.getElementById("modeToggle");
    if (toggleButton) {
      toggleButton.addEventListener("click", switchMode);
    }

    window.addEventListener("resize", () => {
      state.map2D.resize();
      state.globe3D.resize();
    });

    refreshCycle();
    window.setInterval(refreshCycle, REFRESH_INTERVAL_MS);
  }

  document.addEventListener("DOMContentLoaded", init);
})();
