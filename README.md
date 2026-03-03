# Live Vulnerability Map

> A lightweight, interactive map that visualizes live security threats and vulnerability data.

## Link
https://rishwebb.github.io/Live-Vulnerability-Map/

## Features

- Clean, dependency-free frontend (HTML/CSS/JS)
- Loads threat sample data from `sample-threat-data.json`
- Interactive map and markers driven by `main.js`
- Simple styling via `style.css`

## Files

- `index.html` — main entry
- `main.js` — application logic
- `style.css` — styles
- `sample-threat-data.json` — example data feed

## Run locally

1. Open the project folder in a browser, or run a simple static server:

```bash
# Python 3
python3 -m http.server 8000
# then open http://localhost:8000 in your browser
```

2. The app reads `sample-threat-data.json` for demo data. Replace it with your own feed as needed.

## Development

- Edit `main.js` to change data parsing or visualization
- Keep data files small during development for faster reloads

## Security

Do NOT commit secrets or personal access tokens. If you accidentally shared a token, revoke it immediately at https://github.com/settings/tokens and rotate credentials.

## Contributing

Contributions welcome — open an issue or submit a pull request with a clear description and demo steps.

## License

MIT
