# Trafexia - Mobile Traffic Interceptor

A powerful desktop application for intercepting and analyzing HTTP/HTTPS traffic from mobile devices. Built with Electron, Vue 3, and TypeScript.

![Trafexia Screenshot](docs/screenshot.png)

## Features

- **MITM Proxy Server** - Intercept HTTP/HTTPS traffic on port 8888
- **Auto CA Certificate Generation** - Creates and manages SSL certificates for HTTPS interception
- **QR Code Setup** - Easy mobile device configuration via QR code scanning
- **Real-time Request Capture** - Live updates as requests are captured
- **Advanced Filtering** - Filter by method, status, host, content type
- **Request Details** - View headers, body, timing with syntax highlighting
- **Pattern Detection** - Auto-detect JWT tokens, API keys, Base64 strings
- **Export Options** - Export as HAR, cURL, Python code, Postman collection
- **Dark Mode** - Beautiful dark theme UI

## Tech Stack

- **Electron** - Cross-platform desktop framework
- **Vue 3** - Composition API with TypeScript
- **TailwindCSS** - Utility-first CSS
- **PrimeVue** - UI component library
- **Pinia** - State management
- **better-sqlite3** - Fast SQLite database
- **node-forge** - Certificate generation

## Getting Started

### Prerequisites

- Node.js 18+
- npm or yarn

### Installation

```bash
# Clone the repository
git clone https://github.com/danieldev23/trafexia.git
cd trafexia

# Install dependencies
npm install

# Start development
npm run dev
```

### Building

```bash
# Build for current platform
npm run build

# Build for specific platforms
npm run build:mac
npm run build:win
```

### Automated Releases (CI/CD)

Releases are automatically built when you push a version tag:

```bash
# Create a new release
git tag v1.0.1
git push origin v1.0.1
```

GitHub Actions will build for macOS, Windows, and Linux, then upload to [Releases](https://github.com/danieldev23/trafexia/releases).

## Download

📥 **[Download Latest Release](https://github.com/danieldev23/trafexia/releases/latest)**

| Platform | File |
|----------|------|
| macOS | `Trafexia-x.x.x.dmg` |
| Windows | `Trafexia-Setup-x.x.x.exe` |
| Linux | `Trafexia-x.x.x.AppImage` |

## Usage

1. **Start the Proxy** - Click "Start Proxy" to begin intercepting traffic
2. **Scan QR Code** - Use your mobile device to scan the displayed QR code
3. **Install Certificate** - Follow the setup instructions to install the CA certificate
4. **Configure Proxy** - Set up your mobile device to use the proxy
5. **Capture Traffic** - All HTTP/HTTPS traffic will be captured and displayed

### Mobile Setup

#### Android
1. Go to Settings → WiFi → Long press network → Modify → Advanced → Proxy: Manual
2. Enter the proxy IP and port (shown in the app)
3. Download and install the CA certificate
4. Settings → Security → Install from storage → Select the certificate

#### iOS
1. Go to Settings → WiFi → Tap (i) next to network → Configure Proxy → Manual
2. Enter the proxy IP and port
3. Download the CA certificate
4. Settings → General → Profile → Install the profile
5. Settings → General → About → Certificate Trust Settings → Enable the certificate

## Security Notice

⚠️ **Warning**: Installing a CA certificate allows traffic interception. Only use this for development and reverse engineering on your own devices. Remove the certificate when not in use.

## Support

If you find this project helpful, consider supporting me:

<a href="https://buymeacoffee.com/huypc9294" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" style="height: 50px !important;width: 180px !important;" ></a>

## License

MIT License - See [LICENSE](LICENSE) for details.
