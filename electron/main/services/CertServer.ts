import express, { Express, Request, Response } from 'express';
import * as http from 'http';
import * as QRCode from 'qrcode';
import type { CertificateManager } from './CertificateManager';
import type { QrCodeData } from '../../../shared/types';

export class CertServer {
  private app: Express;
  private server: http.Server | null = null;
  private certManager: CertificateManager;
  private getLocalIp: () => string;
  private port = 8889;
  private running = false;

  constructor(certManager: CertificateManager, getLocalIp: () => string) {
    this.certManager = certManager;
    this.getLocalIp = getLocalIp;
    this.app = express();
    this.setupRoutes();
  }

  /**
   * Setup Express routes
   */
  private setupRoutes(): void {
    // CORS middleware
    this.app.use((_req, res, next) => {
      res.header('Access-Control-Allow-Origin', '*');
      res.header('Access-Control-Allow-Methods', 'GET, OPTIONS');
      res.header('Access-Control-Allow-Headers', 'Content-Type');
      next();
    });

    // Certificate download (PEM format)
    this.app.get('/cert', (_req: Request, res: Response) => {
      try {
        const certPem = this.certManager.getCertPem();
        res.setHeader('Content-Type', 'application/x-pem-file');
        res.setHeader('Content-Disposition', 'attachment; filename="TrafexiaCA.pem"');
        res.send(certPem);
      } catch (err) {
        res.status(500).send('Failed to get certificate');
      }
    });

    // Certificate download (DER format for mobile)
    this.app.get('/cert.der', (_req: Request, res: Response) => {
      try {
        const certDer = this.certManager.getCertDer();
        res.setHeader('Content-Type', 'application/x-x509-ca-cert');
        res.setHeader('Content-Disposition', 'attachment; filename="TrafexiaCA.der"');
        res.send(certDer);
      } catch (err) {
        res.status(500).send('Failed to get certificate');
      }
    });

    // Certificate download (CRT format - best for Android)
    this.app.get('/cert.crt', (_req: Request, res: Response) => {
      try {
        const certDer = this.certManager.getCertDer();
        res.setHeader('Content-Type', 'application/x-x509-ca-cert');
        res.setHeader('Content-Disposition', 'attachment; filename="TrafexiaCA.crt"');
        res.send(certDer);
      } catch (err) {
        res.status(500).send('Failed to get certificate');
      }
    });

    // Setup instructions page
    this.app.get('/setup', (_req: Request, res: Response) => {
      const localIp = this.getLocalIp();
      const html = this.getSetupHtml(localIp);
      res.setHeader('Content-Type', 'text/html');
      res.send(html);
    });

    // Health check
    this.app.get('/health', (_req: Request, res: Response) => {
      res.json({ status: 'ok', port: this.port });
    });

    // Root redirect to setup
    this.app.get('/', (_req: Request, res: Response) => {
      res.redirect('/setup');
    });
  }

  /**
   * Start the certificate server
   */
  async start(port?: number): Promise<void> {
    if (this.running) return;

    if (port) this.port = port;

    return new Promise((resolve, reject) => {
      this.server = this.app.listen(this.port, '0.0.0.0', () => {
        this.running = true;
        console.log(`[CertServer] Started on port ${this.port}`);
        resolve();
      });

      this.server.on('error', (err) => {
        reject(err);
      });
    });
  }

  /**
   * Stop the certificate server
   */
  async stop(): Promise<void> {
    return new Promise((resolve) => {
      if (!this.server || !this.running) {
        resolve();
        return;
      }

      this.server.close(() => {
        this.running = false;
        this.server = null;
        console.log('[CertServer] Stopped');
        resolve();
      });
    });
  }

  /**
   * Check if server is running
   */
  isRunning(): boolean {
    return this.running;
  }

  /**
   * Generate QR code containing setup info
   */
  async generateQrCode(proxyPort: number): Promise<string> {
    const localIp = this.getLocalIp();

    const qrData: QrCodeData = {
      proxyIp: localIp,
      proxyPort: proxyPort,
      certUrl: `http://${localIp}:${this.port}/cert`,
      setupInstructions: `http://${localIp}:${this.port}/setup`,
    };

    // Generate QR code as data URL (base64)
    const qrCodeDataUrl = await QRCode.toDataURL(JSON.stringify(qrData), {
      width: 300,
      margin: 2,
      color: {
        dark: '#0f172a',
        light: '#ffffff',
      },
    });

    return qrCodeDataUrl;
  }

  /**
   * Generate QR code for direct URL access
   */
  async generateSimpleQrCode(_proxyPort: number): Promise<string> {
    const localIp = this.getLocalIp();
    const setupUrl = `http://${localIp}:${this.port}/setup`;

    const qrCodeDataUrl = await QRCode.toDataURL(setupUrl, {
      width: 300,
      margin: 2,
      color: {
        dark: '#0f172a',
        light: '#ffffff',
      },
    });

    return qrCodeDataUrl;
  }

  /**
   * Get setup page HTML
   */
  private getSetupHtml(localIp: string): string {
    return `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Trafexia - Mobile Setup</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
      min-height: 100vh;
      color: #e2e8f0;
      padding: 20px;
    }
    .container {
      max-width: 600px;
      margin: 0 auto;
    }
    .header {
      text-align: center;
      padding: 30px 0;
    }
    .logo {
      font-size: 2.5rem;
      font-weight: 700;
      background: linear-gradient(135deg, #38bdf8 0%, #818cf8 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      margin-bottom: 10px;
    }
    .subtitle {
      color: #94a3b8;
      font-size: 1rem;
    }
    .card {
      background: rgba(30, 41, 59, 0.8);
      border-radius: 16px;
      padding: 24px;
      margin-bottom: 20px;
      border: 1px solid rgba(71, 85, 105, 0.5);
    }
    .card-title {
      font-size: 1.25rem;
      font-weight: 600;
      margin-bottom: 16px;
      display: flex;
      align-items: center;
      gap: 10px;
    }
    .step {
      display: flex;
      gap: 16px;
      margin-bottom: 16px;
    }
    .step-number {
      width: 32px;
      height: 32px;
      background: linear-gradient(135deg, #0ea5e9 0%, #6366f1 100%);
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      font-weight: 600;
      flex-shrink: 0;
    }
    .step-content {
      flex: 1;
    }
    .step-title {
      font-weight: 600;
      margin-bottom: 4px;
    }
    .step-desc {
      color: #94a3b8;
      font-size: 0.9rem;
    }
    .info-box {
      background: rgba(14, 165, 233, 0.1);
      border: 1px solid rgba(14, 165, 233, 0.3);
      border-radius: 12px;
      padding: 16px;
      margin: 16px 0;
    }
    .info-label {
      font-size: 0.8rem;
      color: #38bdf8;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      margin-bottom: 4px;
    }
    .info-value {
      font-size: 1.5rem;
      font-weight: 600;
      font-family: 'SF Mono', Monaco, monospace;
    }
    .btn {
      display: inline-block;
      background: linear-gradient(135deg, #0ea5e9 0%, #6366f1 100%);
      color: white;
      padding: 14px 28px;
      border-radius: 12px;
      text-decoration: none;
      font-weight: 600;
      text-align: center;
      transition: transform 0.2s, box-shadow 0.2s;
      width: 100%;
    }
    .btn:hover {
      transform: translateY(-2px);
      box-shadow: 0 10px 20px rgba(14, 165, 233, 0.3);
    }
    .tabs {
      display: flex;
      gap: 8px;
      margin-bottom: 16px;
    }
    .tab {
      flex: 1;
      padding: 12px;
      background: rgba(71, 85, 105, 0.3);
      border: none;
      border-radius: 8px;
      color: #94a3b8;
      cursor: pointer;
      font-weight: 500;
      transition: all 0.2s;
    }
    .tab.active {
      background: rgba(14, 165, 233, 0.2);
      color: #38bdf8;
    }
    .tab-content {
      display: none;
    }
    .tab-content.active {
      display: block;
    }
    .warning {
      background: rgba(245, 158, 11, 0.1);
      border: 1px solid rgba(245, 158, 11, 0.3);
      border-radius: 12px;
      padding: 16px;
      margin-top: 20px;
    }
    .warning-title {
      color: #fbbf24;
      font-weight: 600;
      margin-bottom: 8px;
    }
    .warning-text {
      color: #94a3b8;
      font-size: 0.9rem;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div class="logo">Trafexia</div>
      <div class="subtitle">Mobile Traffic Interceptor</div>
    </div>

    <div class="card">
      <div class="card-title">📱 Proxy Settings</div>
      <div class="info-box">
        <div class="info-label">Proxy Server</div>
        <div class="info-value">${localIp}:8888</div>
      </div>
      <p style="color: #94a3b8; font-size: 0.9rem;">
        Configure your mobile device to use this proxy in WiFi settings.
      </p>
    </div>

    <div class="card">
      <div class="card-title">🔐 Install CA Certificate</div>
      <div style="display: flex; gap: 10px; flex-wrap: wrap;">
        <a href="/cert.crt" class="btn" style="flex: 1;" download="TrafexiaCA.crt">
          📱 Android (.crt)
        </a>
        <a href="/cert" class="btn" style="flex: 1; background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%);" download="TrafexiaCA.pem">
          🍎 iOS (.pem)
        </a>
      </div>
      <p style="color: #94a3b8; font-size: 0.9rem; margin-top: 12px; text-align: center;">
        You must install and trust this certificate to intercept HTTPS traffic.
      </p>
    </div>

    <div class="card">
      <div class="card-title">📋 Setup Instructions</div>
      
      <div class="tabs">
        <button class="tab active" onclick="showTab('android')">Android</button>
        <button class="tab" onclick="showTab('ios')">iOS</button>
      </div>

      <div id="android" class="tab-content active">
        <div style="background: rgba(245, 158, 11, 0.15); border: 1px solid rgba(245, 158, 11, 0.4); border-radius: 8px; padding: 12px; margin-bottom: 16px;">
          <div style="color: #fbbf24; font-weight: 600; font-size: 0.85rem;">⚠️ Android 7+ Notice</div>
          <div style="color: #94a3b8; font-size: 0.8rem; margin-top: 4px;">Apps on Android 7+ don't trust user-installed certificates. Use <b>Chrome browser</b> for testing, or use <b>Android Emulator</b> (recommended).</div>
        </div>
        <div class="step">
          <div class="step-number">1</div>
          <div class="step-content">
            <div class="step-title">Configure Proxy</div>
            <div class="step-desc">Settings → WiFi → Long press network → Modify → Advanced → Proxy: Manual → Enter ${localIp}:8888</div>
          </div>
        </div>
        <div class="step">
          <div class="step-number">2</div>
          <div class="step-content">
            <div class="step-title">Download Certificate (.crt)</div>
            <div class="step-desc">Click the "Android (.crt)" button above to download.</div>
          </div>
        </div>
        <div class="step">
          <div class="step-number">3</div>
          <div class="step-content">
            <div class="step-title">Install Certificate</div>
            <div class="step-desc">Settings → Security → Encryption & credentials → Install a certificate → CA certificate → Select TrafexiaCA.crt</div>
          </div>
        </div>
        <div style="background: rgba(14, 165, 233, 0.1); border: 1px solid rgba(14, 165, 233, 0.3); border-radius: 8px; padding: 12px; margin-top: 16px;">
          <div style="color: #38bdf8; font-weight: 600; font-size: 0.85rem;">💡 Using Android Emulator?</div>
          <div style="color: #94a3b8; font-size: 0.8rem; margin-top: 4px;">Run: <code style="background: rgba(0,0,0,0.3); padding: 2px 6px; border-radius: 4px;">adb shell settings put global http_proxy ${localIp}:8888</code></div>
        </div>
      </div>

      <div id="ios" class="tab-content">
        <div class="step">
          <div class="step-number">1</div>
          <div class="step-content">
            <div class="step-title">Configure Proxy</div>
            <div class="step-desc">Settings → WiFi → Tap (i) next to network → Configure Proxy → Manual → Enter ${localIp}:8888</div>
          </div>
        </div>
        <div class="step">
          <div class="step-number">2</div>
          <div class="step-content">
            <div class="step-title">Download Certificate</div>
            <div class="step-desc">Click the download button above. Safari will prompt to install the profile.</div>
          </div>
        </div>
        <div class="step">
          <div class="step-number">3</div>
          <div class="step-content">
            <div class="step-title">Install Profile</div>
            <div class="step-desc">Settings → General → Profile → Trafexia CA → Install</div>
          </div>
        </div>
        <div class="step">
          <div class="step-number">4</div>
          <div class="step-content">
            <div class="step-title">Trust Certificate</div>
            <div class="step-desc">Settings → General → About → Certificate Trust Settings → Enable "Trafexia Root CA"</div>
          </div>
        </div>
      </div>
    </div>

    <div class="warning">
      <div class="warning-title">⚠️ Security Notice</div>
      <div class="warning-text">
        Installing this CA certificate allows Trafexia to intercept HTTPS traffic. 
        Only use this for development and reverse engineering purposes on your own devices and apps.
        Remove the certificate when not in use.
      </div>
    </div>
  </div>

  <script>
    function showTab(tabId) {
      document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
      document.querySelector('.tab[onclick*="' + tabId + '"]').classList.add('active');
      document.getElementById(tabId).classList.add('active');
    }
  </script>
</body>
</html>
    `;
  }
}
