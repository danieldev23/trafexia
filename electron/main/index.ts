import { app, BrowserWindow, shell } from 'electron';
import { join } from 'path';
import { CertificateManager } from './services/CertificateManager';
import { ProxyServer } from './services/ProxyServer';
import { TrafficStorage } from './services/TrafficStorage';
import { CertServer } from './services/CertServer';
import { BreakpointService } from './services/BreakpointService';
import { MockService } from './services/MockService';
import { RequestComposer } from './services/RequestComposer';
import { setupIpcHandlers } from './ipc-handlers';
import { setupSslBypassIpc, cleanupFridaProcess } from '../ssl-bypass/ssl-bypass-ipc';
import { getLocalIp } from './utils/network';

// Services
let certificateManager: CertificateManager;
let proxyServer: ProxyServer;
let trafficStorage: TrafficStorage;
let certServer: CertServer;
let breakpointService: BreakpointService;
let mockService: MockService;
let requestComposer: RequestComposer;
let mainWindow: BrowserWindow | null = null;

// Disable hardware acceleration for better compatibility
app.disableHardwareAcceleration();

const createWindow = () => {
  // Create the browser window.
  mainWindow = new BrowserWindow({
    resizable: true,
    title: 'Trafexia - Mobile Traffic Interceptor',
    icon: join(__dirname, '../resources/icons/icon.png'),
    webPreferences: {
      preload: join(__dirname, '../preload/index.js'),
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: false, // Required for native modules
    },
    titleBarStyle: 'hiddenInset',
    trafficLightPosition: { x: 15, y: 15 },
    backgroundColor: '#0d1117',
    show: false,
  });

  // Show window when ready
  mainWindow.once('ready-to-show', () => {
    mainWindow?.show();
  });

  // Open external links in browser
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    shell.openExternal(url);
    return { action: 'deny' };
  });

  // Load the app
  if (process.env.VITE_DEV_SERVER_URL) {
    mainWindow.loadURL(process.env.VITE_DEV_SERVER_URL);
    mainWindow.webContents.openDevTools();
  } else {
    mainWindow.loadFile(join(__dirname, '../../dist/index.html'));
  }
};

// Initialize services
const initializeServices = async () => {
  const userDataPath = app.getPath('userData');

  // Initialize certificate manager
  certificateManager = new CertificateManager(userDataPath);
  await certificateManager.initialize();

  // Initialize traffic storage
  trafficStorage = new TrafficStorage(userDataPath);
  await trafficStorage.initialize();

  // Initialize cert server
  certServer = new CertServer(certificateManager, getLocalIp);

  // Initialize new services
  breakpointService = new BreakpointService();
  mockService = new MockService(trafficStorage);
  requestComposer = new RequestComposer();

  // Load mock rules from database
  await mockService.loadRules();

  // Initialize proxy server with new services
  proxyServer = new ProxyServer(certificateManager, trafficStorage, breakpointService, mockService);

  // Register breakpoint events only after renderer is fully ready
  // Prevents mainWindow.webContents.send from firing too early
  mainWindow.on('ready-to-show', () => {
    breakpointService.on('breakpoint:hit', (intercepted) => {
      if (mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.webContents.send('breakpoint:request-pending', intercepted);
      };
    });
  });

  // Setup IPC handlers
  setupIpcHandlers({
    certificateManager,
    proxyServer,
    trafficStorage,
    certServer,
    breakpointService,
    mockService,
    requestComposer,
    mainWindow: () => mainWindow,
  });

  // Setup SSL bypass IPC handlers
  setupSslBypassIpc(() => mainWindow);

  console.log('[Main] Services initialized');
};

// This method will be called when Electron has finished initialization
app.whenReady().then(async () => {
  await initializeServices();
  createWindow();

  // On macOS, re-create window when dock icon is clicked
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

// Quit when all windows are closed, except on macOS
app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

// Cleanup on quit
app.on('before-quit', async () => {
  console.log('[Main] Cleaning up before quit...');

  try {
    // Stop proxy server
    if (proxyServer?.isRunning()) {
      await proxyServer.stop();
    }

    // Stop cert server
    if (certServer?.isRunning()) {
      await certServer.stop();
    }

    // Close database
    if (trafficStorage) {
      trafficStorage.close();
    }

    // Cleanup Frida process
    cleanupFridaProcess();
  } catch (error) {
    console.error('[Main] Cleanup error:', error);
  }
});

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
  console.error('[Main] Uncaught exception:', error);
});

process.on('unhandledRejection', (reason) => {
  console.error('[Main] Unhandled rejection:', reason);
});
