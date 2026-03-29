import { contextBridge, ipcRenderer } from 'electron';
import type {
  IpcApi,
  ProxyConfig,
  ProxyStatus,
  FilterOptions,
  CapturedRequest,
  AppSettings,
  ExportFormat,
  ComposedRequest,
  BreakpointConfig,
  InterceptedRequest,
  MockRule,
  PatchResult,
  FridaArch,
  BypassFramework,
  FridaLogEntry,
  DetectedPinningHost
} from '../../shared/types';
import { IPC_CHANNELS } from '../../shared/types';

// Expose protected methods that allow the renderer process to use
// the ipcRenderer without exposing the entire object
const api: IpcApi = {
  // Proxy
  startProxy: (config: ProxyConfig): Promise<ProxyStatus> => {
    return ipcRenderer.invoke(IPC_CHANNELS.PROXY_START, config);
  },
  stopProxy: (): Promise<void> => {
    return ipcRenderer.invoke(IPC_CHANNELS.PROXY_STOP);
  },
  getProxyStatus: (): Promise<ProxyStatus | null> => {
    return ipcRenderer.invoke(IPC_CHANNELS.PROXY_STATUS);
  },

  // Certificate
  getQrCode: (): Promise<string> => {
    return ipcRenderer.invoke(IPC_CHANNELS.CERT_GET_QR);
  },
  getCertPath: (): Promise<string> => {
    return ipcRenderer.invoke(IPC_CHANNELS.CERT_GET_PATH);
  },

  // Requests
  getRequests: (filter?: FilterOptions): Promise<CapturedRequest[]> => {
    return ipcRenderer.invoke(IPC_CHANNELS.REQUESTS_GET_ALL, filter);
  },
  getRequestById: (id: number): Promise<CapturedRequest | null> => {
    return ipcRenderer.invoke(IPC_CHANNELS.REQUESTS_GET_BY_ID, id);
  },
  clearRequests: (): Promise<void> => {
    return ipcRenderer.invoke(IPC_CHANNELS.REQUESTS_CLEAR);
  },
  deleteRequest: (id: number): Promise<void> => {
    return ipcRenderer.invoke(IPC_CHANNELS.REQUESTS_DELETE, id);
  },
  exportRequests: (format: ExportFormat, ids?: number[]): Promise<string> => {
    return ipcRenderer.invoke(IPC_CHANNELS.REQUESTS_EXPORT, format, ids);
  },
  getRequestCount: (): Promise<number> => {
    return ipcRenderer.invoke(IPC_CHANNELS.REQUESTS_COUNT);
  },

  // Settings
  getSettings: (): Promise<AppSettings> => {
    return ipcRenderer.invoke(IPC_CHANNELS.SETTINGS_GET);
  },
  saveSettings: (settings: Partial<AppSettings>): Promise<void> => {
    return ipcRenderer.invoke(IPC_CHANNELS.SETTINGS_SAVE, settings);
  },

  // App
  getLocalIp: (): Promise<string> => {
    return ipcRenderer.invoke(IPC_CHANNELS.APP_GET_LOCAL_IP);
  },

  // Browser/Emulator
  launchBrowser: (browser: 'chrome' | 'firefox' | 'edge'): Promise<boolean> => {
    return ipcRenderer.invoke(IPC_CHANNELS.LAUNCH_BROWSER, browser);
  },
  launchEmulator: (): Promise<boolean> => {
    return ipcRenderer.invoke(IPC_CHANNELS.LAUNCH_EMULATOR);
  },

  // Request Replay & Composer
  replayRequest: (id: number): Promise<CapturedRequest> => {
    return ipcRenderer.invoke(IPC_CHANNELS.REQUEST_REPLAY, id);
  },
  composeRequest: (request: ComposedRequest): Promise<CapturedRequest> => {
    return ipcRenderer.invoke(IPC_CHANNELS.REQUEST_COMPOSE, request);
  },

  // Breakpoints
  setBreakpointConfig: (config: BreakpointConfig): Promise<void> => {
    return ipcRenderer.invoke(IPC_CHANNELS.BREAKPOINT_SET_CONFIG, config);
  },
  getBreakpointConfig: (): Promise<BreakpointConfig> => {
    return ipcRenderer.invoke(IPC_CHANNELS.BREAKPOINT_GET_CONFIG);
  },
  continueBreakpoint: (id: string, modified?: InterceptedRequest): Promise<void> => {
    return ipcRenderer.invoke(IPC_CHANNELS.BREAKPOINT_CONTINUE, id, modified);
  },
  dropBreakpoint: (id: string): Promise<void> => {
    return ipcRenderer.invoke(IPC_CHANNELS.BREAKPOINT_DROP, id);
  },

  // Mock Rules
  getMockRules: (): Promise<MockRule[]> => {
    return ipcRenderer.invoke(IPC_CHANNELS.MOCK_GET_RULES);
  },
  addMockRule: (rule: Omit<MockRule, 'id'>): Promise<MockRule> => {
    return ipcRenderer.invoke(IPC_CHANNELS.MOCK_ADD_RULE, rule);
  },
  updateMockRule: (id: string, rule: Partial<MockRule>): Promise<void> => {
    return ipcRenderer.invoke(IPC_CHANNELS.MOCK_UPDATE_RULE, id, rule);
  },
  deleteMockRule: (id: string): Promise<void> => {
    return ipcRenderer.invoke(IPC_CHANNELS.MOCK_DELETE_RULE, id);
  },
  toggleMockRule: (id: string, enabled: boolean): Promise<void> => {
    return ipcRenderer.invoke(IPC_CHANNELS.MOCK_TOGGLE_RULE, id, enabled);
  },

  // Events
  onRequestCaptured: (callback: (request: CapturedRequest) => void) => {
    const handler = (_event: Electron.IpcRendererEvent, request: CapturedRequest) => {
      callback(request);
    };
    ipcRenderer.on(IPC_CHANNELS.REQUEST_CAPTURED, handler);
    return () => {
      ipcRenderer.removeListener(IPC_CHANNELS.REQUEST_CAPTURED, handler);
    };
  },

  onProxyError: (callback: (error: string) => void) => {
    const handler = (_event: Electron.IpcRendererEvent, error: string) => {
      callback(error);
    };
    ipcRenderer.on(IPC_CHANNELS.PROXY_ERROR, handler);
    return () => {
      ipcRenderer.removeListener(IPC_CHANNELS.PROXY_ERROR, handler);
    };
  },

  onBreakpointHit: (callback: (intercepted: InterceptedRequest) => void) => {
    const handler = (_event: Electron.IpcRendererEvent, intercepted: InterceptedRequest) => {
      callback(intercepted);
    };
    ipcRenderer.on(IPC_CHANNELS.BREAKPOINT_REQUEST_PENDING, handler);
    return () => {
      ipcRenderer.removeListener(IPC_CHANNELS.BREAKPOINT_REQUEST_PENDING, handler);
    };
  },

  // SSL Bypass
  patchApk: (inputPath: string, outputPath: string): Promise<PatchResult> => {
    return ipcRenderer.invoke(IPC_CHANNELS.SSL_BYPASS_PATCH_APK, inputPath, outputPath);
  },
  injectGadget: (apkPath: string, arch: FridaArch, outputPath: string): Promise<void> => {
    return ipcRenderer.invoke(IPC_CHANNELS.SSL_BYPASS_INJECT_GADGET, apkPath, arch, outputPath);
  },
  startFrida: (packageName: string, framework: BypassFramework): Promise<void> => {
    return ipcRenderer.invoke(IPC_CHANNELS.SSL_BYPASS_START_FRIDA, packageName, framework);
  },
  stopFrida: (): Promise<void> => {
    return ipcRenderer.invoke(IPC_CHANNELS.SSL_BYPASS_STOP_FRIDA);
  },
  getDetectedHosts: (): Promise<DetectedPinningHost[]> => {
    return ipcRenderer.invoke(IPC_CHANNELS.SSL_BYPASS_GET_DETECTED_HOSTS);
  },

  // SSL Bypass Events
  onFridaLog: (callback: (log: FridaLogEntry) => void) => {
    const handler = (_event: Electron.IpcRendererEvent, log: FridaLogEntry) => {
      callback(log);
    };
    ipcRenderer.on(IPC_CHANNELS.SSL_BYPASS_FRIDA_LOG, handler);
    return () => {
      ipcRenderer.removeListener(IPC_CHANNELS.SSL_BYPASS_FRIDA_LOG, handler);
    };
  },
  onHostDetected: (callback: (host: DetectedPinningHost) => void) => {
    const handler = (_event: Electron.IpcRendererEvent, host: DetectedPinningHost) => {
      callback(host);
    };
    ipcRenderer.on(IPC_CHANNELS.SSL_BYPASS_HOST_DETECTED, handler);
    return () => {
      ipcRenderer.removeListener(IPC_CHANNELS.SSL_BYPASS_HOST_DETECTED, handler);
    };
  },
};

// Expose the API to the renderer process
contextBridge.exposeInMainWorld('electronAPI', api);

// Type declaration for renderer process
declare global {
  interface Window {
    electronAPI: IpcApi;
  }
}
