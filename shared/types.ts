// ===== Proxy Configuration =====
export interface ProxyConfig {
  port: number;
  host: string;
  enableHttps: boolean;
}

// ===== Proxy Status =====
export interface ProxyStatus {
  running: boolean;
  port: number;
  localIp: string;
  certDownloadUrl: string;
}

// ===== Captured Request =====
export interface CapturedRequest {
  id: number;
  timestamp: number;
  method: string;
  url: string;
  host: string;
  path: string;
  status: number;
  requestHeaders: Record<string, string>;
  requestBody: string | null;
  responseHeaders: Record<string, string>;
  responseBody: string | null;
  contentType: string;
  duration: number;
  size: number;
}

// ===== Database Row (raw from SQLite) =====
export interface RequestDbRow {
  id: number;
  timestamp: number;
  method: string;
  url: string;
  host: string;
  path: string;
  status: number;
  request_headers: string; // JSON string
  request_body: string | null;
  response_headers: string; // JSON string
  response_body: string | null;
  content_type: string;
  duration: number;
  size: number;
}

// ===== Filter Options =====
export interface FilterOptions {
  searchQuery?: string;
  methods?: string[];
  useRegex?: boolean;
  searchInBody?: boolean;
  searchInHeaders?: boolean;
  minSize?: number | null;
  maxSize?: number | null;
  minDuration?: number | null;
  maxDuration?: number | null;
  statusCodes?: string[];
  hosts?: string[];
  contentTypes?: string[];
  dateRange?: { start: number; end: number };
  limit?: number;
  offset?: number;
}

// ===== App Settings =====
export interface AppSettings {
  proxyPort: number;
  certServerPort: number;
  enableHttps: boolean;
  autoClearHours: number;
  darkMode: boolean;
  maxRequestBodySize: number; // bytes
  maxResponseBodySize: number; // bytes
}

// ===== QR Code Data =====
export interface QrCodeData {
  proxyIp: string;
  proxyPort: number;
  certUrl: string;
  setupInstructions: string;
}

// ===== Export Formats =====
export type ExportFormat = "har" | "json" | "curl" | "python" | "postman";

// ===== Request Composer =====
export interface ComposedRequest {
  method: string;
  url: string;
  headers: Record<string, string>;
  body?: string;
}

// ===== Breakpoint Configuration =====
export interface BreakpointConfig {
  enabled: boolean;
  breakOnRequest: boolean;
  breakOnResponse: boolean;
  urlPattern?: string; // Regex pattern to match URLs
}

// ===== Intercepted Request/Response =====
export interface InterceptedRequest {
  id: string;
  type: "request" | "response";
  timestamp: number;
  method: string;
  url: string;
  headers: Record<string, string>;
  body: string | null;
  status?: number; // Only for responses
}

// ===== Mock Rule =====
export interface MockRule {
  id: string;
  enabled: boolean;
  name: string;
  urlPattern: string; // Regex pattern
  method?: string; // Optional method filter
  responseStatus: number;
  responseHeaders: Record<string, string>;
  responseBody: string;
  delay?: number; // Optional delay in ms
}

// ===== HAR Types =====
export interface HarLog {
  version: string;
  creator: {
    name: string;
    version: string;
  };
  entries: HarEntry[];
}

export interface HarEntry {
  startedDateTime: string;
  time: number;
  request: {
    method: string;
    url: string;
    httpVersion: string;
    headers: { name: string; value: string }[];
    queryString: { name: string; value: string }[];
    postData?: {
      mimeType: string;
      text: string;
    };
    headersSize: number;
    bodySize: number;
  };
  response: {
    status: number;
    statusText: string;
    httpVersion: string;
    headers: { name: string; value: string }[];
    content: {
      size: number;
      mimeType: string;
      text?: string;
    };
    headersSize: number;
    bodySize: number;
  };
  cache: Record<string, unknown>;
  timings: {
    send: number;
    wait: number;
    receive: number;
  };
}

// ===== SSL Bypass Types =====
export interface PatchedItem {
  type:
    | "network_security_config"
    | "manifest"
    | "smali_pin_removed"
    | "smali_trust_override";
  file: string;
  description: string;
}

export interface PatchResult {
  success: boolean;
  patchedItems: PatchedItem[];
  warnings: string[];
  outputPath: string;
}

export interface DetectedPinningHost {
  host: string;
  framework: string;
  detectedAt: number;
  bypassed: boolean;
}

export type FridaArch = "arm64-v8a" | "x86_64";

export type BypassFramework =
  | "auto"
  | "okhttp3"
  | "conscrypt"
  | "webview"
  | "flutter"
  | "react-native"
  | "all";

export interface FridaLogEntry {
  timestamp: number;
  level: "info" | "success" | "error" | "warning";
  message: string;
}

// ===== IPC Channel Names =====
export const IPC_CHANNELS = {
  // Proxy control
  PROXY_START: "proxy:start",
  PROXY_STOP: "proxy:stop",
  PROXY_STATUS: "proxy:status",
  PROXY_ERROR: "proxy:error",

  // Certificate
  CERT_GET_QR: "cert:get-qr",
  CERT_GET_PATH: "cert:get-path",

  // Requests
  REQUEST_CAPTURED: "request:captured",
  REQUESTS_GET_ALL: "requests:get-all",
  REQUESTS_GET_BY_ID: "requests:get-by-id",
  REQUESTS_CLEAR: "requests:clear",
  REQUESTS_DELETE: "requests:delete",
  REQUESTS_EXPORT: "requests:export",
  REQUESTS_COUNT: "requests:count",

  // Settings
  SETTINGS_GET: "settings:get",
  SETTINGS_SAVE: "settings:save",

  // App
  APP_GET_LOCAL_IP: "app:get-local-ip",

  // Browser/Emulator
  LAUNCH_BROWSER: "app:launch-browser",
  LAUNCH_EMULATOR: "app:launch-emulator",

  // Request Replay & Composer
  REQUEST_REPLAY: "request:replay",
  REQUEST_COMPOSE: "request:compose",

  // Breakpoints
  BREAKPOINT_SET_CONFIG: "breakpoint:set-config",
  BREAKPOINT_GET_CONFIG: "breakpoint:get-config",
  BREAKPOINT_REQUEST_PENDING: "breakpoint:request-pending",
  BREAKPOINT_CONTINUE: "breakpoint:continue",
  BREAKPOINT_DROP: "breakpoint:drop",

  // Mock Rules
  MOCK_GET_RULES: "mock:get-rules",
  MOCK_ADD_RULE: "mock:add-rule",
  MOCK_UPDATE_RULE: "mock:update-rule",
  MOCK_DELETE_RULE: "mock:delete-rule",
  MOCK_TOGGLE_RULE: "mock:toggle-rule",

  // SSL Bypass
  SSL_BYPASS_PATCH_APK: "ssl-bypass:patch-apk",
  SSL_BYPASS_INJECT_GADGET: "ssl-bypass:inject-gadget",
  SSL_BYPASS_START_FRIDA: "ssl-bypass:start-frida",
  SSL_BYPASS_STOP_FRIDA: "ssl-bypass:stop-frida",
  SSL_BYPASS_GET_DETECTED_HOSTS: "ssl-bypass:get-detected-hosts",
  SSL_BYPASS_FRIDA_LOG: "ssl-bypass:frida-log",
  SSL_BYPASS_HOST_DETECTED: "ssl-bypass:host-detected",
} as const;

// ===== IPC Handler Types =====
export interface IpcApi {
  // Proxy
  startProxy: (config: ProxyConfig) => Promise<ProxyStatus>;
  stopProxy: () => Promise<void>;
  getProxyStatus: () => Promise<ProxyStatus | null>;

  // Certificate
  getQrCode: () => Promise<string>;
  getCertPath: () => Promise<string>;

  // Requests
  getRequests: (filter?: FilterOptions) => Promise<CapturedRequest[]>;
  getRequestById: (id: number) => Promise<CapturedRequest | null>;
  clearRequests: () => Promise<void>;
  deleteRequest: (id: number) => Promise<void>;
  exportRequests: (format: ExportFormat, ids?: number[]) => Promise<string>;
  getRequestCount: () => Promise<number>;

  // Settings
  getSettings: () => Promise<AppSettings>;
  saveSettings: (settings: Partial<AppSettings>) => Promise<void>;

  // App
  getLocalIp: () => Promise<string>;

  // Browser/Emulator
  launchBrowser: (browser: "chrome" | "firefox" | "edge") => Promise<boolean>;
  launchEmulator: () => Promise<boolean>;

  // Request Replay & Composer
  replayRequest: (id: number) => Promise<CapturedRequest>;
  composeRequest: (request: ComposedRequest) => Promise<CapturedRequest>;

  // Breakpoints
  setBreakpointConfig: (config: BreakpointConfig) => Promise<void>;
  getBreakpointConfig: () => Promise<BreakpointConfig>;
  continueBreakpoint: (
    id: string,
    modified?: InterceptedRequest,
  ) => Promise<void>;
  dropBreakpoint: (id: string) => Promise<void>;

  // Mock Rules
  getMockRules: () => Promise<MockRule[]>;
  addMockRule: (rule: Omit<MockRule, "id">) => Promise<MockRule>;
  updateMockRule: (id: string, rule: Partial<MockRule>) => Promise<void>;
  deleteMockRule: (id: string) => Promise<void>;
  toggleMockRule: (id: string, enabled: boolean) => Promise<void>;

  // SSL Bypass
  patchApk: (inputPath: string, outputPath: string) => Promise<PatchResult>;
  injectGadget: (
    apkPath: string,
    arch: FridaArch,
    outputPath: string,
  ) => Promise<void>;
  startFrida: (
    packageName: string,
    framework: BypassFramework,
  ) => Promise<void>;
  stopFrida: () => Promise<void>;
  getDetectedHosts: () => Promise<DetectedPinningHost[]>;

  // Events
  onRequestCaptured: (
    callback: (request: CapturedRequest) => void,
  ) => () => void;
  onProxyError: (callback: (error: string) => void) => () => void;
  onBreakpointHit: (
    callback: (intercepted: InterceptedRequest) => void,
  ) => () => void;
  onFridaLog: (callback: (log: FridaLogEntry) => void) => () => void;
  onHostDetected: (callback: (host: DetectedPinningHost) => void) => () => void;
}

// ===== Content Type Categories =====
export const CONTENT_TYPE_CATEGORIES = {
  json: ["application/json", "text/json"],
  html: ["text/html"],
  xml: ["application/xml", "text/xml"],
  text: ["text/plain", "text/css", "text/javascript", "application/javascript"],
  image: [
    "image/png",
    "image/jpeg",
    "image/gif",
    "image/webp",
    "image/svg+xml",
  ],
  binary: ["application/octet-stream", "application/pdf", "application/zip"],
  form: ["application/x-www-form-urlencoded", "multipart/form-data"],
} as const;

// ===== HTTP Methods =====
export const HTTP_METHODS = [
  "GET",
  "POST",
  "PUT",
  "PATCH",
  "DELETE",
  "HEAD",
  "OPTIONS",
  "CONNECT",
  "TRACE",
] as const;

export type HttpMethod = (typeof HTTP_METHODS)[number];

// ===== Status Code Ranges =====
export const STATUS_CODE_RANGES = {
  info: { min: 100, max: 199, label: "1xx Informational" },
  success: { min: 200, max: 299, label: "2xx Success" },
  redirect: { min: 300, max: 399, label: "3xx Redirect" },
  clientError: { min: 400, max: 499, label: "4xx Client Error" },
  serverError: { min: 500, max: 599, label: "5xx Server Error" },
} as const;

// ===== Default Settings =====
export const DEFAULT_SETTINGS: AppSettings = {
  proxyPort: 8888,
  certServerPort: 8889,
  enableHttps: true,
  autoClearHours: 24,
  darkMode: true,
  maxRequestBodySize: 1024 * 1024, // 1MB
  maxResponseBodySize: 5 * 1024 * 1024, // 5MB
};
