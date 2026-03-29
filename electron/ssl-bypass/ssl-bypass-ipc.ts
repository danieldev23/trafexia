/**
 * SSL Bypass IPC Bridge — registers ipcMain handlers for all
 * ssl-bypass:* channels and manages the Frida child process lifecycle.
 *
 * Key design: the Frida process stdout/stderr is piped to the renderer
 * via webContents.send so the UI can show a live log console.
 */

import { ipcMain, BrowserWindow, app } from "electron";
import { ChildProcess, spawn } from "child_process";
import * as path from "path";
import { patchAPK } from "./apk-patcher";
import { injectGadget } from "./frida-injector";
import { getBypassScript } from "./bypass-scripts";
import { SslBypassRule } from "./ssl-bypass-rule";
import { IPC_CHANNELS } from "../../shared/types";
import type {
  FridaArch,
  BypassFramework,
  FridaLogEntry,
} from "../../shared/types";

/** Active Frida child process */
let fridaProcess: ChildProcess | null = null;

/** SSL bypass rule instance */
let sslBypassRule: SslBypassRule | null = null;

/**
 * Setup all SSL bypass IPC handlers.
 */
export function setupSslBypassIpc(
  mainWindow: () => BrowserWindow | null,
): SslBypassRule {
  sslBypassRule = new SslBypassRule();

  // === Patch APK ===
  ipcMain.handle(
    IPC_CHANNELS.SSL_BYPASS_PATCH_APK,
    async (_event, inputPath: string, outputPath: string) => {
      try {
        console.log(`[SSL-Bypass-IPC] Patching APK: ${inputPath}`);
        const result = await patchAPK(inputPath, outputPath);
        console.log(
          `[SSL-Bypass-IPC] Patch result: ${result.success ? "success" : "failed"}, ${result.patchedItems.length} items patched`,
        );
        return result;
      } catch (error) {
        console.error("[SSL-Bypass-IPC] Failed to patch APK:", error);
        throw error;
      }
    },
  );

  // === Inject Frida Gadget ===
  ipcMain.handle(
    IPC_CHANNELS.SSL_BYPASS_INJECT_GADGET,
    async (_event, apkPath: string, arch: FridaArch, outputPath: string) => {
      try {
        const cacheDir = path.join(app.getPath("userData"), "frida-gadgets");
        console.log(
          `[SSL-Bypass-IPC] Injecting gadget (${arch}) into: ${apkPath}`,
        );
        await injectGadget(apkPath, arch, outputPath, cacheDir);
        console.log("[SSL-Bypass-IPC] Gadget injection complete");
      } catch (error) {
        console.error("[SSL-Bypass-IPC] Failed to inject gadget:", error);
        throw error;
      }
    },
  );

  // === Start Frida ===
  ipcMain.handle(
    IPC_CHANNELS.SSL_BYPASS_START_FRIDA,
    async (_event, packageName: string, framework: BypassFramework) => {
      try {
        if (fridaProcess) {
          throw new Error("Frida is already running. Stop it first.");
        }

        const script = getBypassScript(framework);

        // Write script to temp file
        const fs = await import("fs");
        const os = await import("os");
        const scriptPath = path.join(os.tmpdir(), "trafexia-bypass.js");
        fs.writeFileSync(scriptPath, script, "utf-8");

        console.log(
          `[SSL-Bypass-IPC] Starting Frida for ${packageName} with ${framework} bypass`,
        );

        // Resolve frida binary path
        const fridaPath = await resolveFridaPath();
        console.log(`[SSL-Bypass-IPC] Using Frida binary: ${fridaPath}`);

        // Spawn frida process
        // frida -U -f <package> -l <script>
        fridaProcess = spawn(
          fridaPath,
          [
            "-U", // USB device
            "-f",
            packageName, // Spawn app
            "-l",
            scriptPath, // Load script
          ],
          {
            stdio: ["pipe", "pipe", "pipe"],
          },
        );

        const win = mainWindow();

        const sendLog = (level: FridaLogEntry["level"], message: string) => {
          const log: FridaLogEntry = {
            timestamp: Date.now(),
            level,
            message: message.trim(),
          };
          if (win && !win.isDestroyed()) {
            win.webContents.send(IPC_CHANNELS.SSL_BYPASS_FRIDA_LOG, log);
          }
        };

        fridaProcess.stdout?.on("data", (data: Buffer) => {
          const text = data.toString("utf-8");
          // Parse Frida output for log levels
          const lines = text.split("\n").filter((l) => l.trim());
          for (const line of lines) {
            if (line.includes("[+]")) {
              sendLog("success", line);
            } else if (line.includes("[-]")) {
              sendLog("error", line);
            } else if (line.includes("[!]") || line.includes("[*]")) {
              sendLog("warning", line);
            } else {
              sendLog("info", line);
            }
          }
        });

        fridaProcess.stderr?.on("data", (data: Buffer) => {
          const text = data.toString("utf-8").trim();
          if (text) {
            sendLog("error", text);
          }
        });

        fridaProcess.on("error", (err) => {
          const message = err.message.includes("ENOENT")
            ? `frida command not found at '${fridaPath}'. Install it with: pip install frida-tools`
            : err.message;
          sendLog("error", `[Frida Process Error] ${message}`);
          fridaProcess = null;
        });

        fridaProcess.on("close", (code) => {
          sendLog(
            "info",
            `[Frida Process] Exited with code ${code ?? "unknown"}`,
          );
          fridaProcess = null;
        });

        console.log(
          "[SSL-Bypass-IPC] Frida process started, PID:",
          fridaProcess.pid,
        );
      } catch (error) {
        console.error("[SSL-Bypass-IPC] Failed to start Frida:", error);
        fridaProcess = null;
        throw error;
      }
    },
  );

  // === Stop Frida ===
  ipcMain.handle(IPC_CHANNELS.SSL_BYPASS_STOP_FRIDA, async () => {
    try {
      if (fridaProcess) {
        console.log("[SSL-Bypass-IPC] Stopping Frida process...");
        fridaProcess.kill("SIGTERM");

        // Force kill after 3 seconds if still running
        const killTimeout = setTimeout(() => {
          if (fridaProcess) {
            fridaProcess.kill("SIGKILL");
            fridaProcess = null;
          }
        }, 3000);

        fridaProcess.on("close", () => {
          clearTimeout(killTimeout);
          fridaProcess = null;
        });
      }
    } catch (error) {
      console.error("[SSL-Bypass-IPC] Failed to stop Frida:", error);
      fridaProcess = null;
      throw error;
    }
  });

  // === Get Detected Hosts ===
  ipcMain.handle(IPC_CHANNELS.SSL_BYPASS_GET_DETECTED_HOSTS, async () => {
    return sslBypassRule?.getDetectedHosts() ?? [];
  });

  return sslBypassRule;
}

/**
 * Cleanup Frida process — call this from app.on('before-quit').
 */
export function cleanupFridaProcess(): void {
  if (fridaProcess) {
    console.log("[SSL-Bypass-IPC] Cleaning up Frida process...");
    try {
      fridaProcess.kill("SIGKILL");
    } catch {
      // Ignore errors during cleanup
    }
    fridaProcess = null;
  }
}

/**
 * Get the current SslBypassRule instance.
 */
export function getSslBypassRule(): SslBypassRule | null {
  return sslBypassRule;
}

/**
 * Resolve the path to the frida binary.
 * Checks system PATH first, then common Python/Homebrew locations.
 */
async function resolveFridaPath(): Promise<string> {
  const { execSync } = await import("child_process");
  const fs = await import("fs");
  const os = await import("os");

  // 1. Try global PATH
  try {
    execSync("frida --version", { stdio: "ignore" });
    return "frida";
  } catch {
    // Not in PATH
  }

  // 2. Common locations
  const home = os.homedir();
  const potentialPaths = [
    // Python user-base bins (macOS)
    path.join(home, "Library/Python/3.9/bin/frida"),
    path.join(home, "Library/Python/3.8/bin/frida"),
    path.join(home, "Library/Python/3.10/bin/frida"),
    path.join(home, "Library/Python/3.11/bin/frida"),
    path.join(home, "Library/Python/3.12/bin/frida"),
    // Homebrew
    "/opt/homebrew/bin/frida",
    "/usr/local/bin/frida",
    // Python Linux
    path.join(home, ".local/bin/frida"),
  ];

  for (const p of potentialPaths) {
    if (fs.existsSync(p)) {
      return p;
    }
  }

  // Fallback to 'frida' and let spawn fail with ENOENT
  return "frida";
}
