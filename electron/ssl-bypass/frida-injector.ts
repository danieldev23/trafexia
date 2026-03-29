/**
 * Frida Gadget Injector — injects frida-gadget.so into an APK.
 *
 * Key technique: download the gadget from GitHub releases, inject it
 * into lib/<arch>/ inside the APK, and patch the Application class
 * smali to call System.loadLibrary("frida-gadget") early.
 *
 * The gadget config uses "listen" mode so Trafexia can connect to it.
 */

import * as path from "path";
import * as fs from "fs";
import * as https from "https";
import AdmZip from "adm-zip";
import type { FridaArch } from "../../shared/types";

/** Default Frida version to download */
const DEFAULT_FRIDA_VERSION = "16.1.4";

/** Gadget config: listen mode on all interfaces */
const GADGET_CONFIG = JSON.stringify(
  {
    interaction: {
      type: "listen",
      address: "0.0.0.0",
      port: 27042,
      on_port_conflict: "pick-next",
      on_load: "wait",
    },
  },
  null,
  2,
);

/**
 * Map of arch identifiers to GitHub release filenames.
 */
function getGadgetFilename(arch: FridaArch, version: string): string {
  const archMap: Record<FridaArch, string> = {
    "arm64-v8a": `frida-gadget-${version}-android-arm64.so`,
    x86_64: `frida-gadget-${version}-android-x86_64.so`,
  };
  return archMap[arch];
}

function getGadgetUrl(arch: FridaArch, version: string): string {
  const filename = getGadgetFilename(arch, version);
  return `https://github.com/frida/frida/releases/download/${version}/${filename}.xz`;
}

/**
 * Download a file from a URL, following redirects (GitHub releases use 302).
 */
function downloadFile(url: string, destPath: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const file = fs.createWriteStream(destPath);

    const doRequest = (reqUrl: string, redirectCount: number) => {
      if (redirectCount > 5) {
        reject(new Error("Too many redirects"));
        return;
      }

      https
        .get(reqUrl, (response) => {
          // Handle redirects
          if (
            response.statusCode &&
            response.statusCode >= 300 &&
            response.statusCode < 400 &&
            response.headers.location
          ) {
            response.destroy();
            doRequest(response.headers.location, redirectCount + 1);
            return;
          }

          if (response.statusCode !== 200) {
            response.destroy();
            reject(
              new Error(`HTTP ${response.statusCode} downloading ${reqUrl}`),
            );
            return;
          }

          response.pipe(file);
          file.on("finish", () => {
            file.close();
            resolve();
          });
        })
        .on("error", (err) => {
          fs.unlink(destPath, () => {
            /* ignore cleanup error */
          });
          reject(err);
        });
    };

    doRequest(url, 0);
  });
}

/**
 * Decompress an .xz file using the native xz command.
 * Falls back to returning the raw file if xz is not available.
 */
async function decompressXz(xzPath: string, outputPath: string): Promise<void> {
  const { exec } = await import("child_process");
  const { promisify } = await import("util");
  const execAsync = promisify(exec);

  try {
    // Try using system xz command
    await execAsync(`xz -dk "${xzPath}" -c > "${outputPath}"`);
  } catch {
    // If xz is not available, try unxz
    try {
      await execAsync(`unxz -k "${xzPath}" -c > "${outputPath}"`);
    } catch {
      throw new Error(
        "xz decompression tool not found. Please install xz:\n" +
          "  macOS: brew install xz\n" +
          "  Linux: sudo apt install xz-utils\n" +
          "  Windows: install 7-Zip or xz from https://tukaani.org/xz/",
      );
    }
  }
}

/**
 * Get or download the Frida Gadget for the specified architecture.
 *
 * Gadgets are cached in the provided cache directory.
 */
async function getGadget(
  arch: FridaArch,
  cacheDir: string,
  version: string = DEFAULT_FRIDA_VERSION,
): Promise<string> {
  const gadgetFilename = `frida-gadget-${version}-android-${arch === "arm64-v8a" ? "arm64" : "x86_64"}.so`;
  const cachedPath = path.join(cacheDir, gadgetFilename);

  if (fs.existsSync(cachedPath)) {
    console.log(`[FridaInjector] Using cached gadget: ${cachedPath}`);
    return cachedPath;
  }

  // Ensure cache directory exists
  if (!fs.existsSync(cacheDir)) {
    fs.mkdirSync(cacheDir, { recursive: true });
  }

  const url = getGadgetUrl(arch, version);
  const xzPath = cachedPath + ".xz";

  console.log(`[FridaInjector] Downloading gadget from: ${url}`);
  await downloadFile(url, xzPath);

  console.log(`[FridaInjector] Decompressing gadget...`);
  await decompressXz(xzPath, cachedPath);

  // Cleanup .xz
  if (fs.existsSync(xzPath)) {
    fs.unlinkSync(xzPath);
  }

  if (!fs.existsSync(cachedPath)) {
    throw new Error(`Gadget decompression failed: ${cachedPath} not found`);
  }

  console.log(`[FridaInjector] Gadget ready: ${cachedPath}`);
  return cachedPath;
}

/**
 * Inject Frida Gadget into an APK.
 *
 * Steps:
 * 1. Download/cache frida-gadget.so
 * 2. Add libfrida-gadget.so to lib/<arch>/
 * 3. Add frida-gadget.config.json to assets/
 * 4. Patch Application class smali to load the gadget
 * 5. Write output APK
 */
export async function injectGadget(
  apkPath: string,
  arch: FridaArch,
  outputPath: string,
  cacheDir: string,
): Promise<void> {
  if (!fs.existsSync(apkPath)) {
    throw new Error(`APK not found: ${apkPath}`);
  }

  // Step 1: Get gadget
  const gadgetPath = await getGadget(arch, cacheDir);
  const gadgetData = fs.readFileSync(gadgetPath);

  // Step 2: Open APK and inject
  const zip = new AdmZip(apkPath);

  // Add gadget .so to the native libs directory
  const libDir = arch === "arm64-v8a" ? "lib/arm64-v8a" : "lib/x86_64";
  zip.addFile(`${libDir}/libfrida-gadget.so`, gadgetData);
  console.log(`[FridaInjector] Added libfrida-gadget.so to ${libDir}/`);

  // Step 3: Add gadget config
  zip.addFile(
    "assets/frida-gadget.config.json",
    Buffer.from(GADGET_CONFIG, "utf-8"),
  );
  console.log("[FridaInjector] Added frida-gadget.config.json to assets/");

  // Step 4: Patch Application class smali
  const smaliPatched = patchApplicationSmali(zip);
  if (!smaliPatched) {
    console.log(
      "[FridaInjector] Warning: Could not patch Application class smali. Gadget may not load automatically.",
    );
    console.log(
      '[FridaInjector] You may need to manually add System.loadLibrary("frida-gadget") to the app.',
    );
  }

  // Step 5: Remove signatures
  const entries = zip.getEntries();
  const metaInfEntries = entries.filter((e) =>
    e.entryName.startsWith("META-INF/"),
  );
  for (const entry of metaInfEntries) {
    zip.deleteFile(entry.entryName);
  }

  // Write output
  const dir = path.dirname(outputPath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  zip.writeZip(outputPath);
  console.log(`[FridaInjector] Output APK: ${outputPath}`);
}

/**
 * Patch the Application class smali to load frida-gadget early.
 *
 * We find the Application class (or the main activity if no custom Application),
 * and inject a System.loadLibrary call in its <clinit> or <init>.
 */
function patchApplicationSmali(zip: AdmZip): boolean {
  const entries = zip.getEntries();

  // First, try to find a custom Application class from the manifest
  // Look for smali files that extend android/app/Application
  const applicationSmalis = entries.filter((e) => {
    if (!e.entryName.endsWith(".smali") || e.isDirectory) return false;
    const content = e.getData().toString("utf-8");
    return (
      content.includes(".super Landroid/app/Application;") ||
      content.includes(".super Landroidx/multidex/MultiDexApplication;")
    );
  });

  if (applicationSmalis.length === 0) {
    // No custom Application class found
    // Try to find main activity as fallback
    const activitySmalis = entries.filter((e) => {
      if (!e.entryName.endsWith(".smali") || e.isDirectory) return false;
      const content = e.getData().toString("utf-8");
      return (
        content.includes(".super Landroid/app/Activity;") ||
        content.includes(".super Landroidx/appcompat/app/AppCompatActivity;")
      );
    });

    if (activitySmalis.length > 0) {
      return injectLoadLibraryIntoSmali(zip, activitySmalis[0]);
    }
    return false;
  }

  return injectLoadLibraryIntoSmali(zip, applicationSmalis[0]);
}

/**
 * Inject System.loadLibrary("frida-gadget") into a smali file's static constructor.
 */
function injectLoadLibraryIntoSmali(
  zip: AdmZip,
  entry: AdmZip.IZipEntry,
): boolean {
  const content = entry.getData().toString("utf-8");

  const loadLibrarySmali = `
    const-string v0, "frida-gadget"
    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
`;

  // Check if already patched
  if (content.includes("frida-gadget")) {
    console.log(
      `[FridaInjector] ${entry.entryName} already contains frida-gadget reference`,
    );
    return true;
  }

  let modified: string;

  // Try to inject into existing <clinit>
  if (content.includes(".method static constructor <clinit>()V")) {
    modified = content.replace(
      /\.method static constructor <clinit>\(\)V\n([\s\S]*?)\.locals (\d+)/,
      (_match, prefix: string, locals: string) => {
        const newLocals = Math.max(parseInt(locals, 10), 1);
        return `.method static constructor <clinit>()V\n${prefix}.locals ${newLocals}\n${loadLibrarySmali}`;
      },
    );
  } else {
    // Add a new <clinit> method before the first method or at the end
    const clinitMethod = `
.method static constructor <clinit>()V
    .registers 1
${loadLibrarySmali}
    return-void
.end method

`;
    // Insert before the first .method
    const firstMethodIdx = content.indexOf("\n.method ");
    if (firstMethodIdx !== -1) {
      modified =
        content.slice(0, firstMethodIdx) +
        "\n" +
        clinitMethod +
        content.slice(firstMethodIdx);
    } else {
      // Append at end
      modified = content + "\n" + clinitMethod;
    }
  }

  zip.updateFile(entry.entryName, Buffer.from(modified, "utf-8"));
  console.log(`[FridaInjector] Injected loadLibrary into ${entry.entryName}`);
  return true;
}
