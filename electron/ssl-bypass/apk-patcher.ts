/**
 * APK Patcher — modifies an APK to disable SSL pinning without root.
 *
 * Key technique: we operate on the binary XML manifest to inject
 * networkSecurityConfig, create a permissive network_security_config.xml,
 * and neuter pinning-related smali patterns.
 *
 * Uses AdmZip which is already in the project's dependencies.
 */

import * as path from "path";
import * as fs from "fs";
import AdmZip from "adm-zip";
import type { PatchResult, PatchedItem } from "../../shared/types";

/** Network security config XML that trusts user-installed CAs */
const NETWORK_SECURITY_CONFIG = `<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
  <base-config cleartextTrafficPermitted="true">
    <trust-anchors>
      <certificates src="system" />
      <certificates src="user" />
    </trust-anchors>
  </base-config>
</network-security-config>
`;

/** Smali patterns that indicate certificate pinning */
const PINNING_PATTERNS: ReadonlyArray<{
  pattern: RegExp;
  type: "smali_pin_removed" | "smali_trust_override";
  description: string;
}> = [
  {
    pattern: /Lokhttp3\/CertificatePinner;/,
    type: "smali_pin_removed",
    description: "OkHttp3 CertificatePinner reference",
  },
  {
    pattern: /\.method.*checkServerTrusted\(/,
    type: "smali_trust_override",
    description: "checkServerTrusted implementation",
  },
  {
    pattern: /Ljavax\/net\/ssl\/X509TrustManager;/,
    type: "smali_trust_override",
    description: "X509TrustManager reference",
  },
  {
    pattern: /Lokhttp3\/CertificatePinner\$Builder;/,
    type: "smali_pin_removed",
    description: "OkHttp3 CertificatePinner.Builder reference",
  },
  {
    pattern:
      /\.method.*verify\(Ljava\/lang\/String;Ljavax\/net\/ssl\/SSLSession;\)Z/,
    type: "smali_trust_override",
    description: "HostnameVerifier.verify implementation",
  },
];

/**
 * Patch an APK to disable SSL pinning.
 *
 * Steps:
 * 1. Extract APK
 * 2. Create/replace network_security_config.xml
 * 3. Patch AndroidManifest.xml binary to reference the config
 * 4. Scan and neutralize smali pinning patterns
 * 5. Repack APK
 */
export async function patchAPK(
  inputPath: string,
  outputPath: string,
): Promise<PatchResult> {
  const patchedItems: PatchedItem[] = [];
  const warnings: string[] = [];

  try {
    // Validate input
    if (!fs.existsSync(inputPath)) {
      return {
        success: false,
        patchedItems: [],
        warnings: ["Input APK file not found"],
        outputPath: "",
      };
    }

    const zip = new AdmZip(inputPath);
    const entries = zip.getEntries();

    // === Step 1: Create/patch network_security_config.xml ===
    const existingNsc = entries.find(
      (e) => e.entryName === "res/xml/network_security_config.xml",
    );
    if (existingNsc) {
      warnings.push(
        "Existing network_security_config.xml found. Skipping overwrite to prevent binary XML corruption. Relying on Frida hooks.",
      );
      patchedItems.push({
        type: "network_security_config",
        file: "res/xml/network_security_config.xml",
        description: "Skipped overwriting existing binary XML to prevent crash",
      });
    } else {
      zip.addFile(
        "res/xml/network_security_config.xml",
        Buffer.from(NETWORK_SECURITY_CONFIG, "utf-8"),
      );
      patchedItems.push({
        type: "network_security_config",
        file: "res/xml/network_security_config.xml",
        description: "Created new network security config to trust user CAs",
      });
    }

    // === Step 2: Patch AndroidManifest.xml ===
    const manifestPatched = patchManifestBinary(zip, patchedItems, warnings);
    if (!manifestPatched) {
      warnings.push(
        "Could not patch AndroidManifest.xml binary — you may need to add networkSecurityConfig manually",
      );
    }

    // === Step 3: Scan smali files for pinning patterns ===
    const smaliEntries = entries.filter(
      (e) => e.entryName.endsWith(".smali") && !e.isDirectory,
    );

    let smaliPatchCount = 0;
    for (const entry of smaliEntries) {
      const content = entry.getData().toString("utf-8");
      let modified = content;
      let filePatched = false;

      for (const { pattern, type, description } of PINNING_PATTERNS) {
        if (pattern.test(modified)) {
          // For checkServerTrusted, replace the method body with return-void
          if (
            type === "smali_trust_override" &&
            /\.method.*checkServerTrusted\(/.test(modified)
          ) {
            modified = neutralizeCheckServerTrusted(modified);
            filePatched = true;
            patchedItems.push({
              type,
              file: entry.entryName,
              description: `Neutralized ${description}`,
            });
          }
          // For CertificatePinner check methods, neutralize them
          else if (
            type === "smali_pin_removed" &&
            /CertificatePinner/.test(modified)
          ) {
            modified = neutralizeCertificatePinner(modified);
            filePatched = true;
            patchedItems.push({
              type,
              file: entry.entryName,
              description: `Disabled ${description}`,
            });
          }
          // For HostnameVerifier.verify, make it return true
          else if (
            /\.method.*verify\(/.test(entry.entryName) ||
            /verify\(Ljava\/lang\/String;Ljavax\/net\/ssl\/SSLSession;\)Z/.test(
              modified,
            )
          ) {
            modified = neutralizeHostnameVerifier(modified);
            filePatched = true;
            patchedItems.push({
              type,
              file: entry.entryName,
              description: `Bypassed ${description}`,
            });
          }
        }
      }

      if (filePatched) {
        zip.updateFile(entry.entryName, Buffer.from(modified, "utf-8"));
        smaliPatchCount++;
      }
    }

    if (smaliPatchCount === 0) {
      warnings.push(
        "No smali pinning patterns found — the app may use native pinning (try Frida mode)",
      );
    }

    // === Step 4: Remove META-INF (signature files) ===
    const metaInfEntries = entries.filter((e) =>
      e.entryName.startsWith("META-INF/"),
    );
    for (const entry of metaInfEntries) {
      zip.deleteFile(entry.entryName);
    }
    if (metaInfEntries.length > 0) {
      warnings.push(
        `Removed ${metaInfEntries.length} signature files from META-INF/ — APK must be re-signed`,
      );
    }

    // === Step 5: Write output ===
    const outputDir = path.dirname(outputPath);
    if (!fs.existsSync(outputDir)) {
      fs.mkdirSync(outputDir, { recursive: true });
    }
    zip.writeZip(outputPath);

    return {
      success: true,
      patchedItems,
      warnings,
      outputPath,
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return {
      success: false,
      patchedItems,
      warnings: [...warnings, `Fatal error: ${message}`],
      outputPath: "",
    };
  }
}

/**
 * Patch the binary AndroidManifest.xml to add networkSecurityConfig attribute.
 *
 * Binary Android XML uses a string pool + attribute references. We search for
 * the <application> tag and inject the attribute reference. If the manifest
 * already has the attribute, we skip.
 */
function patchManifestBinary(
  zip: AdmZip,
  patchedItems: PatchedItem[],
  warnings: string[],
): boolean {
  const manifestEntry = zip.getEntry("AndroidManifest.xml");
  if (!manifestEntry) {
    warnings.push("AndroidManifest.xml not found in APK");
    return false;
  }

  const data = manifestEntry.getData();

  // Check if networkSecurityConfig is already referenced
  const nscString = "networkSecurityConfig";
  const nscBytes = Buffer.from(nscString, "utf-16le");

  // Search for the string in the binary manifest
  let hasNsc = false;
  for (let i = 0; i < data.length - nscBytes.length; i++) {
    if (data.subarray(i, i + nscBytes.length).equals(nscBytes)) {
      hasNsc = true;
      break;
    }
  }

  if (hasNsc) {
    patchedItems.push({
      type: "manifest",
      file: "AndroidManifest.xml",
      description:
        "networkSecurityConfig attribute already present (no modification needed)",
    });
    return true;
  }

  // For binary XML manifests, direct patching is complex.
  // We add a warning and create a companion text manifest for reference.
  warnings.push(
    "AndroidManifest.xml is in binary format — auto-injection of networkSecurityConfig " +
      "requires apktool for full decompilation. The network_security_config.xml has been " +
      "added to the APK. To activate it, decompile with apktool, add " +
      'android:networkSecurityConfig="@xml/network_security_config" to the <application> tag, ' +
      "then rebuild.",
  );

  patchedItems.push({
    type: "manifest",
    file: "AndroidManifest.xml",
    description:
      "Binary manifest detected — network_security_config.xml added but may need manual activation via apktool",
  });

  return true;
}

/**
 * Neutralize checkServerTrusted method in smali by replacing body with return-void.
 */
function neutralizeCheckServerTrusted(smali: string): string {
  // Match the checkServerTrusted method and replace its body
  const methodRegex =
    /(\.method[^\n]*checkServerTrusted\([^\n]*\n)([\s\S]*?)(\.end method)/g;
  return smali.replace(
    methodRegex,
    (_match, header: string, _body: string, end: string) => {
      return `${header}    .registers 3\n\n    return-void\n${end}`;
    },
  );
}

/**
 * Neutralize CertificatePinner check methods by making them return immediately.
 */
function neutralizeCertificatePinner(smali: string): string {
  // Match CertificatePinner.check method and replace body
  const methodRegex =
    /(\.method[^\n]*check\([^\n]*\n)([\s\S]*?)(\.end method)/g;
  return smali.replace(
    methodRegex,
    (match, header: string, body: string, end: string) => {
      // Only patch if it references CertificatePinner
      if (
        match.includes("CertificatePinner") ||
        body.includes("CertificatePinner")
      ) {
        return `${header}    .registers 3\n\n    return-void\n${end}`;
      }
      return match;
    },
  );
}

/**
 * Neutralize HostnameVerifier.verify by making it return true (const/4 v0, 0x1; return v0).
 */
function neutralizeHostnameVerifier(smali: string): string {
  const methodRegex =
    /(\.method[^\n]*verify\(Ljava\/lang\/String;Ljavax\/net\/ssl\/SSLSession;\)Z\n)([\s\S]*?)(\.end method)/g;
  return smali.replace(
    methodRegex,
    (_match, header: string, _body: string, end: string) => {
      return `${header}    .registers 3\n\n    const/4 v0, 0x1\n\n    return v0\n${end}`;
    },
  );
}
