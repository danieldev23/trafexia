/**
 * SSL Bypass Rule — detects SSL pinning from proxy errors and strips
 * HSTS/HPKP headers from responses.
 *
 * This service sits alongside the existing ProxyServer and maintains
 * a list of hosts where pinning has been detected.
 */

import type { DetectedPinningHost } from "../../shared/types";

/** Patterns that indicate SSL pinning in error messages */
const PINNING_ERROR_PATTERNS: ReadonlyArray<{
  pattern: RegExp;
  framework: string;
}> = [
  { pattern: /certificate\s*pin/i, framework: "Certificate Pinning" },
  { pattern: /CERTIFICATE_VERIFY_FAILED/i, framework: "OpenSSL" },
  { pattern: /SSL\s*handshake.*failed/i, framework: "SSL Handshake" },
  { pattern: /CERT_UNTRUSTED/i, framework: "Certificate Trust" },
  { pattern: /peer.*not\s*authenticated/i, framework: "Peer Authentication" },
  { pattern: /self.signed/i, framework: "Self-Signed Detection" },
  { pattern: /hostname.*mismatch/i, framework: "Hostname Verification" },
  { pattern: /UNABLE_TO_VERIFY_LEAF_SIGNATURE/i, framework: "Leaf Signature" },
  { pattern: /ERR_CERT/i, framework: "Certificate Error" },
];

/** Headers to strip from responses to prevent transport security restrictions */
const HEADERS_TO_STRIP: ReadonlyArray<string> = [
  "strict-transport-security",
  "public-key-pins",
  "public-key-pins-report-only",
  "expect-ct",
];

export class SslBypassRule {
  private detectedHosts: Map<string, DetectedPinningHost> = new Map();

  /**
   * Process response headers — strip HSTS and HPKP headers.
   * Returns the cleaned headers object.
   */
  processResponseHeaders(
    headers: Record<string, string>,
  ): Record<string, string> {
    const cleaned: Record<string, string> = {};

    for (const [key, value] of Object.entries(headers)) {
      if (!HEADERS_TO_STRIP.includes(key.toLowerCase())) {
        cleaned[key] = value;
      }
    }

    return cleaned;
  }

  /**
   * Handle an SSL error — check if it indicates certificate pinning.
   * Returns the detected host info if pinning was detected, null otherwise.
   */
  handleSslError(
    host: string,
    errorMessage: string,
  ): DetectedPinningHost | null {
    for (const { pattern, framework } of PINNING_ERROR_PATTERNS) {
      if (pattern.test(errorMessage)) {
        const detected: DetectedPinningHost = {
          host,
          framework,
          detectedAt: Date.now(),
          bypassed: false,
        };

        // Don't duplicate — update timestamp if already known
        const existing = this.detectedHosts.get(host);
        if (existing) {
          existing.detectedAt = Date.now();
          return existing;
        }

        this.detectedHosts.set(host, detected);
        console.log(
          `[SslBypassRule] Pinning detected for ${host} (${framework})`,
        );
        return detected;
      }
    }

    return null;
  }

  /**
   * Get all detected pinning hosts.
   */
  getDetectedHosts(): DetectedPinningHost[] {
    return Array.from(this.detectedHosts.values());
  }

  /**
   * Mark a host as bypassed.
   */
  markBypassed(host: string): void {
    const entry = this.detectedHosts.get(host);
    if (entry) {
      entry.bypassed = true;
    }
  }

  /**
   * Clear all detected hosts.
   */
  clearDetected(): void {
    this.detectedHosts.clear();
  }

  /**
   * Check if a host has been detected as pinning.
   */
  isDetected(host: string): boolean {
    return this.detectedHosts.has(host);
  }
}
