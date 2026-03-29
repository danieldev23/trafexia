import { defineStore } from "pinia";
import { ref, computed } from "vue";
import type {
  DetectedPinningHost,
  FridaLogEntry,
  PatchResult,
  BypassFramework,
  FridaArch,
} from "@shared/types";

export const useSslBypassStore = defineStore("sslBypass", () => {
  // State
  const detectedHosts = ref<DetectedPinningHost[]>([]);
  const fridaRunning = ref(false);
  const currentPackage = ref("");
  const currentFramework = ref<BypassFramework>("all");
  const patchLog = ref<PatchResult | null>(null);
  const fridaLogs = ref<FridaLogEntry[]>([]);
  const isPatching = ref(false);
  const isInjecting = ref(false);

  // Getters
  const detectedCount = computed(() => detectedHosts.value.length);
  const hasLogs = computed(() => fridaLogs.value.length > 0);

  // Actions
  async function patchApk(
    inputPath: string,
    outputPath: string,
  ): Promise<PatchResult> {
    isPatching.value = true;
    patchLog.value = null;
    try {
      const result = await window.electronAPI.patchApk(inputPath, outputPath);
      patchLog.value = result;
      return result;
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error);
      const failResult: PatchResult = {
        success: false,
        patchedItems: [],
        warnings: [msg],
        outputPath: "",
      };
      patchLog.value = failResult;
      return failResult;
    } finally {
      isPatching.value = false;
    }
  }

  async function injectGadget(
    apkPath: string,
    arch: FridaArch,
    outputPath: string,
  ): Promise<void> {
    isInjecting.value = true;
    try {
      await window.electronAPI.injectGadget(apkPath, arch, outputPath);
    } finally {
      isInjecting.value = false;
    }
  }

  async function startFrida(
    packageName: string,
    framework: BypassFramework,
  ): Promise<void> {
    try {
      currentPackage.value = packageName;
      currentFramework.value = framework;
      fridaLogs.value = [];
      await window.electronAPI.startFrida(packageName, framework);
      fridaRunning.value = true;
    } catch (error) {
      fridaRunning.value = false;
      throw error;
    }
  }

  async function stopFrida(): Promise<void> {
    try {
      await window.electronAPI.stopFrida();
    } finally {
      fridaRunning.value = false;
    }
  }

  async function refreshDetectedHosts(): Promise<void> {
    detectedHosts.value = await window.electronAPI.getDetectedHosts();
  }

  function addFridaLog(log: FridaLogEntry): void {
    fridaLogs.value.push(log);
    // Keep max 500 log entries
    if (fridaLogs.value.length > 500) {
      fridaLogs.value = fridaLogs.value.slice(-400);
    }
  }

  function addDetectedHost(host: DetectedPinningHost): void {
    const existing = detectedHosts.value.find((h) => h.host === host.host);
    if (existing) {
      existing.detectedAt = host.detectedAt;
    } else {
      detectedHosts.value.push(host);
    }
  }

  function clearLogs(): void {
    fridaLogs.value = [];
  }

  function clearPatchLog(): void {
    patchLog.value = null;
  }

  return {
    // State
    detectedHosts,
    fridaRunning,
    currentPackage,
    currentFramework,
    patchLog,
    fridaLogs,
    isPatching,
    isInjecting,

    // Getters
    detectedCount,
    hasLogs,

    // Actions
    patchApk,
    injectGadget,
    startFrida,
    stopFrida,
    refreshDetectedHosts,
    addFridaLog,
    addDetectedHost,
    clearLogs,
    clearPatchLog,
  };
});
