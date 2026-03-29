<script setup lang="ts">
import { ref, onMounted, onUnmounted, nextTick, computed } from "vue";
import TabView from "primevue/tabview";
import TabPanel from "primevue/tabpanel";
import DataTable from "primevue/datatable";
import Column from "primevue/column";
import Dropdown from "primevue/dropdown";
import {
  Upload,
  Download,
  Play,
  Square,
  Loader2,
  Trash2,
  CheckCircle,
  AlertTriangle,
  Info,
  Shield,
  Zap,
  Terminal,
  Package,
  X,
  Minus,
} from "lucide-vue-next";
import { useSslBypassStore } from "@/stores/sslBypassStore";
import type { BypassFramework, FridaArch } from "@shared/types";

const store = useSslBypassStore();
const emit = defineEmits<{ (e: "close"): void }>();

// UI state
const isMinimized = ref(false);

// APK Patcher state
const apkFilePath = ref("");
const apkFileName = ref("");
const isDragging = ref(false);

// Frida state
const packageName = ref("");
const selectedFramework = ref<BypassFramework>("all");
const logContainerRef = ref<HTMLElement | null>(null);

// Gadget injection state
const gadgetArch = ref<FridaArch>("arm64-v8a");

const frameworkOptions = [
  { label: "Auto / All Frameworks", value: "all" },
  { label: "OkHttp3", value: "okhttp3" },
  { label: "Conscrypt (Android Default)", value: "conscrypt" },
  { label: "WebView", value: "webview" },
  { label: "Flutter", value: "flutter" },
  { label: "React Native", value: "react-native" },
];

const archOptions = [
  { label: "ARM64 (arm64-v8a)", value: "arm64-v8a" },
  { label: "x86_64", value: "x86_64" },
];

const patchSuccess = computed(() => store.patchLog?.success ?? false);
const hasPatchLog = computed(() => store.patchLog !== null);

// Listeners
let removeFridaLogListener: (() => void) | null = null;
let removeHostDetectedListener: (() => void) | null = null;

onMounted(() => {
  removeFridaLogListener = window.electronAPI.onFridaLog((log) => {
    store.addFridaLog(log);
    // Auto-scroll log console
    nextTick(() => {
      if (logContainerRef.value) {
        logContainerRef.value.scrollTop = logContainerRef.value.scrollHeight;
      }
    });
  });

  removeHostDetectedListener = window.electronAPI.onHostDetected((host) => {
    store.addDetectedHost(host);
  });

  // Refresh detected hosts
  store.refreshDetectedHosts();
});

onUnmounted(() => {
  removeFridaLogListener?.();
  removeHostDetectedListener?.();
});

// APK Patcher handlers
function handleDragOver(e: DragEvent) {
  e.preventDefault();
  isDragging.value = true;
}

function handleDragLeave() {
  isDragging.value = false;
}

function handleDrop(e: DragEvent) {
  e.preventDefault();
  isDragging.value = false;

  const files = e.dataTransfer?.files;
  if (files && files.length > 0) {
    const file = files[0];
    if (file.name.endsWith(".apk")) {
      apkFileName.value = file.name;
      apkFilePath.value = (file as File & { path: string }).path;
    }
  }
}

function handleFileSelect(e: Event) {
  const input = e.target as HTMLInputElement;
  if (input.files && input.files.length > 0) {
    const file = input.files[0];
    apkFileName.value = file.name;
    apkFilePath.value = (file as File & { path: string }).path;
  }
}

async function patchApk() {
  if (!apkFilePath.value) return;
  const outputPath = apkFilePath.value.replace(".apk", "-patched.apk");
  await store.patchApk(apkFilePath.value, outputPath);
}

async function injectGadget() {
  if (!apkFilePath.value) return;
  const outputPath = apkFilePath.value.replace(".apk", "-gadget.apk");
  await store.injectGadget(apkFilePath.value, gadgetArch.value, outputPath);
}

// Frida handlers
async function toggleFrida() {
  if (store.fridaRunning) {
    await store.stopFrida();
  } else {
    if (!packageName.value.trim()) return;
    await store.startFrida(packageName.value.trim(), selectedFramework.value);
  }
}

function formatTime(ts: number): string {
  return new Date(ts).toLocaleTimeString();
}

function getLogClass(level: string): string {
  switch (level) {
    case "success":
      return "log-success";
    case "error":
      return "log-error";
    case "warning":
      return "log-warning";
    default:
      return "log-info";
  }
}
</script>

<template>
  <div class="ssl-bypass-overlay" :class="{ 'is-minimized': isMinimized }">
    <div class="ssl-bypass-panel" :class="{ 'minimized-panel': isMinimized }">
      <!-- Header -->
      <div class="panel-header">
        <div class="header-title">
          <Shield class="w-5 h-5" style="color: #f0883e" />
          <span>SSL Pinning Bypass</span>
        </div>
        <div class="header-actions">
          <button
            class="btn-icon"
            @click="isMinimized = !isMinimized"
            title="Minimize/Expand"
          >
            <Minus class="w-4 h-4" />
          </button>
          <button
            class="btn-icon btn-close"
            @click="emit('close')"
            title="Close"
          >
            <X class="w-4 h-4" />
          </button>
        </div>
      </div>

      <!-- Tab View -->
      <TabView v-show="!isMinimized" class="bypass-tabs">
        <!-- APK Patcher Tab -->
        <TabPanel>
          <template #header>
            <Package class="w-4 h-4" style="margin-right: 6px" />
            <span>APK Patcher</span>
          </template>

          <div class="tab-content">
            <!-- Drop Zone -->
            <div
              class="drop-zone"
              :class="{ dragging: isDragging, 'has-file': !!apkFileName }"
              @dragover="handleDragOver"
              @dragleave="handleDragLeave"
              @drop="handleDrop"
              @click="($refs.fileInput as HTMLInputElement)?.click()"
            >
              <input
                ref="fileInput"
                type="file"
                accept=".apk"
                style="display: none"
                @change="handleFileSelect"
              />
              <Upload class="w-8 h-8" style="color: #8b949e" />
              <p v-if="!apkFileName" class="drop-text">
                Drop APK here or click to browse
              </p>
              <p v-else class="drop-text file-selected">{{ apkFileName }}</p>
            </div>

            <!-- Actions -->
            <div class="action-row" v-if="apkFileName">
              <div class="arch-select">
                <label>Architecture:</label>
                <Dropdown
                  v-model="gadgetArch"
                  :options="archOptions"
                  optionLabel="label"
                  optionValue="value"
                  class="compact-dropdown"
                />
              </div>

              <button
                class="btn btn-primary"
                @click="patchApk"
                :disabled="store.isPatching"
              >
                <Loader2 v-if="store.isPatching" class="w-4 h-4 spin" />
                <Zap v-else class="w-4 h-4" />
                <span>Patch APK</span>
              </button>

              <button
                class="btn btn-secondary"
                @click="injectGadget"
                :disabled="store.isInjecting"
              >
                <Loader2 v-if="store.isInjecting" class="w-4 h-4 spin" />
                <Download v-else class="w-4 h-4" />
                <span>Inject Gadget</span>
              </button>
            </div>

            <!-- Patch Results -->
            <div v-if="hasPatchLog" class="patch-results">
              <div
                class="result-header"
                :class="{ success: patchSuccess, error: !patchSuccess }"
              >
                <CheckCircle v-if="patchSuccess" class="w-5 h-5" />
                <AlertTriangle v-else class="w-5 h-5" />
                <span>{{
                  patchSuccess ? "APK Patched Successfully" : "Patching Failed"
                }}</span>
              </div>

              <!-- Patched Items -->
              <div
                v-if="store.patchLog!.patchedItems.length > 0"
                class="result-section"
              >
                <h4>Patched Items</h4>
                <ul class="patch-list">
                  <li
                    v-for="(item, idx) in store.patchLog!.patchedItems"
                    :key="idx"
                    class="patch-item"
                  >
                    <CheckCircle
                      class="w-4 h-4"
                      style="color: #3fb950; flex-shrink: 0"
                    />
                    <div>
                      <code class="patch-file">{{ item.file }}</code>
                      <p class="patch-desc">{{ item.description }}</p>
                    </div>
                  </li>
                </ul>
              </div>

              <!-- Warnings -->
              <div
                v-if="store.patchLog!.warnings.length > 0"
                class="result-section"
              >
                <h4>Warnings</h4>
                <ul class="warning-list">
                  <li
                    v-for="(warn, idx) in store.patchLog!.warnings"
                    :key="idx"
                    class="warning-item"
                  >
                    <AlertTriangle
                      class="w-4 h-4"
                      style="color: #d29922; flex-shrink: 0"
                    />
                    <span>{{ warn }}</span>
                  </li>
                </ul>
              </div>

              <!-- Output Path -->
              <div v-if="store.patchLog!.outputPath" class="output-path">
                <Info class="w-4 h-4" />
                <span
                  >Output: <code>{{ store.patchLog!.outputPath }}</code></span
                >
              </div>

              <!-- Re-sign instructions -->
              <div class="resign-instructions">
                <h4>Re-sign APK</h4>
                <p>The patched APK is unsigned. Re-sign it with:</p>
                <code class="code-block"
                  >java -jar uber-apk-signer.jar --apks
                  {{ store.patchLog!.outputPath || "patched.apk" }}</code
                >
                <p class="hint">
                  Download uber-apk-signer from
                  <a
                    href="https://github.com/nicknisi/uber-apk-signer"
                    target="_blank"
                    >GitHub</a
                  >
                </p>
              </div>
            </div>
          </div>
        </TabPanel>

        <!-- Frida Mode Tab -->
        <TabPanel>
          <template #header>
            <Terminal class="w-4 h-4" style="margin-right: 6px" />
            <span>Frida Mode</span>
          </template>

          <div class="tab-content">
            <!-- Controls -->
            <div class="frida-controls">
              <div class="control-row">
                <div class="input-group">
                  <label>Package Name</label>
                  <input
                    type="text"
                    v-model="packageName"
                    placeholder="com.target.app"
                    class="text-input"
                    :disabled="store.fridaRunning"
                  />
                </div>
                <div class="input-group">
                  <label>Framework</label>
                  <Dropdown
                    v-model="selectedFramework"
                    :options="frameworkOptions"
                    optionLabel="label"
                    optionValue="value"
                    class="framework-dropdown"
                    :disabled="store.fridaRunning"
                  />
                </div>
                <button
                  class="btn frida-toggle"
                  :class="{ running: store.fridaRunning }"
                  @click="toggleFrida"
                  :disabled="!packageName.trim() && !store.fridaRunning"
                >
                  <Square v-if="store.fridaRunning" class="w-4 h-4" />
                  <Play v-else class="w-4 h-4" />
                  <span>{{ store.fridaRunning ? "Stop" : "Start" }}</span>
                </button>
              </div>
            </div>

            <!-- Live Log Console -->
            <div class="log-console">
              <div class="console-header">
                <Terminal class="w-4 h-4" />
                <span>Frida Console</span>
                <div class="console-actions">
                  <button
                    class="btn-icon-sm"
                    @click="store.clearLogs()"
                    title="Clear Logs"
                  >
                    <Trash2 class="w-3 h-3" />
                  </button>
                </div>
              </div>
              <div class="console-output" ref="logContainerRef">
                <div v-if="store.fridaLogs.length === 0" class="console-empty">
                  <p>No output yet. Start Frida to see bypass logs.</p>
                </div>
                <div
                  v-for="(log, idx) in store.fridaLogs"
                  :key="idx"
                  :class="['console-line', getLogClass(log.level)]"
                >
                  <span class="log-time">{{ formatTime(log.timestamp) }}</span>
                  <span class="log-msg">{{ log.message }}</span>
                </div>
              </div>
            </div>

            <!-- Frida Requirements Notice -->
            <div class="requirements-notice">
              <Info class="w-4 h-4" />
              <span
                >Requires <code>frida-tools</code> installed:
                <code>pip install frida-tools</code></span
              >
            </div>
          </div>
        </TabPanel>

        <!-- Detected Pinning Tab -->
        <TabPanel>
          <template #header>
            <AlertTriangle class="w-4 h-4" style="margin-right: 6px" />
            <span>Detected ({{ store.detectedCount }})</span>
          </template>

          <div class="tab-content">
            <DataTable
              :value="store.detectedHosts"
              :paginator="store.detectedHosts.length > 20"
              :rows="20"
              class="detected-table"
              emptyMessage="No SSL pinning detected yet. Start the proxy and browse target apps."
            >
              <Column
                field="host"
                header="Host"
                sortable
                style="min-width: 200px"
              >
                <template #body="{ data }">
                  <code class="host-code">{{ data.host }}</code>
                </template>
              </Column>
              <Column
                field="framework"
                header="Framework"
                sortable
                style="min-width: 150px"
              >
                <template #body="{ data }">
                  <span class="framework-badge">{{ data.framework }}</span>
                </template>
              </Column>
              <Column
                field="detectedAt"
                header="Detected"
                sortable
                style="min-width: 150px"
              >
                <template #body="{ data }">
                  <span>{{ formatTime(data.detectedAt) }}</span>
                </template>
              </Column>
              <Column field="bypassed" header="Status" style="min-width: 100px">
                <template #body="{ data }">
                  <span
                    :class="[
                      'status-badge',
                      data.bypassed ? 'bypassed' : 'blocked',
                    ]"
                  >
                    {{ data.bypassed ? "Bypassed" : "Blocked" }}
                  </span>
                </template>
              </Column>
            </DataTable>

            <button
              class="btn btn-ghost"
              @click="store.refreshDetectedHosts()"
              style="margin-top: 12px"
            >
              Refresh
            </button>
          </div>
        </TabPanel>
      </TabView>
    </div>
  </div>
</template>

<style scoped>
.ssl-bypass-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: rgba(0, 0, 0, 0.6);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1000;
  backdrop-filter: blur(4px);
  transition: all 0.3s cubic-bezier(0.25, 0.8, 0.25, 1);
}

.ssl-bypass-overlay.is-minimized {
  background: transparent;
  pointer-events: none;
  backdrop-filter: none;
  align-items: flex-end;
  justify-content: flex-end;
  padding: 24px;
}

.ssl-bypass-panel {
  width: 90vw;
  max-width: 900px;
  height: 85vh;
  max-height: 750px;
  background: #0d1117;
  border: 1px solid rgba(48, 54, 61, 0.8);
  border-radius: 12px;
  display: flex;
  flex-direction: column;
  overflow: hidden;
  box-shadow: 0 8px 32px rgba(0, 0, 0, 0.5);
  transition: all 0.3s cubic-bezier(0.25, 0.8, 0.25, 1);
  pointer-events: auto;
}

.ssl-bypass-panel.minimized-panel {
  width: 320px;
  height: auto;
  max-height: 60px;
  border-radius: 8px;
  box-shadow: 0 8px 24px rgba(0, 0, 0, 0.4);
}

.panel-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 16px 20px;
  border-bottom: 1px solid rgba(48, 54, 61, 0.8);
  background: #161b22;
}

.minimized-panel .panel-header {
  padding: 12px 16px;
  border-bottom: none;
}

.header-actions {
  display: flex;
  align-items: center;
  gap: 8px;
}

.btn-icon {
  background: none;
  border: none;
  color: #8b949e;
  cursor: pointer;
  padding: 6px;
  border-radius: 6px;
  transition: all 0.15s;
  display: flex;
  align-items: center;
  justify-content: center;
}

.btn-icon:hover {
  background: rgba(255, 255, 255, 0.1);
  color: #e6edf3;
}

.header-title {
  display: flex;
  align-items: center;
  gap: 10px;
  font-size: 16px;
  font-weight: 600;
  color: #e6edf3;
}

.btn-close {
  background: none;
  border: none;
  color: #8b949e;
  cursor: pointer;
  padding: 6px;
  border-radius: 6px;
  transition: all 0.15s;
}

.btn-close:hover {
  background: rgba(255, 255, 255, 0.1);
  color: #e6edf3;
}

/* Tabs */
.bypass-tabs {
  flex: 1;
  display: flex;
  flex-direction: column;
  overflow: hidden;
}

:deep(.p-tabview-panels) {
  flex: 1;
  overflow-y: auto;
  background: #0d1117;
  padding: 0;
}

:deep(.p-tabview-nav) {
  background: #161b22;
  border-bottom: 1px solid rgba(48, 54, 61, 0.8);
}

:deep(.p-tabview-nav-link) {
  color: #8b949e !important;
  font-size: 13px;
  display: flex;
  align-items: center;
}

:deep(.p-tabview-nav-link:not(.p-disabled):focus) {
  box-shadow: none !important;
}

:deep(.p-highlight .p-tabview-nav-link) {
  color: #e6edf3 !important;
  border-color: #f0883e !important;
}

.tab-content {
  padding: 20px;
}

/* Drop Zone */
.drop-zone {
  border: 2px dashed rgba(48, 54, 61, 0.8);
  border-radius: 12px;
  padding: 40px;
  text-align: center;
  cursor: pointer;
  transition: all 0.2s;
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 12px;
}

.drop-zone:hover,
.drop-zone.dragging {
  border-color: #f0883e;
  background: rgba(240, 136, 62, 0.05);
}

.drop-zone.has-file {
  border-color: #3fb950;
  background: rgba(63, 185, 80, 0.05);
}

.drop-text {
  color: #8b949e;
  font-size: 14px;
  margin: 0;
}

.drop-text.file-selected {
  color: #3fb950;
  font-weight: 500;
}

/* Action Row */
.action-row {
  display: flex;
  align-items: flex-end;
  gap: 12px;
  margin-top: 16px;
  flex-wrap: wrap;
}

.arch-select {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.arch-select label {
  font-size: 11px;
  color: #8b949e;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.btn {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 8px 16px;
  border-radius: 6px;
  font-size: 13px;
  font-weight: 500;
  cursor: pointer;
  border: 1px solid rgba(240, 246, 252, 0.1);
  transition: all 0.15s;
}

.btn-primary {
  background: #238636;
  color: white;
}

.btn-primary:hover:not(:disabled) {
  background: #2ea043;
}

.btn-secondary {
  background: #1f6feb;
  color: white;
}

.btn-secondary:hover:not(:disabled) {
  background: #388bfd;
}

.btn-ghost {
  background: rgba(255, 255, 255, 0.05);
  color: #c9d1d9;
  border-color: rgba(240, 246, 252, 0.1);
}

.btn-ghost:hover {
  background: rgba(255, 255, 255, 0.1);
}

.btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.spin {
  animation: spin 1s linear infinite;
}

@keyframes spin {
  from {
    transform: rotate(0deg);
  }
  to {
    transform: rotate(360deg);
  }
}

/* Patch Results */
.patch-results {
  margin-top: 20px;
  border: 1px solid rgba(48, 54, 61, 0.8);
  border-radius: 8px;
  overflow: hidden;
}

.result-header {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 12px 16px;
  font-weight: 600;
  font-size: 14px;
}

.result-header.success {
  background: rgba(63, 185, 80, 0.1);
  color: #3fb950;
}

.result-header.error {
  background: rgba(248, 81, 73, 0.1);
  color: #f85149;
}

.result-section {
  padding: 12px 16px;
  border-top: 1px solid rgba(48, 54, 61, 0.5);
}

.result-section h4 {
  font-size: 12px;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  color: #8b949e;
  margin: 0 0 8px 0;
}

.patch-list,
.warning-list {
  list-style: none;
  padding: 0;
  margin: 0;
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.patch-item,
.warning-item {
  display: flex;
  align-items: flex-start;
  gap: 8px;
  font-size: 13px;
  color: #c9d1d9;
}

.patch-file {
  font-size: 12px;
  background: rgba(110, 118, 129, 0.15);
  padding: 2px 6px;
  border-radius: 4px;
  color: #79c0ff;
}

.patch-desc {
  margin: 4px 0 0;
  font-size: 12px;
  color: #8b949e;
}

.output-path {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 12px 16px;
  border-top: 1px solid rgba(48, 54, 61, 0.5);
  color: #8b949e;
  font-size: 13px;
}

.output-path code {
  color: #79c0ff;
  font-size: 12px;
}

.resign-instructions {
  padding: 12px 16px;
  border-top: 1px solid rgba(48, 54, 61, 0.5);
}

.resign-instructions h4 {
  font-size: 12px;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  color: #8b949e;
  margin: 0 0 8px;
}

.resign-instructions p {
  font-size: 13px;
  color: #8b949e;
  margin: 4px 0;
}

.code-block {
  display: block;
  padding: 10px 14px;
  background: #161b22;
  border: 1px solid rgba(48, 54, 61, 0.8);
  border-radius: 6px;
  color: #79c0ff;
  font-size: 12px;
  word-break: break-all;
  margin: 8px 0;
}

.hint {
  font-size: 12px;
}

.hint a {
  color: #58a6ff;
  text-decoration: none;
}

.hint a:hover {
  text-decoration: underline;
}

/* Frida Controls */
.frida-controls {
  margin-bottom: 16px;
}

.control-row {
  display: flex;
  align-items: flex-end;
  gap: 12px;
  flex-wrap: wrap;
}

.input-group {
  display: flex;
  flex-direction: column;
  gap: 4px;
  flex: 1;
  min-width: 180px;
}

.input-group label {
  font-size: 11px;
  color: #8b949e;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.text-input {
  padding: 8px 12px;
  background: #0d1117;
  border: 1px solid rgba(48, 54, 61, 0.8);
  border-radius: 6px;
  color: #e6edf3;
  font-size: 13px;
  font-family:
    ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
  outline: none;
  transition: border-color 0.15s;
}

.text-input:focus {
  border-color: #f0883e;
}

.text-input:disabled {
  opacity: 0.5;
}

.frida-toggle {
  background: #238636;
  color: white;
  height: 36px;
  white-space: nowrap;
}

.frida-toggle:hover:not(:disabled) {
  background: #2ea043;
}

.frida-toggle.running {
  background: #21262d;
  color: #f85149;
  border-color: rgba(240, 246, 252, 0.1);
}

.frida-toggle.running:hover {
  background: #30363d;
}

/* Log Console */
.log-console {
  border: 1px solid rgba(48, 54, 61, 0.8);
  border-radius: 8px;
  overflow: hidden;
  display: flex;
  flex-direction: column;
}

.console-header {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 12px;
  background: #161b22;
  border-bottom: 1px solid rgba(48, 54, 61, 0.5);
  font-size: 12px;
  font-weight: 600;
  color: #8b949e;
}

.console-actions {
  margin-left: auto;
}

.btn-icon-sm {
  background: none;
  border: none;
  color: #6e7681;
  cursor: pointer;
  padding: 4px;
  border-radius: 4px;
  display: flex;
  align-items: center;
}

.btn-icon-sm:hover {
  color: #e6edf3;
  background: rgba(255, 255, 255, 0.1);
}

.console-output {
  height: 300px;
  overflow-y: auto;
  padding: 8px 12px;
  background: #010409;
  font-family:
    ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
  font-size: 12px;
  line-height: 1.6;
}

.console-empty {
  display: flex;
  align-items: center;
  justify-content: center;
  height: 100%;
  color: #484f58;
}

.console-line {
  display: flex;
  gap: 8px;
}

.log-time {
  color: #484f58;
  flex-shrink: 0;
}

.log-msg {
  word-break: break-all;
}

.log-success .log-msg {
  color: #3fb950;
}
.log-error .log-msg {
  color: #f85149;
}
.log-warning .log-msg {
  color: #d29922;
}
.log-info .log-msg {
  color: #8b949e;
}

/* Requirements Notice */
.requirements-notice {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-top: 12px;
  padding: 10px 14px;
  background: rgba(56, 139, 253, 0.1);
  border: 1px solid rgba(56, 139, 253, 0.2);
  border-radius: 6px;
  font-size: 12px;
  color: #8b949e;
}

.requirements-notice code {
  color: #79c0ff;
  background: rgba(110, 118, 129, 0.15);
  padding: 1px 5px;
  border-radius: 3px;
  font-size: 11px;
}

/* Detected Table */
:deep(.detected-table .p-datatable-table) {
  font-size: 13px;
}

:deep(.detected-table .p-datatable-thead > tr > th) {
  background: #161b22 !important;
  color: #8b949e !important;
  border-color: rgba(48, 54, 61, 0.5) !important;
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

:deep(.detected-table .p-datatable-tbody > tr) {
  background: #0d1117 !important;
  color: #c9d1d9 !important;
}

:deep(.detected-table .p-datatable-tbody > tr > td) {
  border-color: rgba(48, 54, 61, 0.3) !important;
}

:deep(.detected-table .p-datatable-tbody > tr:hover) {
  background: #161b22 !important;
}

.host-code {
  color: #79c0ff;
  font-size: 12px;
  background: rgba(110, 118, 129, 0.1);
  padding: 2px 6px;
  border-radius: 4px;
}

.framework-badge {
  padding: 3px 8px;
  background: rgba(240, 136, 62, 0.15);
  color: #f0883e;
  border-radius: 10px;
  font-size: 12px;
  font-weight: 500;
}

.status-badge {
  padding: 3px 8px;
  border-radius: 10px;
  font-size: 12px;
  font-weight: 500;
}

.status-badge.bypassed {
  background: rgba(63, 185, 80, 0.15);
  color: #3fb950;
}

.status-badge.blocked {
  background: rgba(248, 81, 73, 0.15);
  color: #f85149;
}

/* Utility */
.w-3 {
  width: 12px;
  height: 12px;
}
.w-4 {
  width: 16px;
  height: 16px;
}
.w-5 {
  width: 20px;
  height: 20px;
}
.w-8 {
  width: 32px;
  height: 32px;
}
.h-3 {
  height: 12px;
}
.h-4 {
  height: 16px;
}
.h-5 {
  height: 20px;
}
</style>
