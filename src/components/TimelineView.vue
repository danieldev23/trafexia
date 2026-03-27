<template>
  <div class="timeline-view">
    <div class="timeline-header">
      <h3>Request Timeline</h3>
      <div class="timeline-controls">
        <label>
          <input type="checkbox" v-model="showOnlySelected" />
          Show only selected
        </label>
        <label>
          Zoom:
          <input type="range" v-model.number="zoomLevel" min="1" max="10" step="0.5" />
          {{ zoomLevel }}x
        </label>
      </div>
    </div>
    
    <div class="timeline-container" ref="containerRef">
      <div class="timeline-axis">
        <div 
          v-for="mark in timeMarks" 
          :key="mark.value"
          class="time-mark"
          :style="{ left: mark.position + '%' }"
        >
          <div class="mark-line"></div>
          <div class="mark-label">{{ mark.label }}</div>
        </div>
      </div>
      
      <div class="timeline-rows" :style="{ width: timelineWidth + 'px' }">
        <div 
          v-for="request in displayRequests" 
          :key="request.id"
          class="timeline-row"
          :class="{ 
            'selected': request.id === trafficStore.selectedRequest?.id,
            'error': request.status >= 400
          }"
          @click="selectRequest(request.id)"
        >
          <div class="row-label">
            <span class="method-badge" :class="'method-' + request.method.toLowerCase()">
              {{ request.method }}
            </span>
            <span class="url-text" :title="request.url">{{ request.host }}{{ request.path }}</span>
            <span class="status-badge" :class="getStatusClass(request.status)">
              {{ request.status }}
            </span>
          </div>
          
          <div class="row-bars">
            <!-- DNS + Connection bar (estimated) -->
            <div 
              v-if="request.duration > 0"
              class="bar bar-connection"
              :style="getBarStyle(request, 'connection')"
              :title="'Connection: ~' + Math.round(request.duration * 0.1) + 'ms'"
            ></div>
            
            <!-- Request sending bar -->
            <div 
              v-if="request.duration > 0"
              class="bar bar-request"
              :style="getBarStyle(request, 'request')"
              :title="'Request: ~' + Math.round(request.duration * 0.1) + 'ms'"
            ></div>
            
            <!-- Waiting (TTFB) bar -->
            <div 
              v-if="request.duration > 0"
              class="bar bar-waiting"
              :style="getBarStyle(request, 'waiting')"
              :title="'Waiting: ~' + Math.round(request.duration * 0.5) + 'ms'"
            ></div>
            
            <!-- Response receiving bar -->
            <div 
              v-if="request.duration > 0"
              class="bar bar-response"
              :style="getBarStyle(request, 'response')"
              :title="'Response: ~' + Math.round(request.duration * 0.3) + 'ms'"
            ></div>
            
            <div class="duration-label">{{ request.duration }}ms</div>
          </div>
        </div>
        
        <div v-if="displayRequests.length === 0" class="empty-state">
          <i class="pi pi-info-circle"></i>
          <p>No requests to display in timeline</p>
        </div>
      </div>
    </div>
    
    <div class="timeline-summary">
      <div class="summary-item">
        <strong>Total Requests:</strong> {{ displayRequests.length }}
      </div>
      <div class="summary-item">
        <strong>Time Range:</strong> {{ formatTimeRange() }}
      </div>
      <div class="summary-item">
        <strong>Total Duration:</strong> {{ totalDuration }}ms
      </div>
      <div class="summary-item">
        <strong>Avg Duration:</strong> {{ avgDuration }}ms
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue';
import { storeToRefs } from 'pinia';
import { useTrafficStore } from '../stores/trafficStore';
import type { CapturedRequest } from '../../shared/types';

const trafficStore = useTrafficStore();
const { filteredRequests } = storeToRefs(trafficStore);

const showOnlySelected = ref(false);
const zoomLevel = ref(1);

// Display requests based on filter
const displayRequests = computed(() => {
  if (showOnlySelected.value && trafficStore.selectedRequest) {
    const selected = filteredRequests.value.find(r => r.id === trafficStore.selectedRequest?.id);
    return selected ? [selected] : [];
  }
  return filteredRequests.value;
});

// Calculate timeline dimensions
const minTimestamp = computed(() => {
  if (displayRequests.value.length === 0) return 0;
  return Math.min(...displayRequests.value.map(r => r.timestamp));
});

const maxTimestamp = computed(() => {
  if (displayRequests.value.length === 0) return 0;
  return Math.max(...displayRequests.value.map(r => r.timestamp + r.duration));
});

const timeRange = computed(() => maxTimestamp.value - minTimestamp.value);

const timelineWidth = computed(() => {
  const baseWidth = 1000;
  return Math.max(baseWidth * zoomLevel.value, 1000);
});

// Generate time marks for axis
const timeMarks = computed(() => {
  if (timeRange.value === 0) return [];
  
  const marks = [];
  const numMarks = 10;
  const interval = timeRange.value / numMarks;
  
  for (let i = 0; i <= numMarks; i++) {
    const value = minTimestamp.value + (interval * i);
    const position = (i / numMarks) * 100;
    const label = formatTimestamp(value);
    marks.push({ value, position, label });
  }
  
  return marks;
});

// Calculate bar styles
function getBarStyle(request: CapturedRequest, phase: string): Record<string, string> {
  const startOffset = request.timestamp - minTimestamp.value;
  const leftPercent = (startOffset / timeRange.value) * 100;
  
  // Estimate phase durations (simplified - in real impl would need actual timing data)
  let phaseStart = 0;
  let phaseWidth = 0;
  const totalDuration = request.duration;
  
  switch (phase) {
    case 'connection':
      phaseStart = 0;
      phaseWidth = totalDuration * 0.1; // 10% for connection
      break;
    case 'request':
      phaseStart = totalDuration * 0.1;
      phaseWidth = totalDuration * 0.1; // 10% for sending request
      break;
    case 'waiting':
      phaseStart = totalDuration * 0.2;
      phaseWidth = totalDuration * 0.5; // 50% waiting for response
      break;
    case 'response':
      phaseStart = totalDuration * 0.7;
      phaseWidth = totalDuration * 0.3; // 30% receiving response
      break;
  }
  
  const phaseLeftPercent = leftPercent + ((phaseStart / timeRange.value) * 100);
  const phaseWidthPercent = (phaseWidth / timeRange.value) * 100;
  
  return {
    left: phaseLeftPercent + '%',
    width: Math.max(phaseWidthPercent, 0.1) + '%'
  };
}

function getStatusClass(status: number): string {
  if (status >= 200 && status < 300) return 'status-success';
  if (status >= 300 && status < 400) return 'status-redirect';
  if (status >= 400 && status < 500) return 'status-client-error';
  if (status >= 500) return 'status-server-error';
  return '';
}

function formatTimestamp(timestamp: number): string {
  const date = new Date(timestamp);
  const time = date.toLocaleTimeString('en-US', { 
    hour: '2-digit', 
    minute: '2-digit', 
    second: '2-digit'
  });
  const ms = date.getMilliseconds().toString().padStart(3, '0');
  return `${time}.${ms}`;
}

function formatTimeRange(): string {
  if (displayRequests.value.length === 0) return 'N/A';
  return `${formatTimestamp(minTimestamp.value)} - ${formatTimestamp(maxTimestamp.value)}`;
}

function selectRequest(id: number) {
  const request = filteredRequests.value.find(r => r.id === id);
  if (request) {
    trafficStore.setSelectedRequest(request);
  }
}

// Summary stats
const totalDuration = computed(() => {
  return displayRequests.value.reduce((sum, r) => sum + r.duration, 0);
});

const avgDuration = computed(() => {
  if (displayRequests.value.length === 0) return 0;
  return Math.round(totalDuration.value / displayRequests.value.length);
});
</script>

<style scoped>
.timeline-view {
  display: flex;
  flex-direction: column;
  height: 100%;
  background: var(--color-bg-primary);
}

.timeline-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 1rem;
  border-bottom: 1px solid var(--color-border);
  background: transparent;
}

.timeline-header h3 {
  margin: 0;
  color: var(--color-text-primary);
}

.timeline-controls {
  display: flex;
  gap: 1.5rem;
  align-items: center;
}

.timeline-controls label {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  color: var(--color-text-primary);
  font-size: 0.9rem;
}

.timeline-controls input[type="checkbox"] {
  cursor: pointer;
}

.timeline-controls input[type="range"] {
  width: 100px;
  cursor: pointer;
}

.timeline-container {
  flex: 1;
  overflow: auto;
  padding: 1rem;
  position: relative;
}

.timeline-axis {
  height: 30px;
  position: sticky;
  top: 0;
  background: var(--color-bg-primary);
  z-index: 10;
  border-bottom: 2px solid var(--color-border);
  margin-bottom: 0.5rem;
}

.time-mark {
  position: absolute;
  top: 0;
  height: 100%;
}

.mark-line {
  width: 1px;
  height: 10px;
  background: var(--color-border);
}

.mark-label {
  font-size: 0.75rem;
  color: var(--color-text-secondary);
  margin-top: 2px;
  white-space: nowrap;
  transform: translateX(-50%);
}

.timeline-rows {
  min-width: 100%;
  padding-bottom: 1rem;
}

.timeline-row {
  display: flex;
  align-items: center;
  margin-bottom: 4px;
  padding: 4px 8px;
  background: transparent;
  border-radius: 4px;
  cursor: pointer;
  transition: all 0.2s;
  border-left: 3px solid transparent;
}

.timeline-row:hover {
  background: var(--color-bg-tertiary);
  transform: translateX(2px);
}

.timeline-row.selected {
  border-left-color: var(--color-accent);
  background: var(--color-accent-muted);
}

.timeline-row.error {
  border-left-color: var(--color-error);
}

.row-label {
  min-width: 400px;
  max-width: 400px;
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-size: 0.85rem;
  padding-right: 1rem;
}

.method-badge {
  padding: 2px 6px;
  border-radius: 3px;
  font-weight: 600;
  font-size: 0.75rem;
  text-transform: uppercase;
  min-width: 45px;
  text-align: center;
}

.method-get { background: #4caf50; color: white; }
.method-post { background: #ff9800; color: white; }
.method-put { background: #2196f3; color: white; }
.method-delete { background: #f44336; color: white; }
.method-patch { background: #9c27b0; color: white; }

.url-text {
  flex: 1;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  color: var(--color-text-primary);
}

.status-badge {
  padding: 2px 6px;
  border-radius: 3px;
  font-weight: 600;
  font-size: 0.75rem;
  min-width: 35px;
  text-align: center;
}

.status-success { background: #4caf50; color: white; }
.status-redirect { background: #2196f3; color: white; }
.status-client-error { background: #ff9800; color: white; }
.status-server-error { background: #f44336; color: white; }

.row-bars {
  flex: 1;
  position: relative;
  height: 24px;
  display: flex;
  align-items: center;
}

.bar {
  position: absolute;
  height: 16px;
  border-radius: 2px;
  transition: all 0.2s;
}

.bar:hover {
  height: 20px;
  z-index: 5;
}

.bar-connection {
  background: #9e9e9e;
  z-index: 1;
}

.bar-request {
  background: #2196f3;
  z-index: 2;
}

.bar-waiting {
  background: #4caf50;
  z-index: 3;
}

.bar-response {
  background: #ff9800;
  z-index: 4;
}

.duration-label {
  position: absolute;
  right: -60px;
  font-size: 0.75rem;
  color: var(--color-text-secondary);
  white-space: nowrap;
}

.empty-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 3rem;
  color: var(--color-text-secondary);
}

.empty-state i {
  font-size: 3rem;
  margin-bottom: 1rem;
  opacity: 0.5;
}

.timeline-summary {
  display: flex;
  gap: 2rem;
  padding: 1rem;
  border-top: 1px solid var(--color-border);
  background: transparent;
}

.summary-item {
  font-size: 0.9rem;
  color: var(--color-text-primary);
}

.summary-item strong {
  margin-right: 0.5rem;
  color: var(--color-text-secondary);
}
</style>
