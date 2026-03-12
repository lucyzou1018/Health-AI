const PARAM_SCHEMA = {
  "agent-audit": [],
  "multichain-contract-vuln": [
    { id: "chain", label: "链类型", type: "select", options: ["evm", "solana"], placeholder: "evm" }
  ],
  "skill-stress-lab": [
    {
      id: "command",
      label: "命令模板",
      type: "textarea",
      placeholder: "python3 skills/skill-stress-lab/tests/helpers/run_http_load.py --url ...",
    },
    { id: "workdir", label: "工作目录", type: "text", placeholder: "例如：skills/skill-stress-lab" },
    { id: "runs", label: "Runs", type: "number", placeholder: "10" },
    { id: "concurrency", label: "Concurrency", type: "number", placeholder: "1" },
    { id: "collectMetrics", label: "Collect Metrics", type: "checkbox" }
  ]
};

const FEATURE_COPY = {
  "agent-audit": {
    title: "Agent Audit",
    desc: "扫描 Skill/Agent 权限、敏感配置与日志，快速定位风险点。"
  },
  "multichain-contract-vuln": {
    title: "Multichain Contract Vuln",
    desc: "一键执行多链合约源码分析，结合 Slither/Anchor 等输出漏洞报告。"
  },
  "skill-stress-lab": {
    title: "Skill Stress Lab",
    desc: "配置命令模板即可跑并发压测、采集 CPU/RSS 与 API 指标。"
  }
};

const VALID_TABS = Object.keys(PARAM_SCHEMA);
let activeTab = (function () {
  const hash = window.location.hash.replace("#", "");
  return VALID_TABS.includes(hash) ? hash : "agent-audit";
})();

const navButtons = document.querySelectorAll("#workspace-tabs button");
const statusBox = document.getElementById("task-status");
const summaryBox = document.getElementById("task-summary");
const artifactBox = document.getElementById("artifact-links");
const runBtn = document.getElementById("run-task");
const codePathInput = document.getElementById("code-path");
const fileInput = document.getElementById("code-upload");
const uploadZone = document.getElementById("upload-zone");
const fileInfo = document.getElementById("file-info");
const fileName = document.getElementById("file-name");
const fileSize = document.getElementById("file-size");
const fileRemove = document.getElementById("file-remove");
const contextTitle = document.getElementById("current-skill-title");
const contextDesc = document.getElementById("current-skill-desc");
const historyList = document.getElementById("history-list");
const historyPanel = document.querySelector(".history-panel");
const reportPreviewBox = document.getElementById("report-preview");
const recordedHistory = new Set();
let previewTaskId = null;
let currentFile = null;
historyPanel?.classList.add("is-empty");

const FINAL_STATUSES = new Set(["completed", "failed"]);
const DEFAULT_API = window.location.origin;
const API_BASE = window.HEALTH_AI_API || DEFAULT_API;
const DETECTOR_REMEDIATIONS = {
  "arbitrary-send-eth": "将资金分发改为 pull/payment 模式，并结合 ReentrancyGuard 与 CEI 避免外部 call 风险。",
  "divide-before-multiply": "避免先除后乘造成截断，可改为先乘再除或使用数学库确保精度。",
  "incorrect-equality": "不要依赖严格等式判断用户状态，改用布尔标记或 <=、>= 范围比较。",
  "timestamp": "不要用 block.timestamp 作为严格控制，需增加时间缓冲或改用区块高度/预言机。",
  "low-level-calls": "统一改用 OpenZeppelin Address 库，或确保低级 call 有完整回退和重入防护。"
};

navButtons.forEach((btn) => btn.addEventListener("click", () => selectTab(btn.dataset.tab)));
if (runBtn) runBtn.addEventListener("click", runTask);
window.addEventListener("hashchange", () => {
  const target = window.location.hash.replace("#", "");
  if (VALID_TABS.includes(target)) {
    selectTab(target, { skipHash: true });
  }
});

// Upload zone event listeners
if (uploadZone && fileInput) {
  // Click to select
  uploadZone.addEventListener("click", (e) => {
    if (e.target.closest(".file-remove")) return;
    fileInput.click();
  });

  // File selected via input
  fileInput.addEventListener("change", () => {
    const file = fileInput.files?.[0];
    if (file) {
      setCurrentFile(file);
    }
  });

  // Drag events
  uploadZone.addEventListener("dragover", (e) => {
    e.preventDefault();
    e.stopPropagation();
    uploadZone.classList.add("dragover");
  });

  uploadZone.addEventListener("dragleave", (e) => {
    e.preventDefault();
    e.stopPropagation();
    uploadZone.classList.remove("dragover");
  });

  uploadZone.addEventListener("drop", (e) => {
    e.preventDefault();
    e.stopPropagation();
    uploadZone.classList.remove("dragover");

    const files = e.dataTransfer?.files;
    if (files?.length > 0) {
      const file = files[0];
      if (file.name.endsWith(".zip")) {
        // Set the file to the input for form submission
        const dt = new DataTransfer();
        dt.items.add(file);
        fileInput.files = dt.files;
        setCurrentFile(file);
      } else {
        setSummary("请上传 .zip 格式的压缩包");
        setStatus("格式错误", "error");
      }
    }
  });
}

// Remove file button
if (fileRemove) {
  fileRemove.addEventListener("click", (e) => {
    e.stopPropagation();
    clearCurrentFile();
  });
}

function setCurrentFile(file) {
  currentFile = file;
  if (fileName) fileName.textContent = file.name;
  if (fileSize) fileSize.textContent = formatFileSize(file.size);
  if (uploadZone) uploadZone.classList.add("has-file");
  if (fileInfo) fileInfo.classList.remove("hidden");
}

function clearCurrentFile() {
  currentFile = null;
  if (fileInput) fileInput.value = "";
  if (uploadZone) uploadZone.classList.remove("has-file");
  if (fileInfo) fileInfo.classList.add("hidden");
  if (fileName) fileName.textContent = "";
  if (fileSize) fileSize.textContent = "";
}

function formatFileSize(bytes) {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + " " + sizes[i];
}

selectTab(activeTab, { skipHash: true });

function selectTab(tab, opts = {}) {
  if (!PARAM_SCHEMA[tab]) return;
  activeTab = tab;
  navButtons.forEach((btn) => btn.classList.toggle("active", btn.dataset.tab === tab));
  if (!opts.skipHash) {
    window.location.hash = tab;
  }
  renderParamFields();
  updateContextBanner();
}

function updateContextBanner() {
  const copy = FEATURE_COPY[activeTab];
  if (copy) {
    if (contextTitle) contextTitle.textContent = copy.title;
    if (contextDesc) contextDesc.textContent = copy.desc;
    document.title = `Health AI · ${copy.title}`;
  }
}

async function uploadFileIfNeeded() {
  const file = fileInput?.files?.[0];
  if (!file) return null;
  const formData = new FormData();
  formData.append("file", file);
  const resp = await fetch(`${API_BASE}/api/uploads`, { method: "POST", body: formData });
  if (!resp.ok) {
    throw new Error(`上传失败：${await resp.text()}`);
  }
  // Don't clear file input here - we want to keep showing the selected file
  const data = await resp.json();
  return data.uploadId;
}

function collectParams() {
  const schema = PARAM_SCHEMA[activeTab] || [];
  const params = {};
  schema.forEach((field) => {
    const el = document.getElementById(`param-${field.id}`);
    if (!el) return;
    if (field.type === "number") {
      const value = el.value ? Number(el.value) : undefined;
      if (!Number.isNaN(value) && value !== undefined) params[field.id] = value;
    } else if (["select", "text", "textarea", "password"].includes(field.type)) {
      if (el.value) params[field.id] = el.value;
    } else if (field.type === "checkbox") {
      params[field.id] = el.checked;
    } else if (el.value) {
      params[field.id] = el.value;
    }
  });
  return params;
}

function renderParamFields() {
  const paramContainer = document.getElementById("param-fields");
  if (!paramContainer) return;
  paramContainer.innerHTML = "";
  const schema = PARAM_SCHEMA[activeTab] || [];
  schema.forEach((field) => {
    const wrapper = document.createElement("label");
    wrapper.className = "field";
    const span = document.createElement("span");
    span.textContent = field.label;
    wrapper.appendChild(span);
    let input;
    if (field.type === "select") {
      input = document.createElement("select");
      (field.options || []).forEach((opt) => {
        const option = document.createElement("option");
        option.value = opt;
        option.textContent = opt;
        input.appendChild(option);
      });
    } else if (field.type === "textarea") {
      input = document.createElement("textarea");
      input.rows = 4;
      input.placeholder = field.placeholder || "";
    } else if (field.type === "checkbox") {
      input = document.createElement("input");
      input.type = "checkbox";
    } else {
      input = document.createElement("input");
      input.type = field.type || "text";
      input.placeholder = field.placeholder || "";
    }
    input.id = `param-${field.id}`;
    wrapper.appendChild(input);
    paramContainer.appendChild(wrapper);
  });
}

async function runTask() {
  try {
    setStatus("运行中...", "running");
    setSummary("正在准备任务……");
    artifactBox?.classList.add("hidden");
    const uploadId = await uploadFileIfNeeded();
    const params = collectParams();
    const codePathValue = codePathInput?.value?.trim();
    if (!codePathValue && !uploadId) {
      throw new Error("请先上传 Skill/Agent 压缩包");
    }
    if (activeTab === "skill-stress-lab" && !params.command) {
      throw new Error("Stress Lab 需要命令模板");
    }
    const body = {
      skillType: activeTab,
      codePath: codePathValue || null,
      uploadId: uploadId,
      params,
    };
    const resp = await fetch(`${API_BASE}/api/tasks`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!resp.ok) {
      throw new Error(await resp.text());
    }
    const task = await resp.json();
    renderTask(task);
    if (!FINAL_STATUSES.has(task.status)) {
      await pollTask(task.taskId);
    }
  } catch (err) {
    setStatus("失败", "error");
    const message = err instanceof Error ? err.message : String(err);
    setSummary(message);
    artifactBox?.classList.add("hidden");
  }
}

function setStatus(text, variant = "info") {
  if (!statusBox) return;
  statusBox.textContent = text;
  statusBox.className = `status ${variant}`;
}

function setSummary(text) {
  if (!summaryBox) return;
  summaryBox.textContent = text;
}

function describeTask(task) {
  if (!task) return "上传 Skill 包后，可在这里查看状态并下载报告。";
  if (task.status === "failed") {
    return task.message ? `任务失败：${task.message}` : "任务失败，请检查日志";
  }
  if (task.status === "completed") {
    return `任务 ${task.taskId} 已完成，可下载报告 / 摘要 / 日志。`;
  }
  return `任务 ${task.taskId} 正在执行...`;
}

const timeFormatter = new Intl.DateTimeFormat("zh-CN", {
  month: "2-digit",
  day: "2-digit",
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  hour12: false,
});

function formatHistoryTime(value) {
  try {
    return timeFormatter.format(value ? new Date(value) : new Date());
  } catch (err) {
    return new Date().toLocaleString();
  }
}

function appendHistoryEntry(task) {
  if (!historyList || !FINAL_STATUSES.has(task.status)) return;
  if (recordedHistory.has(task.taskId)) return;
  recordedHistory.add(task.taskId);
  const emptyRow = historyList.querySelector("li.empty");
  if (emptyRow) emptyRow.remove();
  historyPanel?.classList.remove("is-empty");
  const item = document.createElement("li");
  item.className = "history-item";

  const meta = document.createElement("div");
  meta.className = "history-meta";
  const time = document.createElement("span");
  time.className = "time";
  time.textContent = formatHistoryTime(task.updatedAt || task.createdAt);
  const taskId = document.createElement("span");
  taskId.className = "task-id";
  taskId.textContent = task.taskId;
  meta.append(time, taskId);

  const badge = document.createElement("span");
  const statusClass = task.status === "failed" ? "error" : "success";
  badge.className = `history-status ${statusClass}`;
  badge.textContent = task.status;

  item.append(meta, badge);
  historyList.prepend(item);

  while (historyList.children.length > 5) {
    historyList.lastElementChild?.remove();
  }
}

function renderArtifacts(task) {
  if (!artifactBox) return;
  if (!task || (!task.reportPath && !task.summaryPath && !task.logPath)) {
    artifactBox.classList.add("hidden");
    artifactBox.innerHTML = "";
    return;
  }
  const links = [];
  if (task.reportPath) links.push({ label: "下载报告", href: `${API_BASE}/api/tasks/${task.taskId}/report` });
  if (task.summaryPath) links.push({ label: "下载摘要", href: `${API_BASE}/api/tasks/${task.taskId}/artifact?kind=summary` });
  if (task.logPath) links.push({ label: "下载日志", href: `${API_BASE}/api/tasks/${task.taskId}/artifact?kind=log` });
  if (!links.length) {
    artifactBox.classList.add("hidden");
    artifactBox.innerHTML = "";
    return;
  }
  artifactBox.classList.remove("hidden");
  artifactBox.innerHTML = links
    .map((link) => `<a href="${link.href}" target="_blank" rel="noopener">${link.label}</a>`)
    .join("");
}

async function fetchTask(taskId) {
  const resp = await fetch(`${API_BASE}/api/tasks/${taskId}`);
  if (!resp.ok) throw new Error(await resp.text());
  return resp.json();
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function pollTask(taskId) {
  let attempts = 0;
  while (attempts < 120) {
    const task = await fetchTask(taskId);
    renderTask(task);
    if (FINAL_STATUSES.has(task.status)) return task;
    await delay(1500);
    attempts += 1;
  }
  throw new Error("轮询超时，请手动刷新状态");
}

function renderTask(task) {
  if (!task) return;
  const variant = task.status === "failed" ? "error" : task.status === "completed" ? "success" : "running";
  setStatus(`状态：${task.status}`, variant);
  setSummary(describeTask(task));
  renderArtifacts(task);
  appendHistoryEntry(task);
  renderReportPreview(task);
}

function renderReportPreview(task) {
  if (!reportPreviewBox) return;
  if (!task || task.skillType !== "multichain-contract-vuln" || task.status !== "completed") {
    reportPreviewBox.classList.add("hidden");
    reportPreviewBox.innerHTML = "";
    previewTaskId = null;
    return;
  }
  if (previewTaskId === task.taskId && !reportPreviewBox.classList.contains("hidden")) {
    return;
  }
  const targetId = task.taskId;
  previewTaskId = targetId;
  fetch(`${API_BASE}/api/tasks/${task.taskId}/report`)
    .then((resp) => {
      if (!resp.ok) throw new Error("report fetch failed");
      return resp.text();
    })
    .then((text) => {
      if (previewTaskId !== targetId) return;
      const html = buildReportSummary(text);
      if (html) {
        reportPreviewBox.innerHTML = html;
        reportPreviewBox.classList.remove("hidden");
      } else {
        reportPreviewBox.classList.add("hidden");
        reportPreviewBox.innerHTML = "";
      }
    })
    .catch(() => {
      if (previewTaskId === targetId) {
        reportPreviewBox.classList.add("hidden");
        reportPreviewBox.innerHTML = "";
        previewTaskId = null;
      }
    });
}

function buildReportSummary(text) {
  if (!text) return "";
  const detectorSummaries = extractDetectorSummaries(text);
  const keyFindings = detectorSummaries.slice(0, 3);
  if (!keyFindings.length) return "";
  const recommendations = keyFindings.map((item) => buildDetectorRecommendation(item.name));
  let html = "";
  html += `<h4>关键结论</h4><ol>${keyFindings
    .map((item) => `<li><strong>${item.name}</strong> · ${item.desc || "详见报告"}</li>`)
    .join("")}</ol>`;
  html += `<h4>建议方向</h4><ul>${recommendations
    .map((rec) => `<li>${rec}</li>`)
    .join("")}</ul>`;
  return html;
}

function extractDetectorSummaries(text) {
  const parts = text.split(/\nDetector:/);
  const items = [];
  for (let i = 1; i < parts.length; i++) {
    const chunk = parts[i].trim();
    if (!chunk) continue;
    const lines = chunk.split(/\r?\n/);
    const name = lines[0]?.trim();
    if (!name) continue;
    const detailLine = lines.slice(1).find((l) => l.trim());
    const desc = detailLine ? detailLine.replace(/^[-•]\s*/, '').trim() : "";
    items.push({ name, desc });
  }
  return items;
}

function buildDetectorRecommendation(name) {
  return (
    DETECTOR_REMEDIATIONS[name] ||
    `针对 ${name} 告警，请复核相应业务逻辑并按报告中的修复建议加固。`
  );
}
