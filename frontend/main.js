const PARAM_SCHEMA = {
  "agent-audit": [],
  "multichain-contract-vuln": [
    { id: "chain", label: "链类型", type: "select", options: ["evm", "solana"], placeholder: "evm" }
  ],
  "skill-stress-lab": []
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
const DEFAULT_RUN_LABEL = "开始分析";
const DISABLED_RUN_LABEL = "功能暂未开放";
const DISABLED_TABS = new Set(["skill-stress-lab"]);
const codePathInput = document.getElementById("code-path");
const fileInput = document.getElementById("code-upload");
const contextTitle = document.getElementById("current-skill-title");
const contextDesc = document.getElementById("current-skill-desc");
const historyList = document.getElementById("history-list");
const historyPanel = document.querySelector(".history-panel");
const recordedHistory = new Set();
historyPanel?.classList.add("is-empty");

const FINAL_STATUSES = new Set(["completed", "failed"]);
const DEFAULT_API = window.location.origin;
const API_BASE = window.HEALTH_AI_API || DEFAULT_API;

navButtons.forEach((btn) => btn.addEventListener("click", () => selectTab(btn.dataset.tab)));
if (runBtn) runBtn.addEventListener("click", runTask);
window.addEventListener("hashchange", () => {
  const target = window.location.hash.replace("#", "");
  if (VALID_TABS.includes(target)) {
    selectTab(target, { skipHash: true });
  }
});

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
  updateRunButtonState();
}

function updateContextBanner() {
  const copy = FEATURE_COPY[activeTab];
  if (copy) {
    if (contextTitle) contextTitle.textContent = copy.title;
    if (contextDesc) contextDesc.textContent = copy.desc;
    document.title = `Health AI · ${copy.title}`;
  }
}

function updateRunButtonState() {
  if (!runBtn) return;
  const disabled = DISABLED_TABS.has(activeTab);
  runBtn.disabled = disabled;
  runBtn.textContent = disabled ? DISABLED_RUN_LABEL : DEFAULT_RUN_LABEL;
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
  fileInput.value = "";
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
  if (DISABLED_TABS.has(activeTab)) {
    setStatus("暂未开放", "info");
    setSummary("该功能已在后台关闭");
    return;
  }
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
}
