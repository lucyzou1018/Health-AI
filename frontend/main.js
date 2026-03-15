const PARAM_SCHEMA = {
  "skill-security-audit": [
    // Upload skill zip file instead of path/URL
  ],
  "multichain-contract-vuln": [
    { id: "chain", label: "链类型", type: "select", options: ["evm", "solana"], placeholder: "evm" }
  ],
  "skill-stress-lab": [
    // 命令模板和工作目录使用默认值，不在界面显示
    { id: "runs", label: "运行次数", type: "number", placeholder: "10", default: "10" },
    { id: "concurrency", label: "并发数", type: "number", placeholder: "3", default: "3" }
  ]
};

const FEATURE_COPY = {
  "skill-security-audit": {
    title: "Skill Security Audit",
    desc: "对指定 Skill 执行安全体检，检查权限、配置、日志并输出 0-100 评分报告。"
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
  return VALID_TABS.includes(hash) ? hash : "skill-security-audit";
})();

// Wallet State
let currentWallet = null;
let walletToken = localStorage.getItem("wallet_token");
const SKILL_LABELS = {
  "skill-security-audit": "Skill 安全审计",
  "multichain-contract-vuln": "合约审计",
  "skill-stress-lab": "压力测试"
};

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
const walletBtn = document.getElementById("wallet-connect");
const walletText = document.getElementById("wallet-text");
const historyFilters = document.querySelectorAll(".filter-btn");
const historyCount = document.getElementById("history-count");
const historyEmpty = document.getElementById("history-empty");
const historyPanel = document.getElementById("history-panel");
const reportPreviewBox = document.getElementById("report-preview");
const paginationEl = document.getElementById("pagination");
const pagePrevBtn = document.getElementById("page-prev");
const pageNextBtn = document.getElementById("page-next");
const pageInfoEl = document.getElementById("page-info");
const recordedHistory = new Set();
let previewTaskId = null;
let currentFile = null;

// Pagination state
let allHistoryTasks = [];
let currentPage = 1;
const ITEMS_PER_PAGE = 10;

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
  updateRunButtonState();
}

function clearCurrentFile() {
  currentFile = null;
  if (fileInput) fileInput.value = "";
  if (uploadZone) uploadZone.classList.remove("has-file");
  if (fileInfo) fileInfo.classList.add("hidden");
  if (fileName) fileName.textContent = "";
  if (fileSize) fileSize.textContent = "";
  updateRunButtonState();
}

function clearResults() {
  // 清除任务状态
  if (statusBox) {
    statusBox.textContent = "未开始";
    statusBox.className = "status";
  }
  if (summaryBox) summaryBox.textContent = "上传 Skill 包后，可在这里查看状态并下载报告。";
  if (artifactBox) artifactBox.classList.add("hidden");
  if (reportPreviewBox) {
    reportPreviewBox.classList.add("hidden");
    reportPreviewBox.innerHTML = "";
    previewTaskId = null;
  }
  updateRunButtonState();
}

function updateRunButtonState() {
  if (!runBtn) return;
  
  const hasFile = currentFile !== null || (fileInput && fileInput.files && fileInput.files[0]);
  const isRunning = statusBox && statusBox.textContent === "运行中...";
  const hasWallet = currentWallet !== null;
  
  // Check Skill Stress Lab params
  let hasValidParams = true;
  if (activeTab === "skill-stress-lab") {
    const runsInput = document.getElementById("param-runs");
    const concurrencyInput = document.getElementById("param-concurrency");
    
    if (runsInput && concurrencyInput) {
      const runs = parseInt(runsInput.value, 10);
      const concurrency = parseInt(concurrencyInput.value, 10);
      
      // Validate: must be positive integers > 0
      if (isNaN(runs) || runs <= 0 || isNaN(concurrency) || concurrency <= 0) {
        hasValidParams = false;
      }
    } else {
      hasValidParams = false;
    }
  }
  
  if (!hasWallet) {
    runBtn.disabled = true;
    runBtn.textContent = "请先连接钱包";
  } else if (!hasFile) {
    runBtn.disabled = true;
    runBtn.textContent = "开始分析";
  } else if (activeTab === "skill-stress-lab" && !hasValidParams) {
    runBtn.disabled = true;
    runBtn.textContent = "开始分析";
  } else if (isRunning) {
    runBtn.disabled = true;
    runBtn.textContent = "分析中...";
  } else {
    runBtn.disabled = false;
    runBtn.textContent = "开始分析";
  }
  
  runBtn.style.opacity = runBtn.disabled ? "0.5" : "1";
  runBtn.style.cursor = runBtn.disabled ? "not-allowed" : "pointer";
}

function formatFileSize(bytes) {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + " " + sizes[i];
}

selectTab(activeTab, { skipHash: true });
updateRunButtonState(); // 初始化按钮状态

function selectTab(tab, opts = {}) {
  if (!PARAM_SCHEMA[tab]) return;
  activeTab = tab;
  navButtons.forEach((btn) => btn.classList.toggle("active", btn.dataset.tab === tab));
  if (!opts.skipHash) {
    window.location.hash = tab;
  }
  renderParamFields();
  updateContextBanner();
  // 清除上传的文件和结果
  clearCurrentFile();
  clearResults();
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
      
      // For number fields, restrict to positive integers only
      if (field.type === "number") {
        input.min = "1";
        input.step = "1";
        // Prevent non-numeric characters, decimal points, and minus sign
        input.addEventListener("keydown", function(e) {
          // Allow: backspace, delete, tab, escape, enter
          if ([46, 8, 9, 27, 13].indexOf(e.keyCode) !== -1 ||
              // Allow: Ctrl+A, Ctrl+C, Ctrl+V, Ctrl+X
              (e.keyCode === 65 && e.ctrlKey === true) ||
              (e.keyCode === 67 && e.ctrlKey === true) ||
              (e.keyCode === 86 && e.ctrlKey === true) ||
              (e.keyCode === 88 && e.ctrlKey === true) ||
              // Allow: home, end, left, right
              (e.keyCode >= 35 && e.keyCode <= 39)) {
            return;
          }
          // Ensure that it is a number and stop the keypress if not
          if ((e.shiftKey || (e.keyCode < 48 || e.keyCode > 57)) && (e.keyCode < 96 || e.keyCode > 105)) {
            e.preventDefault();
          }
        });
        // Clean up pasted content
        input.addEventListener("paste", function(e) {
          e.preventDefault();
          const pastedText = (e.clipboardData || window.clipboardData).getData("text");
          const cleanedText = pastedText.replace(/[^0-9]/g, "");
          if (cleanedText) {
            const num = parseInt(cleanedText, 10);
            if (num > 0) {
              input.value = num;
              updateRunButtonState();
            }
          }
        });
      }
    }
    input.id = `param-${field.id}`;
    // Set default value if provided
    if (field.default !== undefined) {
      if (field.type === "checkbox") {
        input.checked = field.default;
      } else {
        input.value = field.default;
      }
    }
    
    // Add event listener to update button state on value change
    input.addEventListener("input", function() {
      updateRunButtonState();
    });
    
    wrapper.appendChild(input);
    paramContainer.appendChild(wrapper);
  });
  
  // Update button state after rendering fields
  updateRunButtonState();
}

async function runTask() {
  // 检查是否已连接钱包
  if (!currentWallet) {
    alert("请先连接钱包后再进行分析");
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
    // Note: command is set to default value in backend if not provided
    const body = {
      skillType: activeTab,
      codePath: codePathValue || null,
      uploadId: uploadId,
      params,
      walletAddress: currentWallet,
    };
    const headers = { "Content-Type": "application/json" };
    if (walletToken) {
      headers["X-Wallet-Token"] = walletToken;
    }
    const resp = await fetch(`${API_BASE}/api/tasks`, {
      method: "POST",
      headers: headers,
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
  updateRunButtonState();
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
  if (task.reportPath) {
    links.push({ label: "📊 图文报告", href: `report.html?task=${task.taskId}` });
    links.push({ label: "📄 下载报告", href: `${API_BASE}/api/tasks/${task.taskId}/report` });
  }
  if (task.summaryPath) links.push({ label: "📋 下载摘要", href: `${API_BASE}/api/tasks/${task.taskId}/artifact?kind=summary` });
  if (task.logPath) links.push({ label: "📝 下载日志", href: `${API_BASE}/api/tasks/${task.taskId}/artifact?kind=log` });
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
  // Support multichain-contract-vuln, skill-security-audit, and skill-stress-lab
  const supportedTypes = ["multichain-contract-vuln", "skill-security-audit", "skill-stress-lab"];
  if (!task || !supportedTypes.includes(task.skillType) || task.status !== "completed") {
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
      let html = "";
      if (task.skillType === "skill-security-audit") {
        html = buildSecurityAuditSummary(text);
      } else if (task.skillType === "skill-stress-lab") {
        html = buildStressLabSummary(text);
      } else {
        html = buildReportSummary(text);
      }
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
  if (!detectorSummaries.length) return "";
  
  // 按严重程度分组
  const highRisk = ['arbitrary-send-eth', 'reentrancy', 'unchecked-transfer', 'delegatecall'];
  const mediumRisk = ['divide-before-multiply', 'incorrect-equality', 'timestamp', 'low-level-calls'];
  
  const highFindings = detectorSummaries.filter(f => highRisk.some(r => f.name.toLowerCase().includes(r)));
  const mediumFindings = detectorSummaries.filter(f => mediumRisk.some(r => f.name.toLowerCase().includes(r)));
  const otherFindings = detectorSummaries.filter(f => !highFindings.includes(f) && !mediumFindings.includes(f));

  let html = "";
  
  // 统计卡片
  html += `<div class="report-stats-cards">`;
  html += `<div class="stat-card high"><span class="stat-number">${highFindings.length}</span><span class="stat-label">高风险</span></div>`;
  html += `<div class="stat-card medium"><span class="stat-number">${mediumFindings.length}</span><span class="stat-label">中风险</span></div>`;
  html += `<div class="stat-card low"><span class="stat-number">${otherFindings.length}</span><span class="stat-label">低风险</span></div>`;
  html += `<div class="stat-card total"><span class="stat-number">${detectorSummaries.length}</span><span class="stat-label">总计</span></div>`;
  html += `</div>`;

  return html;
}

// Build security audit score cards (6 dimensions)
function buildSecurityAuditSummary(text) {
  if (!text) return "";
  
  const scores = {};
  const lines = text.split(/\r?\n/);
  
  // Parse scores from report (support both Chinese and English formats)
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    // Match formats: "- Privacy: 35" or "隐私安全：35/100"
    const overallMatch = line.match(/(?:Overall Safety|综合安全评分)[:：\/]?\s*(\d+)/i);
    if (overallMatch) scores['Overall'] = parseInt(overallMatch[1]);
    const privacyMatch = line.match(/(?:^-\s*Privacy|隐私安全)[:：\/]?\s*(\d+)/i);
    if (privacyMatch) scores['Privacy'] = parseInt(privacyMatch[1]);
    const privilegeMatch = line.match(/(?:^-\s*Privilege|权限安全)[:：\/]?\s*(\d+)/i);
    if (privilegeMatch) scores['Privilege'] = parseInt(privilegeMatch[1]);
    const memoryMatch = line.match(/(?:^-\s*Memory(?: Footprint)?|内存安全)[:：\/]?\s*(\d+)/i);
    if (memoryMatch) scores['Memory'] = parseInt(memoryMatch[1]);
    const tokenMatch = line.match(/(?:^-\s*Token(?: Cost)?|Token 安全)[:：\/]?\s*(\d+)/i);
    if (tokenMatch) scores['Token'] = parseInt(tokenMatch[1]);
    const failureMatch = line.match(/(?:^-\s*(?:Failure Rate|Stability)|稳定性)[:：\/]?\s*(\d+)/i);
    if (failureMatch) scores['Failure'] = parseInt(failureMatch[1]);
  }
  
  // Fallback: calculate overall if not parsed
  let overallScore = scores['Overall'] || 0;
  if (!overallScore) {
    const scoreValues = Object.values(scores).filter(s => s > 0);
    overallScore = scoreValues.length ? Math.round(scoreValues.reduce((a, b) => a + b, 0) / scoreValues.length) : 0;
  }
  
  // Get individual scores
  const privacyScore = scores['Privacy'] || 0;
  const privilegeScore = scores['Privilege'] || 0;
  const memoryScore = scores['Memory'] || 0;
  const tokenScore = scores['Token'] || 0;
  const failureScore = scores['Failure'] || 0;
  
  // Determine score class based on value (higher = safer)
  function getScoreClass(score) {
    if (score >= 80) return 'low';      // 优秀 - 绿色
    if (score >= 60) return 'total';    // 良好 - 蓝色  
    if (score >= 40) return 'medium';   // 一般 - 黄色
    return 'high';                      // 需改进 - 红色
  }
  
  // Build 6 score cards - emoji and text on same line
  let html = `<div class="report-stats-cards" style="grid-template-columns: repeat(6, 1fr);">`;
  html += `<div class="stat-card ${getScoreClass(overallScore)}"><span class="stat-number">${overallScore}</span><span class="stat-label"><span class="stat-icon">📊</span>综合</span></div>`;
  html += `<div class="stat-card ${getScoreClass(privacyScore)}"><span class="stat-number">${privacyScore}</span><span class="stat-label"><span class="stat-icon">🔒</span>隐私</span></div>`;
  html += `<div class="stat-card ${getScoreClass(privilegeScore)}"><span class="stat-number">${privilegeScore}</span><span class="stat-label"><span class="stat-icon">🔐</span>权限</span></div>`;
  html += `<div class="stat-card ${getScoreClass(memoryScore)}"><span class="stat-number">${memoryScore}</span><span class="stat-label"><span class="stat-icon">💾</span>内存</span></div>`;
  html += `<div class="stat-card ${getScoreClass(tokenScore)}"><span class="stat-number">${tokenScore}</span><span class="stat-label"><span class="stat-icon">🪙</span>Token</span></div>`;
  html += `<div class="stat-card ${getScoreClass(failureScore)}"><span class="stat-number">${failureScore}</span><span class="stat-label"><span class="stat-icon">✅</span>稳定</span></div>`;
  html += `</div>`;
  
  // Add score legend
  html += `<div style="margin-top: 8px; padding: 8px 12px; background: rgba(99, 102, 241, 0.1); border-radius: 6px; font-size: 12px; color: #94a3b8;">`;
  html += `评分说明：80-100=优秀 🟢 | 60-79=良好 🔵 | 40-59=一般 🟡 | <40=需改进 🔴`;
  html += `</div>`;
  
  return html;
}

// Build Skill Stress Lab 5-dimension score cards
function buildStressLabSummary(text) {
  if (!text) return "";
  
  const scores = {};
  const lines = text.split(/\r?\n/);
  
  // Parse 5-dimension scores from report
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    // Match patterns like "🛡️ **稳定性** | 100/100" or "稳定性 | 100/100"
    const stabilityMatch = line.match(/(?:🛡️\s*)?(?:稳定性|Stability)[^\d]*(\d+)\/100/i);
    if (stabilityMatch) scores['Stability'] = parseInt(stabilityMatch[1]);
    
    const performanceMatch = line.match(/(?:⚡\s*)?(?:性能|Performance)[^\d]*(\d+)\/100/i);
    if (performanceMatch) scores['Performance'] = parseInt(performanceMatch[1]);
    
    const resourceMatch = line.match(/(?:💾\s*)?(?:资源|Resource)[^\d]*(\d+)\/100/i);
    if (resourceMatch) scores['Resource'] = parseInt(resourceMatch[1]);
    
    const consistencyMatch = line.match(/(?:🔄\s*)?(?:一致性|Consistency)[^\d]*(\d+)\/100/i);
    if (consistencyMatch) scores['Consistency'] = parseInt(consistencyMatch[1]);
    
    const recoveryMatch = line.match(/(?:🆘\s*)?(?:恢复|Recovery)[^\d]*(\d+)\/100/i);
    if (recoveryMatch) scores['Recovery'] = parseInt(recoveryMatch[1]);
    
    // Match overall score like "综合评分：97/100" or "Overall: 97/100"
    const overallMatch = line.match(/(?:🎯\s*|综合|Overall)[^\d]*(\d+)\/100/i);
    if (overallMatch && !scores['Overall']) scores['Overall'] = parseInt(overallMatch[1]);
  }
  
  // Get scores with defaults
  let overallScore = scores['Overall'] || 0;
  const stabilityScore = scores['Stability'] || 0;
  const performanceScore = scores['Performance'] || 0;
  const resourceScore = scores['Resource'] || 0;
  const consistencyScore = scores['Consistency'] || 0;
  const recoveryScore = scores['Recovery'] || 0;
  
  // Calculate overall if not parsed
  if (!overallScore) {
    const scoreValues = [stabilityScore, performanceScore, resourceScore, consistencyScore, recoveryScore].filter(s => s > 0);
    overallScore = scoreValues.length ? Math.round(scoreValues.reduce((a, b) => a + b, 0) / scoreValues.length) : 0;
  }
  
  // Determine score class (higher = better)
  function getScoreClass(score) {
    if (score >= 80) return 'low';      // 优秀 - 绿色
    if (score >= 60) return 'total';    // 良好 - 蓝色
    if (score >= 40) return 'medium';   // 一般 - 黄色
    return 'high';                      // 需改进 - 红色
  }
  
  // Build 6 score cards (overall + 5 dimensions) - emoji and text on same line
  let html = `<div class="report-stats-cards" style="grid-template-columns: repeat(6, 1fr);">`;
  html += `<div class="stat-card ${getScoreClass(overallScore)}"><span class="stat-number">${overallScore}</span><span class="stat-label"><span class="stat-icon">🎯</span>综合</span></div>`;
  html += `<div class="stat-card ${getScoreClass(stabilityScore)}"><span class="stat-number">${stabilityScore}</span><span class="stat-label"><span class="stat-icon">🛡️</span>稳定</span></div>`;
  html += `<div class="stat-card ${getScoreClass(performanceScore)}"><span class="stat-number">${performanceScore}</span><span class="stat-label"><span class="stat-icon">⚡</span>性能</span></div>`;
  html += `<div class="stat-card ${getScoreClass(resourceScore)}"><span class="stat-number">${resourceScore}</span><span class="stat-label"><span class="stat-icon">💾</span>资源</span></div>`;
  html += `<div class="stat-card ${getScoreClass(consistencyScore)}"><span class="stat-number">${consistencyScore}</span><span class="stat-label"><span class="stat-icon">🔄</span>一致</span></div>`;
  html += `<div class="stat-card ${getScoreClass(recoveryScore)}"><span class="stat-number">${recoveryScore}</span><span class="stat-label"><span class="stat-icon">🆘</span>恢复</span></div>`;
  html += `</div>`;
  
  // Add score legend
  html += `<div style="margin-top: 8px; padding: 8px 12px; background: rgba(99, 102, 241, 0.1); border-radius: 6px; font-size: 12px; color: #94a3b8;">`;
  html += `评分说明：80-100=优秀 🟢 | 60-79=良好 🔵 | 40-59=一般 🟡 | <40=需改进 🔴`;
  html += `</div>`;
  
  return html;
}

// 统一的问题提取函数
function extractAllIssues(text) {
  const items = [];
  const lines = text.split(/\r?\n/);
  let currentDetector = "";
  let currentDesc = "";
  
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    
    if (line.startsWith("Detector:")) {
      currentDetector = line.replace("Detector:", "").trim();
      currentDesc = "";
      continue;
    }
    
    if (line.match(/^\s/)) continue;
    
    if (currentDetector && !currentDesc && line.trim() && !line.startsWith("Reference:")) {
      currentDesc = line.trim().replace(/^[-•]\s*/, '');
      continue;
    }
    
    // 匹配位置 - 统一三种格式
    let location = null;
    const match1 = line.match(/(\w+\.sol#\d+(?:-\d+)?)/);
    const match2 = line.match(/in\s+\w+\([^)]*\)\s*\(([^)]+\.sol#\d+(?:-\d+)?)\)/);
    const match3 = line.match(/\((src\/[^)]+\.sol#\d+(?:-\d+)?)\)/);
    location = match1 ? match1[1] : (match2 ? match2[1] : (match3 ? match3[1] : null));
    
    if (location && currentDetector) {
      items.push({
        name: currentDetector,
        desc: currentDesc || "详见报告",
        location: location
      });
    }
  }
  return items;
}

function extractKeyRisks(text) {
  const items = extractAllIssues(text);
  return items.map(item => ({
    type: item.name,
    location: item.location,
    desc: item.desc
  }));
}

function extractDetectorSummaries(text) {
  return extractAllIssues(text);
}

function buildDetectorRecommendation(name) {
  return (
    DETECTOR_REMEDIATIONS[name] ||
    `针对 ${name} 告警，请复核相应业务逻辑并按报告中的修复建议加固。`
  );
}

// --------------------------- Wallet Functions ---------------------------

function formatWalletAddress(address) {
  if (!address) return "";
  return address.slice(0, 6) + "..." + address.slice(-4);
}

function updateWalletUI() {
  if (currentWallet && walletBtn && walletText) {
    walletBtn.classList.add("connected");
    walletText.textContent = formatWalletAddress(currentWallet);
  } else if (walletBtn && walletText) {
    walletBtn.classList.remove("connected");
    walletText.textContent = "连接钱包";
  }
}

// 检测可用的钱包提供者
function detectWalletProviders() {
  const providers = [];
  
  // 检测 OKX Wallet
  if (window.okxwallet) {
    providers.push({
      name: "OKX Wallet",
      icon: "🔵",
      provider: window.okxwallet
    });
  }
  
  // 检测 MetaMask
  if (window.ethereum) {
    // 检查是否是 MetaMask
    const isMetaMask = window.ethereum.isMetaMask || 
                       (window.ethereum.providers && window.ethereum.providers.some(p => p.isMetaMask));
    
    if (isMetaMask && !window.ethereum.providers) {
      // 单一 MetaMask
      providers.push({
        name: "MetaMask",
        icon: "🦊",
        provider: window.ethereum
      });
    } else if (window.ethereum.providers) {
      // 多个钱包插件
      window.ethereum.providers.forEach(provider => {
        if (provider.isMetaMask && !providers.some(p => p.name === "MetaMask")) {
          providers.push({
            name: "MetaMask",
            icon: "🦊",
            provider: provider
          });
        }
      });
    }
  }
  
  return providers;
}

// 显示钱包选择弹窗
function showWalletSelector(providers) {
  return new Promise((resolve, reject) => {
    // 创建弹窗
    const modal = document.createElement("div");
    modal.className = "wallet-modal";
    modal.innerHTML = `
      <div class="wallet-modal-backdrop"></div>
      <div class="wallet-modal-content">
        <h3>选择钱包</h3>
        <div class="wallet-list">
          ${providers.map((p, i) => `
            <button class="wallet-option" data-index="${i}">
              <span class="wallet-option-icon">${p.icon}</span>
              <span class="wallet-option-name">${p.name}</span>
            </button>
          `).join("")}
        </div>
        <button class="wallet-modal-close">取消</button>
      </div>
    `;
    
    // 添加样式
    const style = document.createElement("style");
    style.textContent = `
      .wallet-modal {
        position: fixed;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        z-index: 1000;
        display: flex;
        align-items: center;
        justify-content: center;
      }
      .wallet-modal-backdrop {
        position: absolute;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        background: rgba(0,0,0,0.5);
      }
      .wallet-modal-content {
        position: relative;
        background: var(--bg-secondary);
        border: 1px solid var(--border-subtle);
        border-radius: var(--radius-lg);
        padding: 24px;
        min-width: 280px;
        max-width: 90vw;
      }
      .wallet-modal-content h3 {
        margin: 0 0 16px 0;
        font-size: 16px;
        text-align: center;
      }
      .wallet-list {
        display: flex;
        flex-direction: column;
        gap: 8px;
        margin-bottom: 16px;
      }
      .wallet-option {
        display: flex;
        align-items: center;
        gap: 12px;
        padding: 12px 16px;
        background: var(--bg-tertiary);
        border: 1px solid var(--border-subtle);
        border-radius: var(--radius);
        color: var(--text-primary);
        font-size: 14px;
        cursor: pointer;
        transition: all 150ms ease;
      }
      .wallet-option:hover {
        border-color: var(--accent);
        background: var(--accent-subtle);
      }
      .wallet-option-icon {
        font-size: 20px;
      }
      .wallet-modal-close {
        width: 100%;
        padding: 10px;
        background: transparent;
        border: 1px solid var(--border-subtle);
        border-radius: var(--radius);
        color: var(--text-secondary);
        font-size: 13px;
        cursor: pointer;
      }
      .wallet-modal-close:hover {
        border-color: var(--border-default);
        color: var(--text-primary);
      }
    `;
    document.head.appendChild(style);
    document.body.appendChild(modal);
    
    // 处理选择
    modal.querySelectorAll(".wallet-option").forEach(btn => {
      btn.addEventListener("click", () => {
        const index = parseInt(btn.dataset.index);
        document.body.removeChild(modal);
        document.head.removeChild(style);
        resolve(providers[index]);
      });
    });
    
    // 处理关闭
    modal.querySelector(".wallet-modal-close").addEventListener("click", () => {
      document.body.removeChild(modal);
      document.head.removeChild(style);
      reject(new Error("用户取消"));
    });
    
    modal.querySelector(".wallet-modal-backdrop").addEventListener("click", () => {
      document.body.removeChild(modal);
      document.head.removeChild(style);
      reject(new Error("用户取消"));
    });
  });
}

async function connectWallet() {
  // 检测可用的钱包
  const providers = detectWalletProviders();
  
  if (providers.length === 0) {
    // 没有安装任何钱包
    const installModal = document.createElement("div");
    installModal.className = "wallet-modal";
    installModal.innerHTML = `
      <div class="wallet-modal-backdrop"></div>
      <div class="wallet-modal-content">
        <h3>未检测到钱包</h3>
        <p style="color: var(--text-secondary); font-size: 13px; margin-bottom: 16px;">
          请安装以下钱包之一：
        </p>
        <div class="wallet-list">
          <a href="https://www.okx.com/web3" target="_blank" class="wallet-option">
            <span class="wallet-option-icon">🔵</span>
            <span class="wallet-option-name">OKX Wallet</span>
          </a>
          <a href="https://metamask.io/download/" target="_blank" class="wallet-option">
            <span class="wallet-option-icon">🦊</span>
            <span class="wallet-option-name">MetaMask</span>
          </a>
        </div>
        <button class="wallet-modal-close">关闭</button>
      </div>
    `;
    
    const style = document.createElement("style");
    style.textContent = `
      .wallet-modal {
        position: fixed;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        z-index: 1000;
        display: flex;
        align-items: center;
        justify-content: center;
      }
      .wallet-modal-backdrop {
        position: absolute;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        background: rgba(0,0,0,0.5);
      }
      .wallet-modal-content {
        position: relative;
        background: var(--bg-secondary);
        border: 1px solid var(--border-subtle);
        border-radius: var(--radius-lg);
        padding: 24px;
        min-width: 280px;
        max-width: 90vw;
      }
      .wallet-modal-content h3 {
        margin: 0 0 16px 0;
        font-size: 16px;
        text-align: center;
      }
      .wallet-list {
        display: flex;
        flex-direction: column;
        gap: 8px;
        margin-bottom: 16px;
      }
      .wallet-option {
        display: flex;
        align-items: center;
        gap: 12px;
        padding: 12px 16px;
        background: var(--bg-tertiary);
        border: 1px solid var(--border-subtle);
        border-radius: var(--radius);
        color: var(--text-primary);
        font-size: 14px;
        cursor: pointer;
        text-decoration: none;
        transition: all 150ms ease;
      }
      .wallet-option:hover {
        border-color: var(--accent);
        background: var(--accent-subtle);
      }
      .wallet-option-icon {
        font-size: 20px;
      }
      .wallet-modal-close {
        width: 100%;
        padding: 10px;
        background: transparent;
        border: 1px solid var(--border-subtle);
        border-radius: var(--radius);
        color: var(--text-secondary);
        font-size: 13px;
        cursor: pointer;
      }
      .wallet-modal-close:hover {
        border-color: var(--border-default);
        color: var(--text-primary);
      }
    `;
    document.head.appendChild(style);
    document.body.appendChild(installModal);
    
    installModal.querySelector(".wallet-modal-close").addEventListener("click", () => {
      document.body.removeChild(installModal);
      document.head.removeChild(style);
    });
    installModal.querySelector(".wallet-modal-backdrop").addEventListener("click", () => {
      document.body.removeChild(installModal);
      document.head.removeChild(style);
    });
    return;
  }
  
  let selectedProvider;
  
  try {
    // 如果有多个钱包，显示选择弹窗
    if (providers.length > 1) {
      selectedProvider = await showWalletSelector(providers);
    } else {
      selectedProvider = providers[0];
    }
  } catch (err) {
    // 用户取消
    return;
  }

  try {
    // 请求连接钱包
    const accounts = await selectedProvider.provider.request({
      method: "eth_requestAccounts"
    });
    
    if (accounts.length === 0) {
      alert("请授权连接钱包");
      return;
    }

    const walletAddress = accounts[0];
    
    // 获取 nonce
    const nonceResp = await fetch(`${API_BASE}/api/wallet/nonce?wallet_address=${walletAddress}`);
    const { message } = await nonceResp.json();
    
    // 请求签名
    const signature = await selectedProvider.provider.request({
      method: "personal_sign",
      params: [message, walletAddress]
    });
    
    // 验证签名
    const verifyResp = await fetch(`${API_BASE}/api/wallet/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        walletAddress: walletAddress,
        signature: signature,
        message: message
      })
    });
    
    if (!verifyResp.ok) {
      throw new Error("验证失败");
    }
    
    const { token } = await verifyResp.json();
    
    // 保存 token 和钱包地址
    localStorage.setItem("wallet_token", token);
    localStorage.setItem("wallet_address", walletAddress);
    walletToken = token;
    currentWallet = walletAddress;
    
    updateWalletUI();
    updateRunButtonState();
    loadWalletHistory();
    
  } catch (err) {
    console.error("Wallet connection failed:", err);
    alert("连接钱包失败: " + err.message);
  }
}

function disconnectWallet() {
  localStorage.removeItem("wallet_token");
  localStorage.removeItem("wallet_address");
  walletToken = null;
  currentWallet = null;
  updateWalletUI();
  updateRunButtonState();
  
  // 清空历史列表
  if (historyList) {
    historyList.innerHTML = '<li class="empty" id="history-empty">请先连接钱包查看历史记录</li>';
  }
}

async function loadWalletHistory(skillType = "all") {
  if (!walletToken || !historyList) return;
  
  try {
    const url = new URL(`${API_BASE}/api/wallet/history`);
    if (skillType && skillType !== "all") {
      url.searchParams.set("skill_type", skillType);
    }
    url.searchParams.set("limit", "20");
    
    const resp = await fetch(url, {
      headers: { "X-Wallet-Token": walletToken }
    });
    
    if (!resp.ok) {
      if (resp.status === 401) {
        // Token 过期，重新登录
        disconnectWallet();
        return;
      }
      throw new Error("获取历史记录失败");
    }
    
    const tasks = await resp.json();
    renderWalletHistory(tasks);
    
  } catch (err) {
    console.error("Failed to load history:", err);
  }
}

function renderWalletHistory(tasks) {
  // Store all tasks for pagination
  allHistoryTasks = tasks;
  recordedHistory.clear();
  tasks.forEach(function(t) { recordedHistory.add(t.taskId); });
  currentPage = 1;
  renderHistoryPage();
  if (historyCount) historyCount.textContent = tasks.length + " 条记录";
}

function renderHistoryPage() {
  if (!historyList) return;
  
  var activeFilterBtn = document.querySelector('.filter-btn.active');
  var activeFilter = activeFilterBtn ? activeFilterBtn.dataset.filter : 'all';
  
  var filteredTasks = allHistoryTasks;
  if (activeFilter !== 'all') {
    filteredTasks = allHistoryTasks.filter(function(t) { return t.skillType === activeFilter; });
  }
  
  var totalPages = Math.ceil(filteredTasks.length / ITEMS_PER_PAGE);
  if (currentPage > totalPages) currentPage = Math.max(1, totalPages);
  
  var startIndex = (currentPage - 1) * ITEMS_PER_PAGE;
  var endIndex = startIndex + ITEMS_PER_PAGE;
  var pageTasks = filteredTasks.slice(startIndex, endIndex);
  
  historyList.innerHTML = '';
  
  if (pageTasks.length === 0) {
    historyList.innerHTML = '<li class="empty">暂无分析记录</li>';
    if (paginationEl) paginationEl.style.display = 'none';
    return;
  }
  
  if (historyPanel) historyPanel.classList.remove("is-empty");
  if (paginationEl) paginationEl.style.display = 'flex';
  
  for (var i = 0; i < pageTasks.length; i++) {
    var task = pageTasks[i];
    var item = createHistoryItem(task);
    historyList.appendChild(item);
  }
  
  updatePagination(totalPages);
}

function createHistoryItem(task) {
  var li = document.createElement("li");
  li.className = "history-item";
  
  var isCompleted = task.status === "completed";
  var isFailed = task.status === "failed";
  var statusIcon = isCompleted ? "✅" : isFailed ? "❌" : "⏳";
  var skillLabel = SKILL_LABELS[task.skillType] || task.skillType;
  
  li.innerHTML = 
    '<div class="history-header">' +
      '<span class="history-skill">' + skillLabel + '</span>' +
      '<span class="history-time">' + formatHistoryTime(task.createdAt) + '</span>' +
    '</div>' +
    '<div class="history-status-row">' +
      '<span class="history-status">' + statusIcon + ' ' + task.status + '</span>' +
    '</div>' +
    (isCompleted ? 
      '<div class="history-report-row"><a href="report.html?task=' + task.taskId + '" target="_blank" class="history-link">查看报告</a></div>' : 
      '<div class="history-report-row"><span class="history-link-placeholder"></span></div>');
  
  return li;
}

function updatePagination(totalPages) {
  if (!pagePrevBtn || !pageNextBtn || !pageInfoEl) return;
  
  pagePrevBtn.disabled = currentPage <= 1;
  pageNextBtn.disabled = currentPage >= totalPages || totalPages === 0;
  pageInfoEl.textContent = '第 ' + currentPage + ' 页 / 共 ' + totalPages + ' 页';
}

function goToPage(page) {
  currentPage = page;
  renderHistoryPage();
}

// 钱包按钮事件
if (walletBtn) {
  walletBtn.addEventListener("click", function() {
    if (currentWallet) {
      if (confirm("是否断开钱包连接？")) {
        disconnectWallet();
      }
    } else {
      connectWallet();
    }
  });
}

// 历史记录筛选按钮
historyFilters.forEach(function(btn) {
  btn.addEventListener("click", function() {
    historyFilters.forEach(function(b) { b.classList.remove("active"); });
    btn.classList.add("active");
    currentPage = 1;
    renderHistoryPage();
  });
});

// 分页按钮事件
if (pagePrevBtn) {
  pagePrevBtn.addEventListener("click", function() {
    if (currentPage > 1) {
      goToPage(currentPage - 1);
    }
  });
}

if (pageNextBtn) {
  pageNextBtn.addEventListener("click", function() {
    var activeFilterBtn = document.querySelector('.filter-btn.active');
    var activeFilter = activeFilterBtn ? activeFilterBtn.dataset.filter : 'all';
    
    var filteredTasks = allHistoryTasks;
    if (activeFilter !== 'all') {
      filteredTasks = allHistoryTasks.filter(function(t) { return t.skillType === activeFilter; });
    }
    var totalPages = Math.ceil(filteredTasks.length / ITEMS_PER_PAGE);
    if (currentPage < totalPages) {
      goToPage(currentPage + 1);
    }
  });
}

// 检查本地存储的钱包登录状态
function initWallet() {
  const savedAddress = localStorage.getItem("wallet_address");
  const savedToken = localStorage.getItem("wallet_token");
  if (savedAddress && savedToken) {
    currentWallet = savedAddress;
    walletToken = savedToken;
    updateWalletUI();
    updateRunButtonState();
    loadWalletHistory();
  }
}

// 页面加载时初始化钱包
initWallet();

