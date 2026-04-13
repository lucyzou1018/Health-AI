// ── 设备指纹（仅使用用户无法通过软件修改的硬件属性）────────────────────────
// 包含：物理屏幕参数、CPU 核心数、内存大小、Canvas GPU 渲染指纹、WebGL GPU 型号
// 排除：userAgent（DevTools 可改）、language（浏览器设置可改）、timezone（OS 可改）
let _deviceIdCache = null;
async function getDeviceId() {
  if (_deviceIdCache) return _deviceIdCache;
  const components = [
    // 物理显示器参数（由硬件决定，无法通过软件修改）
    `${screen.width}x${screen.height}x${screen.colorDepth}`,
    // CPU 核心数
    String(navigator.hardwareConcurrency || ""),
    // 内存大小（GB 取整，由硬件决定）
    String(navigator.deviceMemory || ""),
    // OS 平台（macOS/Win32/Linux 等，基本不变）
    navigator.platform || "",
  ];

  // Canvas 指纹：GPU 渲染管线决定，跨浏览器在同一台机器上保持一致
  try {
    const canvas = document.createElement("canvas");
    const ctx = canvas.getContext("2d");
    ctx.textBaseline = "top";
    ctx.font = "14px Arial";
    ctx.fillStyle = "#f60";
    ctx.fillRect(0, 0, 100, 20);
    ctx.fillStyle = "#069";
    ctx.fillText("device-fp-🔐", 2, 2);
    ctx.fillStyle = "rgba(102,204,0,0.7)";
    ctx.fillText("device-fp-🔐", 4, 4);
    components.push(canvas.toDataURL());
  } catch (_) {}

  // WebGL GPU 型号（renderer/vendor 字符串，由显卡硬件决定）
  try {
    const gl = document.createElement("canvas").getContext("webgl")
            || document.createElement("canvas").getContext("experimental-webgl");
    if (gl) {
      const ext = gl.getExtension("WEBGL_debug_renderer_info");
      if (ext) {
        components.push(gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) || "");
        components.push(gl.getParameter(ext.UNMASKED_VENDOR_WEBGL) || "");
      } else {
        components.push(gl.getParameter(gl.RENDERER) || "");
        components.push(gl.getParameter(gl.VENDOR) || "");
      }
    }
  } catch (_) {}

  const raw = components.join("|");
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(raw));
  _deviceIdCache = Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")
    .substring(0, 32);
  return _deviceIdCache;
}

const PARAM_SCHEMA = {
  "skill-security-audit": [
    // Upload skill zip file instead of path/URL
  ],
  "multichain-contract-vuln": [
    { id: "chain", label: "Chain Type", type: "select", options: ["evm", "solana"], placeholder: "evm" }
  ],
  "skill-stress-lab": [
    // command template and workdir use default values, not shown in UI
    { id: "runs", label: "Runs", type: "number", placeholder: "Enter 1 – 100", default: "10", min: 1, max: 100, hint: "Integer between 1 and 100" },
    { id: "concurrency", label: "Concurrency", type: "number", placeholder: "Enter 1 – 100", default: "3", min: 1, max: 100, hint: "Integer between 1 and 100" }
  ]
};

const FEATURE_COPY = {
  "skill-security-audit": {
    title: "Skill Security Audit",
    desc: "One-click comprehensive scan for Skill security risks — intelligently detects permission vulnerabilities and configuration issues, outputs a multi-dimensional health score."
  },
  "multichain-contract-vuln": {
    title: "Contract Audit",
    desc: "One-click scan of multi-chain contract source code, precise vulnerability detection, professional audit report generation."
  },
  "skill-stress-lab": {
    title: "Stress Test",
    desc: "One-click concurrent stress testing, real-time performance metrics collection, comprehensive system capacity evaluation."
  }
};

function workspaceI18n(key) {
  const dict = {
    en: {
      signInFirst: "Sign In First",
      startAnalysis: "Start Analysis",
      analyzing: "Analyzing...",
      notStarted: "Not Started",
      emptySummary: "Upload a Skill package to view status and download reports here.",
      scanComplete: "Scan Complete",
      scanFailed: "Scan Failed",
      analyzingEllipsis: "Analyzing…",
      queued: "Queued",
      loading: "Loading…",
      refreshing: "Refreshing task status…",
      titlePrefix: "CodeAutrix · ",
      viewReport: "View Report",
      downloadReport: "Download Report",
      shareTo: "Share to",
      completedSecurity: "Security scan completed. Your health score report is ready.",
      completedContract: "Contract audit completed. Vulnerability report is ready.",
      completedStress: "Stress test completed. Performance report is ready.",
      completedDefault: "completed. Your report is ready to download.",
      runningSecurity: "Scanning your Skill package for vulnerabilities…",
      runningContract: "Auditing smart contract across chains…",
      runningStress: "Running security pre-check before stress test…",
      runningDefault: "Analysis in progress, please wait…",
      overall: "Overall",
      privacy: "Privacy",
      privilege: "Privilege",
      integrity: "Integrity",
      dependencyRisk: "Dependency Risk",
      stability: "Stability",
      accessControl: "Access Control",
      financialSecurity: "Financial Security",
      randomnessOracle: "Randomness & Oracle",
      dosResistance: "DoS Resistance",
      businessLogic: "Business Logic",
      performance: "Performance",
      resource: "Resource",
      consistency: "Consistency",
      recovery: "Recovery",
      highRisk: "High Risk",
      mediumRisk: "Medium Risk",
      lowRisk: "Low Risk",
      total: "Total",
      scoreExcellent: "Excellent",
      scoreGood: "Good",
      scoreCaution: "Caution",
      scoreRisk: "Risk",
      downloadFailed: "Download failed"
    },
    "zh-CN": {
      signInFirst: "请先登录",
      startAnalysis: "开始分析",
      analyzing: "分析中...",
      notStarted: "未开始",
      emptySummary: "上传 Skill 代码包后，可在这里查看状态并下载报告。",
      scanComplete: "扫描完成",
      scanFailed: "扫描失败",
      analyzingEllipsis: "分析中…",
      queued: "排队中",
      loading: "加载中…",
      refreshing: "正在刷新任务状态…",
      titlePrefix: "CodeAutrix · ",
      viewReport: "查看报告",
      downloadReport: "下载报告",
      shareTo: "分享到",
      completedSecurity: "安全扫描完成，健康评分报告已生成。",
      completedContract: "合约审计完成，漏洞报告已生成。",
      completedStress: "压力测试完成，性能报告已生成。",
      completedDefault: "分析完成，报告可下载。",
      runningSecurity: "正在扫描 Skill 代码包中的漏洞…",
      runningContract: "正在跨链审计智能合约…",
      runningStress: "正在运行压力测试前安全预检…",
      runningDefault: "分析进行中，请稍候…",
      overall: "综合",
      privacy: "隐私",
      privilege: "权限",
      integrity: "完整性",
      dependencyRisk: "依赖风险",
      stability: "稳定性",
      accessControl: "访问控制",
      financialSecurity: "金融安全",
      randomnessOracle: "随机数与预言机",
      dosResistance: "抗 DoS",
      businessLogic: "业务逻辑",
      performance: "性能",
      resource: "资源",
      consistency: "一致性",
      recovery: "恢复",
      highRisk: "高风险",
      mediumRisk: "中风险",
      lowRisk: "低风险",
      total: "总计",
      scoreExcellent: "优秀",
      scoreGood: "良好",
      scoreCaution: "警告",
      scoreRisk: "风险",
      downloadFailed: "下载失败"
    }
  };
  const lang = getCurrentUILang();
  return (dict[lang] || dict.en)[key] || dict.en[key] || key;
}

const VALID_TABS = Object.keys(PARAM_SCHEMA);
let activeTab = (function () {
  const hash = window.location.hash.replace("#", "");
  return VALID_TABS.includes(hash) ? hash : "skill-security-audit";
})();

// Login State
let currentWallet = null;
let walletToken = localStorage.getItem("wallet_token");
let loginType = localStorage.getItem("login_type"); // "wallet" or "google"
let loginEmail = localStorage.getItem("login_email");

// Google OAuth Client ID
const GOOGLE_CLIENT_ID = window.HEALTH_AI_GOOGLE_CLIENT_ID || "744175699896-h7k636bv5g8bggvgdumdoqt3om6pcpk9.apps.googleusercontent.com";
const GITHUB_CLIENT_ID = window.HEALTH_AI_GITHUB_CLIENT_ID || (function() {
  var h = window.location.hostname;
  if (h === "codeautrix.agentese.ai") return "Ov23liE0GA6KVy3Qs4vc";
  if (h === "health-ai-alpha-six.vercel.app") return "Ov23livecFSIM0UymN3w";
  return "Ov23lidd5lnCSTryITS5"; // localhost dev
})();
const SKILL_LABELS = {
  "skill-security-audit": "Skill Security Audit",
  "multichain-contract-vuln": "Contract Audit",
  "skill-stress-lab": "Stress Test"
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
const historyPanel = document.getElementById("history-panel");
const reportPreviewBox = document.getElementById("report-preview");
const paginationEl = document.getElementById("pagination");
const pagePrevBtn = document.getElementById("page-prev");
const pageNextBtn = document.getElementById("page-next");
const pageInfoEl = document.getElementById("page-info");
const recordedHistory = new Set();
let previewTaskId = null;
let currentFile = null;

function getCurrentUILang() {
  try {
    return localStorage.getItem("codeautrix_lang") || "en";
  } catch (_) {
    return "en";
  }
}

function historyI18n(key) {
  const dict = {
    en: {
      signInToViewHistory: "Sign In to view history",
      sessionUnavailable: "Session unavailable. Refresh later to reload history.",
      records: "records",
      noAnalysisRecords: "No analysis records found",
      done: "Done",
      failed: "Failed",
      processing: "Processing",
      viewReport: "View Report",
      shareToX: "Share to",
      downloadPdf: "Download PDF",
      pdfButton: "↓ PDF",
      pagePrefix: "Page ",
      pageSuffix: ""
    },
    "zh-CN": {
      signInToViewHistory: "登录后查看历史记录",
      sessionUnavailable: "当前会话不可用，请稍后刷新重新加载历史记录。",
      records: "条记录",
      noAnalysisRecords: "暂无分析记录",
      done: "已完成",
      failed: "失败",
      processing: "处理中",
      viewReport: "查看报告",
      shareToX: "分享到",
      downloadPdf: "下载 PDF",
      pdfButton: "↓ PDF",
      pagePrefix: "第 ",
      pageSuffix: " 页"
    }
  };
  const lang = getCurrentUILang();
  const val = (dict[lang] || dict.en)[key];
  if (val !== undefined) return val;
  const enVal = dict.en[key];
  return enVal !== undefined ? enVal : key;
}
// 每个 skill 类型是否有任务正在运行
const runningTabs = {
  "skill-security-audit": false,
  "multichain-contract-vuln": false,
  "skill-stress-lab": false,
};

// Per-tab state: stores the last known task and polling message for each tab.
// Used to restore the correct UI when the user switches tabs while a task runs.
const lastTaskPerTab = {
  "skill-security-audit":     null,
  "multichain-contract-vuln": null,
  "skill-stress-lab":         null,
};
const pollingMsgPerTab = {
  "skill-security-audit":     null,
  "multichain-contract-vuln": null,
  "skill-stress-lab":         null,
};

// Pagination state
let allHistoryTasks = [];
let currentPage = 1;
const ITEMS_PER_PAGE = 5;

historyPanel?.classList.add("is-empty");

const FINAL_STATUSES = new Set(["completed", "failed"]);

// 各 tab 的文件大小上限 (MB)
const MAX_FILE_SIZES = {
  "skill-security-audit":    10,
  "multichain-contract-vuln": 10,
  "skill-stress-lab":         10,
};

function showUploadError(msg) {
  const el = document.getElementById("upload-error");
  if (!el) return;
  el.innerHTML =
    `<svg class="ue-icon" width="14" height="14" viewBox="0 0 14 14" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"><circle cx="7" cy="7" r="6"/><path d="M7 4.5v2.8M7 9.5h.01"/></svg>` +
    `<span class="ue-text">${msg}</span>`;
  el.classList.remove("hidden");
  uploadZone?.classList.add("has-error");
}

function clearUploadError() {
  const el = document.getElementById("upload-error");
  if (!el) return;
  el.classList.add("hidden");
  uploadZone?.classList.remove("has-error");
}
// Local dev: frontend runs on :3000 (static), backend on :8000 (FastAPI)
// Production (Vercel): vercel.json rewrites /api/* to backend, so origin works fine
const DEFAULT_API = (window.location.hostname === 'localhost' && ['3000','8091'].includes(window.location.port))
  ? 'http://localhost:8000'
  : window.location.origin;
const API_BASE = window.HEALTH_AI_API || DEFAULT_API;
const DETECTOR_REMEDIATIONS = {
  "arbitrary-send-eth": "Switch fund distribution to a pull/payment pattern and combine with ReentrancyGuard and CEI to avoid external call risks.",
  "divide-before-multiply": "Avoid truncation from divide-before-multiply; reorder to multiply first, then divide, or use a math library for precision.",
  "incorrect-equality": "Do not rely on strict equality to check user state; use boolean flags or range comparisons (<=, >=) instead.",
  "timestamp": "Do not use block.timestamp as a strict control; add a time buffer or switch to block height / oracle-based timing.",
  "low-level-calls": "Replace with OpenZeppelin's Address library, or ensure all low-level calls have complete fallback handling and reentrancy protection."
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
      const maxMB = MAX_FILE_SIZES[activeTab] ?? 50;
      if (file.size > maxMB * 1024 * 1024) {
        fileInput.value = "";
        showUploadError(
          `File is too large (${formatFileSize(file.size)}). Maximum size for ${SKILL_LABELS[activeTab]} is ${maxMB} MB.`
        );
        return;
      }
      clearUploadError();
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
      if (!file.name.endsWith(".zip")) {
        showUploadError("Invalid format. Please upload a .zip archive.");
        return;
      }
      const maxMB = MAX_FILE_SIZES[activeTab] ?? 50;
      if (file.size > maxMB * 1024 * 1024) {
        showUploadError(
          `File is too large (${formatFileSize(file.size)}). Maximum size for ${SKILL_LABELS[activeTab]} is ${maxMB} MB.`
        );
        return;
      }
      clearUploadError();
      // Set the file to the input for form submission
      const dt = new DataTransfer();
      dt.items.add(file);
      fileInput.files = dt.files;
      setCurrentFile(file);
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
  clearUploadError();
  updateRunButtonState();
}

function clearResults() {
  // 清除任务状态
  if (statusBox) {
    statusBox.textContent = workspaceI18n("notStarted");
    statusBox.className = "status";
  }
  if (summaryBox) summaryBox.textContent = workspaceI18n("emptySummary");
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
  const isRunning = !!runningTabs[activeTab];
  const hasWallet = currentWallet !== null;
  
  // Check Skill Stress Lab params
  let hasValidParams = true;
  if (activeTab === "skill-stress-lab") {
    const runsInput = document.getElementById("param-runs");
    const concurrencyInput = document.getElementById("param-concurrency");
    
    if (runsInput && concurrencyInput) {
      const runs = parseInt(runsInput.value, 10);
      const concurrency = parseInt(concurrencyInput.value, 10);
      
      // Validate: must be integers between 1 and 100
      if (isNaN(runs) || runs < 1 || runs > 100 || isNaN(concurrency) || concurrency < 1 || concurrency > 100) {
        hasValidParams = false;
      }
    } else {
      hasValidParams = false;
    }
  }
  
  if (!hasWallet) {
    runBtn.disabled = true;
    runBtn.textContent = workspaceI18n("signInFirst");
  } else if (!hasFile) {
    runBtn.disabled = true;
    runBtn.textContent = workspaceI18n("startAnalysis");
  } else if (activeTab === "skill-stress-lab" && !hasValidParams) {
    runBtn.disabled = true;
    runBtn.textContent = workspaceI18n("startAnalysis");
  } else if (isRunning) {
    runBtn.disabled = true;
    runBtn.textContent = workspaceI18n("analyzing");
  } else {
    runBtn.disabled = false;
    runBtn.textContent = workspaceI18n("startAnalysis");
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
  // 清除上传的文件
  clearCurrentFile();
  // Restore this tab's last task state, or show empty defaults if no task yet
  const lastTask = lastTaskPerTab[tab];
  if (lastTask) {
    // If the stored task is in a non-final state but polling has already stopped,
    // the status is stale — refresh from backend to get the real state.
    if (!FINAL_STATUSES.has(lastTask.status) && !runningTabs[tab]) {
      fetch(`${API_BASE}/api/tasks/${lastTask.taskId}`)
        .then(r => r.ok ? r.json() : null)
        .then(fresh => {
          if (!fresh) return;
          lastTaskPerTab[tab] = fresh;
          if (activeTab === tab) {
            const v = fresh.status === "failed" ? "error" : fresh.status === "completed" ? "success" : "running";
            const label = { completed:workspaceI18n("scanComplete"), failed:workspaceI18n("scanFailed"), running:workspaceI18n("analyzingEllipsis"), pending:workspaceI18n("queued") }[fresh.status] || fresh.status;
            setStatus(label, v);
            setSummary(describeTask(fresh));
            renderArtifacts(fresh);
            renderReportPreview(fresh);
          }
        })
        .catch(() => {});
      // Show a neutral loading state while fetching
      setStatus(workspaceI18n("loading"), "info");
      setSummary(workspaceI18n("refreshing"));
      return;
    }
    const variant = lastTask.status === "failed" ? "error"
                  : lastTask.status === "completed" ? "success"
                  : "running";
    const statusLabel = {
      completed: workspaceI18n("scanComplete"),
      failed:    workspaceI18n("scanFailed"),
      running:   workspaceI18n("analyzingEllipsis"),
      pending:   workspaceI18n("queued"),
    }[lastTask.status] || lastTask.status;
    setStatus(statusLabel, variant);
    const msg = (!FINAL_STATUSES.has(lastTask.status) && pollingMsgPerTab[tab])
      ? pollingMsgPerTab[tab]
      : describeTask(lastTask);
    setSummary(msg);
    renderArtifacts(lastTask);
    renderReportPreview(lastTask);
  } else {
    clearResults();
  }
}

function updateContextBanner() {
  if (typeof window.applyWorkspaceLocale === "function") {
    window.applyWorkspaceLocale(getCurrentUILang());
    return;
  }
  const copy = FEATURE_COPY[activeTab];
  if (copy) {
    if (contextTitle) contextTitle.textContent = copy.title;
    if (contextDesc) contextDesc.textContent = copy.desc;
    document.title = workspaceI18n("titlePrefix") + copy.title;
  }
}

async function uploadFileIfNeeded() {
  const file = fileInput?.files?.[0];
  if (!file) return null;
  const formData = new FormData();
  formData.append("file", file);
  const resp = await fetch(`${API_BASE}/api/uploads`, { method: "POST", body: formData });
  if (!resp.ok) {
    throw new Error(`Upload failed: ${await resp.text()}`);
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
    // Use div for select fields — label wrapping a hidden select triggers native dropdown on click
    const wrapper = document.createElement(field.type === "select" ? "div" : "label");
    wrapper.className = "field";
    const span = document.createElement("span");
    span.textContent = field.label;
    wrapper.appendChild(span);
    let input;
    if (field.type === "select") {
      // Build a hidden real select for value collection
      input = document.createElement("select");
      input.style.display = "none";
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
        input.min = field.min !== undefined ? String(field.min) : "1";
        input.max = field.max !== undefined ? String(field.max) : "";
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
            let num = parseInt(cleanedText, 10);
            if (num > 0) {
              const maxVal = field.max !== undefined ? field.max : Infinity;
              if (num > maxVal) num = maxVal;
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
    
    // Add hint text below number fields (e.g. "Integer between 1 and 100")
    if (field.hint) {
      const hint = document.createElement("span");
      hint.className = "field-hint";
      hint.textContent = field.hint;
      hint.style.cssText = "display:block;font-size:11px;color:var(--text-tertiary,#64748b);margin-top:4px;opacity:0.8;";
      wrapper.appendChild(hint);
    }

    // Add event listener to update button state on value change
    input.addEventListener("input", function() {
      updateRunButtonState();
    });
    
    if (field.type === "select") {
      const options = field.options || [];
      const defaultVal = (field.default !== undefined ? field.default : options[0]) || "";

      const customDrop = document.createElement("div");
      customDrop.className = "custom-select";
      customDrop.setAttribute("tabindex", "0");

      customDrop.innerHTML = `
        <div class="cs-trigger">
          <span class="cs-value">${defaultVal}</span>
          <svg class="cs-chevron" viewBox="0 0 16 16" fill="none">
            <path d="M4 6l4 4 4-4" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
          </svg>
        </div>
        <div class="cs-dropdown">
          ${options.map(opt => `<div class="cs-option${opt === defaultVal ? " cs-option--selected" : ""}" data-value="${opt}">${opt}</div>`).join("")}
        </div>
      `;

      // sync hidden select default
      input.value = defaultVal;

      const trigger = customDrop.querySelector(".cs-trigger");
      const dropdown = customDrop.querySelector(".cs-dropdown");
      const valueEl = customDrop.querySelector(".cs-value");

      trigger.addEventListener("click", (e) => {
        e.stopPropagation();
        const isOpen = customDrop.classList.toggle("cs-open");
        if (isOpen) {
          // close others
          document.querySelectorAll(".custom-select.cs-open").forEach(el => {
            if (el !== customDrop) el.classList.remove("cs-open");
          });
        }
      });

      customDrop.querySelectorAll(".cs-option").forEach(optEl => {
        optEl.addEventListener("click", (e) => {
          e.stopPropagation();
          const val = optEl.dataset.value;
          valueEl.textContent = val;
          input.value = val;
          customDrop.querySelectorAll(".cs-option").forEach(o => o.classList.remove("cs-option--selected"));
          optEl.classList.add("cs-option--selected");
          customDrop.classList.remove("cs-open");
          input.dispatchEvent(new Event("input"));
        });
      });

      document.addEventListener("click", () => customDrop.classList.remove("cs-open"), { capture: false });

      wrapper.appendChild(input);       // hidden real select (for collectParams)
      wrapper.appendChild(customDrop);
    } else {
      wrapper.appendChild(input);
    }
    paramContainer.appendChild(wrapper);
  });
  
  // Update button state after rendering fields
  updateRunButtonState();
}

async function runTask() {
  // 检查是否已连接钱包
  if (!currentWallet) {
    alert("Please connect your wallet before running analysis.");
    return;
  }

  // 同一类型任务同时只允许一个
  if (runningTabs[activeTab]) return;

  const taskTab = activeTab; // 闭包保存，防止中途切 tab 影响状态恢复
  runningTabs[taskTab] = true;
  updateRunButtonState();

  try {
    // Clear previous task results before starting a new analysis
    clearResults();
    setStatus("Analyzing...", "running");
    setSummary("Uploading package and preparing scan…");
    artifactBox?.classList.add("hidden");
    const uploadId = await uploadFileIfNeeded();
    const params = collectParams();
    const codePathValue = codePathInput?.value?.trim();
    if (!codePathValue && !uploadId) {
      throw new Error("Please upload a Skill/Agent archive first.");
    }
    // Note: command is set to default value in backend if not provided
    const deviceId = await getDeviceId();
    const body = {
      skillType: activeTab,
      codePath: codePathValue || null,
      uploadId: uploadId,
      params,
      walletAddress: currentWallet,
      fileName: currentFile ? currentFile.name : null,
      deviceId: deviceId,
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
      let errMsg;
      try {
        const errJson = await resp.json();
        errMsg = errJson.detail || JSON.stringify(errJson);
      } catch (_) {
        errMsg = await resp.text();
      }
      if (resp.status === 409) {
        // 同类型任务已在运行中，提示等待，不展示 Failed
        if (activeTab === taskTab) {
          setStatus("In Queue", "running");
          setSummary("A task of this type is already running. Please wait for it to complete before submitting a new one.");
        }
        runningTabs[taskTab] = false;
        updateRunButtonState();
        return;
      }
      if (resp.status === 429) {
        // 每日配额已达上限，友好提示，不展示 Scan Failed
        if (activeTab === taskTab) {
          setStatus("Daily Limit Reached", "warning");
          setSummary("⏳ You've used all 3 tasks for today. Your quota resets at midnight UTC+0 — come back tomorrow to continue scanning.");
        }
        runningTabs[taskTab] = false;
        updateRunButtonState();
        return;
      }
      throw new Error(errMsg);
    }
    const task = await resp.json();
    renderTask(task);
    // 立刻在历史列表中插入 Processing 记录
    upsertHistoryTask(task);
    let finalTask = task;
    if (!FINAL_STATUSES.has(task.status)) {
      finalTask = await pollTask(task.taskId, taskTab);
      // pollTask 超时时返回 null，不重置上传区（让用户直接 retry）
      if (finalTask === null) {
        runningTabs[taskTab] = false;
        updateRunButtonState();
        return;
      }
    }
    // 任务结束：原地更新历史记录状态
    if (finalTask) upsertHistoryTask(finalTask);
    // Keep the uploaded file visible after completion — user can manually remove it.
  } catch (err) {
    let message = err instanceof Error ? err.message : String(err);
    // If the error contains "[stderr]", show only the stderr content
    const stderrMatch = message.match(/\[stderr\]\s*([\s\S]+)/);
    if (stderrMatch) message = stderrMatch[1].trim();
    if (activeTab === taskTab) {
      setStatus("Scan Failed", "error");
      setSummary(message);
    }
    artifactBox?.classList.add("hidden");
    // 网络/上传阶段失败才清空，扫描本身失败保留文件方便重试
  } finally {
    runningTabs[taskTab] = false;
    updateRunButtonState();
  }
}

function setStatus(text, variant = "info") {
  if (!statusBox) return;
  statusBox.className = `status ${variant}`;
  if (variant === "running") {
    statusBox.innerHTML = `<span class="radar-icon"><span class="radar-sweep"></span><span class="radar-cross"></span><span class="radar-ping"></span><span class="radar-ping radar-ping-2"></span></span>${text}`;
  } else {
    statusBox.textContent = text;
  }
  updateRunButtonState();
}

function setSummary(text) {
  if (!summaryBox) return;
  summaryBox.textContent = text;
}

function describeTask(task) {
  if (!task) return "Upload a package and run an analysis to see results here.";

  const SKILL_NAMES = {
    "skill-security-audit":    "Security Audit",
    "multichain-contract-vuln": "Contract Audit",
    "skill-stress-lab":         "Stress Test"
  };
  const skillName = SKILL_NAMES[task.skillType] || "Analysis";

  if (task.status === "failed") {
    const raw = task.message || "";

    // Stress Test: show backend error message directly (already user-friendly)
    if (task.skillType === "skill-stress-lab") {
      return `⚠️ ${raw}`;
    }

    // Extract [stderr] content if present — this is the clean, user-facing
    // error emitted directly by the script (e.g. "No supported source files…")
    const stderrMatch = raw.match(/\[stderr\]\s*([\s\S]{1,300})/);
    if (stderrMatch) {
      const msg = stderrMatch[1].trim().replace(/\s+/g, " ");
      return msg.slice(0, 200) + (msg.length > 200 ? "…" : "");
    }

    // General error handling: strip file paths and exit codes
    const cleaned = raw
      .replace(/\/[^\s:]+/g, "")      // remove file paths
      .replace(/exit \d+[^.)]*/gi, "") // remove exit code
      .replace(/\s{2,}/g, " ")
      .trim();
    const snippet = cleaned.length > 0
      ? cleaned.slice(0, 140) + (cleaned.length > 140 ? "…" : "")
      : "Please check the logs for details.";
    return `${skillName} encountered an error — ${snippet}`;
  }

  if (task.status === "completed") {
    const msgs = {
      "skill-security-audit":    workspaceI18n("completedSecurity"),
      "multichain-contract-vuln": workspaceI18n("completedContract"),
      "skill-stress-lab":         workspaceI18n("completedStress")
    };
    return msgs[task.skillType] || `${skillName} ${workspaceI18n("completedDefault")}`;
  }

  // running / pending
  const runMsgs = {
    "skill-security-audit":    workspaceI18n("runningSecurity"),
    "multichain-contract-vuln": workspaceI18n("runningContract"),
    "skill-stress-lab":         workspaceI18n("runningStress")
  };
  return runMsgs[task.skillType] || workspaceI18n("runningDefault");
}

const timeFormatter = new Intl.DateTimeFormat("en-US", {
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

// 立刻插入或原地更新历史记录（支持 Processing → Done/Failed 过渡）
function upsertHistoryTask(task) {
  var idx = allHistoryTasks.findIndex(function(t) { return t.taskId === task.taskId; });
  if (idx >= 0) {
    allHistoryTasks[idx] = task;
  } else {
    recordedHistory.add(task.taskId);
    allHistoryTasks.unshift(task);
  }
  renderHistoryPage();
}

function appendHistoryEntry(task) {
  upsertHistoryTask(task);
}

/**
 * 通过 fetch + Blob URL 强制触发浏览器下载，绕开跨域时 <a download> 失效的问题。
 */
async function triggerDownload(url, filename) {
  try {
    const resp = await fetch(url);
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const blob = await resp.blob();
    const blobUrl = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = blobUrl;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    // 短暂延迟后释放 Blob 内存
    setTimeout(() => URL.revokeObjectURL(blobUrl), 10_000);
  } catch (err) {
    alert(`${workspaceI18n('downloadFailed')}: ${err.message}`);
  }
}

function renderArtifacts(task) {
  if (!artifactBox) return;
  if (!task || (!task.reportPath && !task.summaryPath && !task.logPath)) {
    artifactBox.classList.add("hidden");
    artifactBox.innerHTML = "";
    return;
  }

  const tid = task.taskId;
  const skillSlug = (task.skillType || "report").replace(/[^a-z0-9-]/gi, "-");
  const items = [];

  if (task.reportPath) {
    // View Report — 正常跳转页面
    items.push(`<a href="report.html?task=${tid}" target="_blank" rel="noopener">📊 ${workspaceI18n("viewReport")}</a>`);
    // Download Report — 下载 PDF
    items.push(`<button class="artifact-dl-btn" data-url="${API_BASE}/api/tasks/${tid}/report/pdf" data-filename="${skillSlug}-report.pdf">📄 ${workspaceI18n("downloadReport")}</button>`);
  }

  if (!items.length) {
    artifactBox.classList.add("hidden");
    artifactBox.innerHTML = "";
    return;
  }

  // Add Share button
  items.push(`<button class="share-results-btn" data-task-id="${tid}" data-skill-type="${task.skillType}">${workspaceI18n("shareTo")} <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor" style="vertical-align:-2px"><path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-5.214-6.817L4.99 21.75H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231zm-1.161 17.52h1.833L7.084 4.126H5.117z"/></svg></button>`);

  artifactBox.classList.remove("hidden");
  artifactBox.innerHTML = items.join("");

  // 绑定下载按钮事件
  artifactBox.querySelectorAll(".artifact-dl-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      triggerDownload(btn.dataset.url, btn.dataset.filename);
    });
  });

  // 绑定分享按钮事件
  const shareBtn = artifactBox.querySelector(".share-results-btn");
  if (shareBtn) {
    shareBtn.addEventListener("click", () => {
      fetch(`${API_BASE}/api/tasks/${tid}/report`)
        .then(r => r.ok ? r.text() : "")
        .then(text => showShareModal(buildShareText(task, text)))
        .catch(() => showShareModal(buildShareText(task, "")));
    });
  }
}

async function fetchTask(taskId) {
  const resp = await fetch(`${API_BASE}/api/tasks/${taskId}`);
  if (!resp.ok) throw new Error(await resp.text());
  return resp.json();
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function pollTask(taskId, taskTab) {
  // 每 2s 轮询一次，最多 150 次（5 分钟），足以覆盖大文件分析
  const MAX_ATTEMPTS  = 150;
  const POLL_INTERVAL = 2000;
  let attempts = 0;
  let consecutiveErrors = 0;

  while (attempts < MAX_ATTEMPTS) {
    let task;
    try {
      task = await fetchTask(taskId);
      consecutiveErrors = 0;
    } catch (fetchErr) {
      consecutiveErrors += 1;
      // 允许网络短暂抖动：连续 5 次失败才放弃
      if (consecutiveErrors >= 5) {
        throw new Error("网络连接中断，无法获取分析状态。请检查网络后刷新页面。");
      }
      await delay(POLL_INTERVAL);
      attempts += 1;
      continue;
    }

    // renderTask is tab-aware: updates DOM only if taskTab === activeTab
    renderTask(task);
    if (FINAL_STATUSES.has(task.status)) {
      pollingMsgPerTab[taskTab] = null;
      return task;
    }

    // Build progress message and save it for the tab
    const elapsed = Math.round((attempts * POLL_INTERVAL) / 1000);
    let progressMsg;
    if (taskTab === "skill-stress-lab") {
      // Stress Test has a security pre-check phase before the actual stress test
      const phase = elapsed < 30
        ? "Running security pre-check…"
        : "Security pre-check passed, running stress test…";
      progressMsg = `${phase} (${elapsed}s elapsed)`;
    } else {
      progressMsg = `Analyzing… (${elapsed}s elapsed — large packages may take several minutes)`;
    }
    pollingMsgPerTab[taskTab] = progressMsg;
    // Only update the visible panel if this task's tab is currently active
    if (activeTab === taskTab) {
      setSummary(progressMsg);
    }

    await delay(POLL_INTERVAL);
    attempts += 1;
  }

  // 超时：服务可能在处理中，给出明确指引
  pollingMsgPerTab[taskTab] = null;
  if (activeTab === taskTab) {
    setStatus("Timeout", "error");
    setSummary(
      "Analysis is taking longer than expected. " +
      "The server may have restarted — please re-upload your file and try again. " +
      "If this keeps happening, check the server logs."
    );
  }
  // 不 throw，避免触发 catch 再次 clearCurrentFile，让用户可以直接 retry
  return null;
}

function renderTask(task) {
  if (!task) return;
  // Always save per-tab state and update history (global)
  lastTaskPerTab[task.skillType] = task;
  appendHistoryEntry(task);
  // Only update the visible panel if this task belongs to the currently active tab
  if (task.skillType !== activeTab) return;
  const variant = task.status === "failed" ? "error" : task.status === "completed" ? "success" : "running";
  const statusLabel = {
    completed: workspaceI18n("scanComplete"),
    failed:    workspaceI18n("scanFailed"),
    running:   workspaceI18n("analyzingEllipsis"),
    pending:   workspaceI18n("queued")
  }[task.status] || task.status;
  setStatus(statusLabel, variant);
  setSummary(describeTask(task));
  renderArtifacts(task);
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

// Build contract audit score cards — new format (6 dimension scores)
function buildContractAuditSummary(text) {
  // Parse new 5-dimension format (per CONTRACT_AUDIT_GUIDE.md).
  // Only scan the summary section before "Per-File Analysis" to avoid
  // per-file dimension scores overwriting the aggregate scores.
  const scores = {};
  const summarySection = text.split(/^##\s+📄\s+Per-File Analysis/m)[0];
  for (const line of summarySection.split(/\r?\n/)) {
    if (/Overall Security/.test(line)) {
      const m = line.match(/\*?\*?(\d+)\/100/);
      if (m) scores['Overall'] = parseInt(m[1]);
    }
    if (/\|\s*[^\|]*Access Control/.test(line)) {
      const m = line.match(/Access Control[^\|]*\|\s*\*?\*?(\d+)\/100/i);
      if (m) scores['Access'] = parseInt(m[1]);
    }
    if (/\|\s*[^\|]*Financial Security/.test(line)) {
      const m = line.match(/Financial Security[^\|]*\|\s*\*?\*?(\d+)\/100/i);
      if (m) scores['Financial'] = parseInt(m[1]);
    }
    if (/\|\s*[^\|]*Randomness.*Oracle/.test(line)) {
      const m = line.match(/Randomness[^\|]*Oracle[^\|]*\|\s*\*?\*?(\d+)\/100/i);
      if (m) scores['Randomness'] = parseInt(m[1]);
    }
    if (/\|\s*[^\|]*DoS Resistance/.test(line)) {
      const m = line.match(/DoS Resistance[^\|]*\|\s*\*?\*?(\d+)\/100/i);
      if (m) scores['DoS'] = parseInt(m[1]);
    }
    if (/\|\s*[^\|]*Business Logic/.test(line)) {
      const m = line.match(/Business Logic[^\|]*\|\s*\*?\*?(\d+)\/100/i);
      if (m) scores['Logic'] = parseInt(m[1]);
    }
  }

  const dims = [
    { key: 'Overall',    icon: '📊', label: workspaceI18n('overall') },
    { key: 'Access',     icon: '🔐', label: workspaceI18n('accessControl') },
    { key: 'Financial',  icon: '💰', label: workspaceI18n('financialSecurity') },
    { key: 'Randomness', icon: '🎲', label: workspaceI18n('randomnessOracle') },
    { key: 'DoS',        icon: '⚡', label: workspaceI18n('dosResistance') },
    { key: 'Logic',      icon: '🛡️', label: workspaceI18n('businessLogic') },
  ];

  // Contract Audit uses guide thresholds: 90/70/50 (not 80/60/40 used elsewhere)
  function contractScoreClass(s) {
    if (s >= 90) return 'low';    // green  — Excellent
    if (s >= 70) return 'total';  // blue   — Good
    if (s >= 50) return 'medium'; // yellow — Caution
    return 'high';                // red    — Risk
  }

  let html = `<div class="report-stats-cards report-stats-cards--6">`;
  for (const d of dims) {
    const s = scores[d.key] ?? 0;
    html += _scoreCard(s, d.icon, d.label, contractScoreClass);
  }
  html += `</div>`;
  html += _scoreLegend('contract');

  return html;
}

function buildReportSummary(text) {
  if (!text) return "";

  // Detect new-format contract audit report (has dimension score table)
  if (/\|\s*[^\|]*Access Control/.test(text)) {
    return buildContractAuditSummary(text);
  }

  // Legacy format: show 4 severity count cards
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
  html += `<div class="stat-card high"><span class="stat-number">${highFindings.length}</span><span class="stat-label">${workspaceI18n('highRisk')}</span></div>`;
  html += `<div class="stat-card medium"><span class="stat-number">${mediumFindings.length}</span><span class="stat-label">${workspaceI18n('mediumRisk')}</span></div>`;
  html += `<div class="stat-card low"><span class="stat-number">${otherFindings.length}</span><span class="stat-label">${workspaceI18n('lowRisk')}</span></div>`;
  html += `<div class="stat-card total"><span class="stat-number">${detectorSummaries.length}</span><span class="stat-label">${workspaceI18n('total')}</span></div>`;
  html += `</div>`;

  return html;
}

// Shared helpers for score card rendering (80/60/40 thresholds used by Security Audit and Stress Lab)
function _scoreClass(score) {
  if (score >= 80) return 'low';    // Excellent - green
  if (score >= 60) return 'total';  // Good - blue
  if (score >= 40) return 'medium'; // Caution - yellow
  return 'high';                    // Risk - red
}

function _scoreCard(score, icon, label, classFn) {
  const cls = (classFn || _scoreClass)(score);
  return `<div class="stat-card ${cls}"><span class="stat-number">${score}</span><span class="stat-label"><span class="stat-icon">${icon}</span>${label}</span></div>`;
}

function _scoreLegend(thresholds) {
  const e = workspaceI18n('scoreExcellent'), g = workspaceI18n('scoreGood'), c = workspaceI18n('scoreCaution'), r = workspaceI18n('scoreRisk');
  const text = thresholds === 'contract'
    ? `90-100 = ${e} 🟢 | 70-89 = ${g} 🔵 | 50-69 = ${c} 🟡 | &lt;50 = ${r} 🔴`
    : `80-100 = ${e} 🟢 | 60-79 = ${g} 🔵 | 40-59 = ${c} 🟡 | &lt;40 = ${r} 🔴`;
  return `<div style="margin-top: 8px; padding: 8px 12px; background: rgba(99, 102, 241, 0.1); border-radius: 6px; font-size: 12px; color: #94a3b8;">${text}</div>`;
}

// Build security audit score cards (6 dimensions)
function buildSecurityAuditSummary(text) {
  if (!text) return "";
  
  const scores = {};
  const lines = text.split(/\r?\n/);
  
  // Parse scores from report
  // New table format: | 🏆 **Overall Security** | **83/100** | ... |
  //                   | 🔏 Privacy | 95/100 | ... |
  // Legacy format:    - Privacy: 95/100
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Overall Security (table format)
    if (/Overall Security/.test(line)) {
      const m = line.match(/\*?\*?(\d+)\/100/);
      if (m) scores['Overall'] = parseInt(m[1]);
    }
    if (scores['Overall'] === undefined) {
      const m = line.match(/(?:Overall Safety|综合安全评分)[:：\/]?\s*(\d+)/i);
      if (m) scores['Overall'] = parseInt(m[1]);
    }

    // Privacy
    if (/\|\s*[^\|]*Privacy/.test(line)) {
      const m = line.match(/\|\s*[^\|]*Privacy[^\|]*\|\s*\*?\*?(\d+)\/100/i);
      if (m) scores['Privacy'] = parseInt(m[1]);
    } else {
      const m = line.match(/(?:^-\s*Privacy|隐私安全)[:：\/]?\s*(\d+)/i);
      if (m) scores['Privacy'] = parseInt(m[1]);
    }

    // Privilege
    if (/\|\s*[^\|]*Privilege/.test(line)) {
      const m = line.match(/\|\s*[^\|]*Privilege[^\|]*\|\s*\*?\*?(\d+)\/100/i);
      if (m) scores['Privilege'] = parseInt(m[1]);
    } else {
      const m = line.match(/(?:^-\s*Privilege|权限安全)[:：\/]?\s*(\d+)/i);
      if (m) scores['Privilege'] = parseInt(m[1]);
    }

    // Integrity (replaces Memory)
    if (/\|\s*[^\|]*Integrity/.test(line)) {
      const m = line.match(/\|\s*[^\|]*Integrity[^\|]*\|\s*\*?\*?(\d+)\/100/i);
      if (m) scores['Integrity'] = parseInt(m[1]);
    }

    // Dependency Risk (replaces Token)
    if (/\|\s*[^\|]*Dependency Risk/.test(line)) {
      const m = line.match(/\|\s*[^\|]*Dependency Risk[^\|]*\|\s*\*?\*?(\d+)\/100/i);
      if (m) scores['SupplyChain'] = parseInt(m[1]);
    }

    // Stability (mapped to Failure key)
    if (/\|\s*[^\|]*Stability/.test(line)) {
      const m = line.match(/\|\s*[^\|]*Stability[^\|]*\|\s*\*?\*?(\d+)\/100/i);
      if (m) scores['Failure'] = parseInt(m[1]);
    } else {
      const m = line.match(/(?:^-\s*(?:Failure Rate|Stability)|稳定性)[:：\/]?\s*(\d+)/i);
      if (m) scores['Failure'] = parseInt(m[1]);
    }
  }
  
  // Fallback: calculate overall if not parsed
  let overallScore = scores['Overall'] || 0;
  if (!overallScore) {
    const scoreValues = Object.values(scores).filter(s => s > 0);
    overallScore = scoreValues.length ? Math.round(scoreValues.reduce((a, b) => a + b, 0) / scoreValues.length) : 0;
  }
  
  // Get individual scores
  const privacyScore     = scores['Privacy']     || 0;
  const privilegeScore   = scores['Privilege']   || 0;
  const integrityScore   = scores['Integrity']   || 0;
  const supplyChainScore = scores['SupplyChain'] || 0;
  const failureScore     = scores['Failure']     || 0;

  // Build 6 score cards — 3-column grid (2 rows of 3)
  let html = `<div class="report-stats-cards report-stats-cards--6">`;
  html += _scoreCard(overallScore,    '📊', workspaceI18n('overall'));
  html += _scoreCard(privacyScore,    '🔏', workspaceI18n('privacy'));
  html += _scoreCard(privilegeScore,  '🔐', workspaceI18n('privilege'));
  html += _scoreCard(integrityScore,  '🛡️', workspaceI18n('integrity'));
  html += _scoreCard(supplyChainScore,'🔗', workspaceI18n('dependencyRisk'));
  html += _scoreCard(failureScore,    '✅', workspaceI18n('stability'));
  html += `</div>`;
  html += _scoreLegend();

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
  
  // Build 6 score cards (overall + 5 dimensions) — 3-column grid (2 rows of 3)
  let html = `<div class="report-stats-cards report-stats-cards--6">`;
  html += _scoreCard(overallScore,     '🎯', workspaceI18n('overall'));
  html += _scoreCard(stabilityScore,   '🛡️', workspaceI18n('stability'));
  html += _scoreCard(performanceScore, '⚡', workspaceI18n('performance'));
  html += _scoreCard(resourceScore,    '💾', workspaceI18n('resource'));
  html += _scoreCard(consistencyScore, '🔄', workspaceI18n('consistency'));
  html += _scoreCard(recoveryScore,    '🆘', workspaceI18n('recovery'));
  html += `</div>`;
  html += _scoreLegend();

  return html;
}

// ── Share Results Feature ──────────────────────────────────────

function buildShareText(task, reportText) {
  const REPORT_URL = window.location.origin + "/report.html?task=" + task.taskId;
  const scores = {};
  const lines = (reportText || "").split(/\r?\n/);

  if (task.skillType === "skill-security-audit") {
    // Parse overall + dimension scores
    for (const line of lines) {
      if (/Overall Security/.test(line)) { const m = line.match(/(\d+)\/100/); if (m) scores.overall = m[1]; }
      if (/Privacy/.test(line))   { const m = line.match(/(\d+)\/100/); if (m) scores.privacy = m[1]; }
      if (/Privilege/.test(line)) { const m = line.match(/(\d+)\/100/); if (m) scores.privilege = m[1]; }
      if (/Integrity/.test(line)) { const m = line.match(/(\d+)\/100/); if (m) scores.integrity = m[1]; }
    }
    const s = scores.overall || "—";
    return `🛡️ My Skill scored ${s}/100 on @CodeAutrix.\n` +
      `Privacy: ${scores.privacy || "—"} · Privilege: ${scores.privilege || "—"} · Integrity: ${scores.integrity || "—"}\n\n` +
      `One-click AI security audit 👇\n${REPORT_URL}\n\n` +
      `#CodeAutrix #Web3Security`;
  }

  if (task.skillType === "multichain-contract-vuln") {
    // Parse severity counts or overall score
    let critical = 0, high = 0, medium = 0, low = 0, overall = "";
    for (const line of lines) {
      if (/Overall/.test(line)) { const m = line.match(/(\d+)\/100/); if (m) overall = m[1]; }
      const sevMatch = line.match(/\|\s*(\d+)\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|/);
      if (sevMatch) { critical = sevMatch[1]; high = sevMatch[2]; medium = sevMatch[3]; low = sevMatch[4]; }
    }
    const total = parseInt(critical) + parseInt(high) + parseInt(medium) + parseInt(low);
    const totalStr = total > 0 ? `${total} vulnerabilities caught` : "Contract analyzed";
    return `📋 ${totalStr} caught by @CodeAutrix.\n` +
      `🔴 ${critical} Critical · 🟠 ${high} High · 🟡 ${medium} Medium · 🟢 ${low} Low\n\n` +
      `One-click contract audit 👇\n${REPORT_URL}\n\n` +
      `#CodeAutrix #SmartContract`;
  }

  if (task.skillType === "skill-stress-lab") {
    let overall = "", stability = "", performance = "";
    for (const line of lines) {
      if (/(?:Overall|综合)/.test(line)) { const m = line.match(/(\d+)\/100/); if (m) overall = m[1]; }
      if (/(?:Stability|稳定性)/.test(line)) { const m = line.match(/(\d+)\/100/); if (m) stability = m[1]; }
      if (/(?:Performance|性能)/.test(line)) { const m = line.match(/(\d+)\/100/); if (m) performance = m[1]; }
    }
    return `⚡ Stress tested on @CodeAutrix.\n` +
      `Score: ${overall || "—"}/100 · Stability: ${stability || "—"} · Performance: ${performance || "—"}\n\n` +
      `One-click reliability test 👇\n${REPORT_URL}\n\n` +
      `#CodeAutrix #StressTest`;
  }

  return `🔒 Just scanned my project on @CodeAutrix — one-click security audit for Web3.\n\n${REPORT_URL}\n\n#CodeAutrix`;
}

function showShareModal(shareText) {
  // Remove existing modal
  const existing = document.querySelector(".share-modal-overlay");
  if (existing) existing.remove();

  const overlay = document.createElement("div");
  overlay.className = "share-modal-overlay";
  overlay.innerHTML = `
    <div class="share-modal-backdrop"></div>
    <div class="share-modal-content">
      <div class="share-modal-header">
        <h3>Share Results</h3>
        <button class="share-modal-close">&times;</button>
      </div>
      <p class="share-modal-subtitle">Preview and share your scan results on X (Twitter)</p>
      <textarea class="share-modal-textarea" rows="8">${shareText.replace(/</g, '&lt;').replace(/>/g, '&gt;')}</textarea>
      <div class="share-modal-charcount"><span class="share-char-num">${xCharCount(shareText)}</span>/280</div>
      <button class="share-modal-twitter-btn">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-5.214-6.817L4.99 21.75H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231zm-1.161 17.52h1.833L7.084 4.126H5.117z"/></svg>
        Share on X
      </button>
    </div>
  `;

  const style = document.createElement("style");
  style.className = "share-modal-style";
  style.textContent = `
    .share-modal-overlay {
      position: fixed; top: 0; left: 0; right: 0; bottom: 0;
      z-index: 1100; display: flex; align-items: center; justify-content: center;
    }
    .share-modal-backdrop {
      position: absolute; top: 0; left: 0; right: 0; bottom: 0;
      background: rgba(0,0,0,0.6); backdrop-filter: blur(4px);
    }
    .share-modal-content {
      position: relative; background: var(--bg-secondary, #0f1629);
      border: 1px solid rgba(255,255,255,0.1); border-radius: 16px;
      padding: 24px; width: 440px; max-width: 90vw;
      box-shadow: 0 20px 60px rgba(0,0,0,0.4);
    }
    .share-modal-header {
      display: flex; align-items: center; justify-content: space-between; margin-bottom: 4px;
    }
    .share-modal-header h3 { margin: 0; font-size: 18px; font-weight: 600; color: #f3f4f6; }
    .share-modal-close {
      background: none; border: none; color: #94a3b8; font-size: 22px;
      cursor: pointer; padding: 0 4px; line-height: 1; transition: color 0.2s;
    }
    .share-modal-close:hover { color: #fff; }
    .share-modal-subtitle {
      color: #94a3b8; font-size: 13px; margin: 0 0 16px 0;
    }
    .share-modal-textarea {
      width: 100%; background: rgba(255,255,255,0.04); border: 1px solid rgba(255,255,255,0.1);
      border-radius: 10px; padding: 12px; color: #e2e8f0; font-size: 13px;
      line-height: 1.6; resize: vertical; font-family: inherit;
      transition: border-color 0.2s; box-sizing: border-box;
    }
    .share-modal-textarea:focus { outline: none; border-color: rgba(99,102,241,0.5); }
    .share-modal-charcount {
      text-align: right; font-size: 11px; color: #64748b; margin: 6px 0 16px;
    }
    .share-modal-charcount .share-char-num.over { color: #ef4444; }
    .share-modal-twitter-btn {
      width: 100%; display: flex; align-items: center; justify-content: center; gap: 8px;
      padding: 12px; background: #000; color: #fff; border: 1px solid rgba(255,255,255,0.15);
      border-radius: 10px; font-size: 14px; font-weight: 600; cursor: pointer;
      transition: all 0.2s;
    }
    .share-modal-twitter-btn:hover {
      background: #1a1a2e; border-color: rgba(255,255,255,0.25);
      box-shadow: 0 4px 16px rgba(0,0,0,0.3);
    }
  `;
  document.head.appendChild(style);
  document.body.appendChild(overlay);

  const textarea = overlay.querySelector(".share-modal-textarea");
  const charNum = overlay.querySelector(".share-char-num");

  // X counts all URLs as 23 chars regardless of actual length (t.co shortening)
  function xCharCount(text) {
    return text.replace(/https?:\/\/\S+/g, "X".repeat(23)).length;
  }

  // Live char count
  textarea.addEventListener("input", () => {
    const len = xCharCount(textarea.value);
    charNum.textContent = len;
    charNum.classList.toggle("over", len > 280);
  });

  // Share on X
  overlay.querySelector(".share-modal-twitter-btn").addEventListener("click", () => {
    const text = textarea.value;
    const url = `https://twitter.com/intent/tweet?text=${encodeURIComponent(text)}`;
    window.open(url, "_blank", "noopener,noreferrer");
  });

  // Close handlers
  const cleanup = () => { overlay.remove(); style.remove(); };
  overlay.querySelector(".share-modal-close").addEventListener("click", cleanup);
  overlay.querySelector(".share-modal-backdrop").addEventListener("click", cleanup);
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

    // Match location - unified across three formats
    let location = null;
    const match1 = line.match(/(\w+\.sol#\d+(?:-\d+)?)/);
    const match2 = line.match(/in\s+\w+\([^)]*\)\s*\(([^)]+\.sol#\d+(?:-\d+)?)\)/);
    const match3 = line.match(/\((src\/[^)]+\.sol#\d+(?:-\d+)?)\)/);
    location = match1 ? match1[1] : (match2 ? match2[1] : (match3 ? match3[1] : null));
    
    if (location && currentDetector) {
      items.push({
        name: currentDetector,
        desc: currentDesc || "See report for details",
        location: location
      });
    }
  }
  return items;
}

function extractDetectorSummaries(text) {
  return extractAllIssues(text);
}

// --------------------------- Wallet Functions ---------------------------

function formatWalletAddress(address) {
  if (!address) return "";
  return address.slice(0, 6) + "..." + address.slice(-4);
}

function updateWalletUI() {
  if (currentWallet && walletBtn && walletText) {
    walletBtn.classList.add("connected");
    if (loginType === "github") {
      var ghLogin = localStorage.getItem("github_login") || loginEmail || "";
      walletText.textContent = ghLogin.length > 14 ? ghLogin.slice(0, 12) + ".." : (ghLogin || formatWalletAddress(currentWallet));
    } else if (loginType === "google" && loginEmail) {
      const email = loginEmail;
      if (email.length > 14) {
        var parts = email.split(".");
        var last = parts[parts.length - 1];
        var front = email.slice(0, 4);
        walletText.textContent = front + "..." + last;
      } else {
        walletText.textContent = email;
      }
    } else {
      walletText.textContent = formatWalletAddress(currentWallet);
    }
  } else if (walletBtn && walletText) {
    walletBtn.classList.remove("connected");
    walletText.textContent = "Sign In";
  }
}

// ── EIP-6963 钱包发现 + 传统注入检测 ──
// 收集通过 EIP-6963 协议注册的钱包
const eip6963Providers = [];
if (typeof window !== "undefined") {
  window.addEventListener("eip6963:announceProvider", (event) => {
    if (event.detail && event.detail.provider) {
      eip6963Providers.push(event.detail);
    }
  });
  window.dispatchEvent(new Event("eip6963:requestProvider"));
}

function detectWalletProviders() {
  const providers = [];
  const seenRdns = new Set();

  // 1) EIP-6963 detected wallets (modern standard, wallets provide their own name + icon)
  for (const detail of eip6963Providers) {
    const rdns = detail.info && detail.info.rdns;
    const key = rdns || detail.info.name;
    if (seenRdns.has(key)) continue;
    seenRdns.add(key);
    providers.push({
      name: detail.info.name,
      icon: detail.info.icon, // data URI provided by the wallet itself
      provider: detail.provider,
      rdns: rdns
    });
  }

  // 2) Legacy fallback: check known window injection points for wallets that don't support EIP-6963
  const legacyWallets = [
    { rdns: "io.metamask",          name: "MetaMask",        get: () => { if (window.ethereum) { const ps = window.ethereum.providers || [window.ethereum]; return ps.find(p => p.isMetaMask); } return null; } },
    { rdns: "com.okex.wallet",      name: "OKX Wallet",      get: () => window.okxwallet },
    { rdns: "com.coinbase.wallet",   name: "Coinbase Wallet", get: () => window.coinbaseWalletExtension || (window.ethereum && window.ethereum.isCoinbaseWallet ? window.ethereum : null) },
    { rdns: "app.phantom",          name: "Phantom",         get: () => window.phantom && window.phantom.ethereum },
    { rdns: "com.bitget.web3",      name: "Bitget Wallet",   get: () => window.bitkeep && window.bitkeep.ethereum },
    { rdns: "com.trustwallet.app",  name: "Trust Wallet",    get: () => window.trustwallet || (window.ethereum && window.ethereum.isTrust ? window.ethereum : null) },
    { rdns: "io.rabby",             name: "Rabby Wallet",    get: () => window.rabby },
    { rdns: "io.zerion.wallet",     name: "Zerion",          get: () => window.zerion },
    { rdns: "com.brave.wallet",     name: "Brave Wallet",    get: () => (window.ethereum && window.ethereum.isBraveWallet) ? window.ethereum : null },
    { rdns: "pro.tokenpocket",      name: "TokenPocket",     get: () => { if (window.ethereum) { const ps = window.ethereum.providers || [window.ethereum]; return ps.find(p => p.isTokenPocket); } return null; } },
    { rdns: "im.token",             name: "imToken",         get: () => { if (window.ethereum) { const ps = window.ethereum.providers || [window.ethereum]; return ps.find(p => p.isImToken); } return null; } },
  ];

  for (const w of legacyWallets) {
    if (seenRdns.has(w.rdns) || seenRdns.has(w.name)) continue;
    try {
      const provider = w.get();
      if (provider) {
        seenRdns.add(w.rdns);
        providers.push({ name: w.name, icon: null, provider });
      }
    } catch (_) {}
  }

  // 3) Final fallback: generic browser wallet
  if (providers.length === 0 && window.ethereum) {
    providers.push({ name: "Browser Wallet", icon: null, provider: window.ethereum });
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
        <h3>Select Wallet</h3>
        <div class="wallet-list">
          ${providers.map((p, i) => `
            <button class="wallet-option" data-index="${i}">
              ${p.icon
                ? `<img class="wallet-option-icon-img" src="${p.icon}" alt="${p.name}" onerror="this.style.display='none'; this.nextElementSibling.style.display='inline-flex';" /><span class="wallet-option-icon wallet-option-badge" style="display:none;">${(p.name||'W').slice(0,2).toUpperCase()}</span>`
                : `<span class="wallet-option-icon wallet-option-badge">${(p.name||'W').slice(0,2).toUpperCase()}</span>`
              }
              <span class="wallet-option-name">${p.name}</span>
            </button>
          `).join("")}
        </div>
        <button class="wallet-modal-close">Cancel</button>
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
        font-size: 12px;
        font-weight: 700;
      }
      .wallet-option-badge {
        width: 28px;
        height: 28px;
        border-radius: 999px;
        display: inline-flex;
        align-items: center;
        justify-content: center;
        background: rgba(255,255,255,0.08);
        color: #f3f4f6;
        border: 1px solid rgba(255,255,255,0.10);
        font-family: Inter, sans-serif;
        letter-spacing: 0.02em;
      }
      .wallet-option-icon-img {
        width: 28px;
        height: 28px;
        border-radius: 999px;
        object-fit: cover;
        border: 1px solid rgba(255,255,255,0.10);
        background: rgba(255,255,255,0.06);
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
      reject(new Error("Cancelled by user"));
    });

    modal.querySelector(".wallet-modal-backdrop").addEventListener("click", () => {
      document.body.removeChild(modal);
      document.head.removeChild(style);
      reject(new Error("Cancelled by user"));
    });
  });
}

// ── Login Method Selection Modal ──
function showLoginModal() {
  return new Promise((resolve, reject) => {
    const modal = document.createElement("div");
    modal.className = "wallet-modal";
    modal.innerHTML = `
      <div class="wallet-modal-backdrop"></div>
      <div class="wallet-modal-content">
        <h3>Sign In</h3>
        <p style="color: var(--text-secondary); font-size: 13px; margin-bottom: 16px; text-align: center;">
          Choose a login method to continue
        </p>
        <div class="wallet-list">
          <button class="wallet-option" data-method="google">
            <span class="wallet-option-icon">
              <svg width="20" height="20" viewBox="0 0 48 48"><path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"/><path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"/><path fill="#FBBC05" d="M10.53 28.59A14.5 14.5 0 019.5 24c0-1.59.28-3.14.76-4.59l-7.98-6.19A23.93 23.93 0 000 24c0 3.77.89 7.35 2.56 10.56l7.97-5.97z"/><path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 5.97C6.51 42.62 14.62 48 24 48z"/></svg>
            </span>
            <span class="wallet-option-name">Continue with Google</span>
          </button>
          <button class="wallet-option" data-method="github">
            <span class="wallet-option-icon">
              <svg width="20" height="20" viewBox="0 0 48 48" fill="none"><circle cx="24" cy="24" r="24" fill="#24292f"/><path d="M24 5C13.5 5 5 13.5 5 24c0 8.4 5.5 15.5 13 18 1 .2 1.3-.4 1.3-.9v-3.5c-5.3 1.1-6.4-2.2-6.4-2.2-.9-2.2-2.1-2.8-2.1-2.8-1.7-1.2.1-1.1.1-1.1 1.9.1 2.9 1.9 2.9 1.9 1.7 2.9 4.4 2.1 5.5 1.6.2-1.2.7-2.1 1.2-2.5-4.2-.5-8.7-2.1-8.7-9.3 0-2.1.7-3.7 1.9-5.1-.2-.5-.8-2.4.2-5 0 0 1.6-.5 5.1 1.9 1.5-.4 3.1-.6 4.6-.6s3.1.2 4.6.6c3.6-2.4 5.1-1.9 5.1-1.9 1 2.6.4 4.5.2 5 1.2 1.3 1.9 3 1.9 5.1 0 7.2-4.4 8.8-8.7 9.3.7.6 1.3 1.8 1.3 3.5v5.2c0 .5.3 1.1 1.3.9C37.5 39.5 43 32.4 43 24 43 13.5 34.5 5 24 5z" fill="#ffffff"/></svg>
            </span>
            <span class="wallet-option-name">Continue with GitHub</span>
          </button>
          <button class="wallet-option" data-method="wallet">
            <span class="wallet-option-icon">
              <svg width="20" height="20" viewBox="0 0 48 48" fill="none"><defs><linearGradient id="wg" x1="0" y1="0" x2="48" y2="48"><stop offset="0%" stop-color="#6366f1"/><stop offset="100%" stop-color="#8b5cf6"/></linearGradient></defs><rect x="2" y="10" width="36" height="30" rx="4" fill="url(#wg)"/><path d="M38 10H8C4.69 10 2 12.69 2 16V10C2 6.69 4.69 4 8 4H34C37.31 4 38 6.69 38 10Z" fill="#a78bfa"/><rect x="30" y="22" width="16" height="12" rx="3" fill="#22d3ee"/><circle cx="38" cy="28" r="2.5" fill="#fff"/></svg>
            </span>
            <span class="wallet-option-name">Connect Wallet</span>
          </button>
        </div>
        <button class="wallet-modal-close">Cancel</button>
      </div>
    `;

    const style = document.createElement("style");
    style.textContent = `
      .wallet-modal {
        position: fixed; top: 0; left: 0; right: 0; bottom: 0;
        z-index: 1000; display: flex; align-items: center; justify-content: center;
      }
      .wallet-modal-backdrop {
        position: absolute; top: 0; left: 0; right: 0; bottom: 0;
        background: rgba(0,0,0,0.5);
      }
      .wallet-modal-content {
        position: relative; background: var(--bg-secondary);
        border: 1px solid var(--border-subtle); border-radius: var(--radius-lg);
        padding: 24px; min-width: 320px; max-width: 90vw;
      }
      .wallet-modal-content h3 {
        margin: 0 0 16px 0; font-size: 18px; text-align: center;
      }
      .wallet-list {
        display: flex; flex-direction: column; gap: 8px; margin-bottom: 16px;
      }
      .wallet-option {
        display: flex; align-items: center; gap: 12px; padding: 14px 16px;
        background: var(--bg-tertiary); border: 1px solid var(--border-subtle);
        border-radius: var(--radius); color: var(--text-primary);
        font-size: 14px; cursor: pointer; transition: all 150ms ease;
        text-decoration: none;
      }
      .wallet-option:hover {
        border-color: var(--accent); background: var(--accent-subtle);
      }
      .wallet-option-icon { font-size: 20px; display: flex; align-items: center; }
      .wallet-modal-close {
        width: 100%; padding: 10px; background: transparent;
        border: 1px solid var(--border-subtle); border-radius: var(--radius);
        color: var(--text-secondary); font-size: 13px; cursor: pointer;
      }
      .wallet-modal-close:hover {
        border-color: var(--border-default); color: var(--text-primary);
      }
    `;
    document.head.appendChild(style);
    document.body.appendChild(modal);

    function cleanup() {
      if (modal.parentNode) document.body.removeChild(modal);
      if (style.parentNode) document.head.removeChild(style);
    }

    modal.querySelectorAll(".wallet-option").forEach(btn => {
      btn.addEventListener("click", () => {
        const method = btn.dataset.method;
        cleanup();
        resolve(method);
      });
    });
    modal.querySelector(".wallet-modal-close").addEventListener("click", () => { cleanup(); reject(new Error("Cancelled")); });
    modal.querySelector(".wallet-modal-backdrop").addEventListener("click", () => { cleanup(); reject(new Error("Cancelled")); });
  });
}

// ── Google OAuth Login (full-page redirect) ──
function loginWithGoogle() {
  if (!GOOGLE_CLIENT_ID) {
    alert("Google Login is not configured. Please set GOOGLE_CLIENT_ID.");
    return;
  }

  // Save current page to return after login
  localStorage.setItem("google_oauth_redirect", window.location.href);

  // Redirect to Google OAuth
  const redirectUri = window.location.origin + "/workspace.html";
  const params = new URLSearchParams({
    client_id: GOOGLE_CLIENT_ID,
    redirect_uri: redirectUri,
    response_type: "token",
    scope: "email profile",
    prompt: "select_account"
  });
  window.location.href = "https://accounts.google.com/o/oauth2/v2/auth?" + params.toString();
}

// ── GitHub OAuth ──
function loginWithGithub() {
  if (!GITHUB_CLIENT_ID) {
    alert("GitHub Login is not configured. Please set GITHUB_CLIENT_ID.");
    return;
  }

  // Save current page to return after login
  localStorage.setItem("github_oauth_redirect", window.location.href);

  // Redirect to GitHub OAuth (redirect_uri adapts to current environment)
  var redirectUri = window.location.origin + "/workspace.html";
  var params = new URLSearchParams({
    client_id: GITHUB_CLIENT_ID,
    redirect_uri: redirectUri,
    scope: "user:email"
  });
  window.location.href = "https://github.com/login/oauth/authorize?" + params.toString();
}

// Handle GitHub OAuth redirect callback
async function handleGithubCallback() {
  var params = new URLSearchParams(window.location.search);
  var code = params.get("code");

  // Only handle if this is actually a GitHub callback (has code param and was initiated by us)
  if (!code) return false;
  // If there's no record of us initiating a GitHub login, this code param isn't for us
  if (!localStorage.getItem("github_oauth_redirect")) return false;

  // GitHub returned an error
  var error = params.get("error");
  if (error) {
    console.error("[GitHubAuth] OAuth error:", error, params.get("error_description") || "");
    history.replaceState(null, "", window.location.pathname + window.location.hash);
    localStorage.removeItem("github_oauth_redirect");
    return false;
  }

  // Clear the code from URL immediately (preserve hash for other handlers)
  history.replaceState(null, "", window.location.pathname + window.location.hash);
  localStorage.removeItem("github_oauth_redirect");

  try {
    console.log("[GitHubAuth] Exchanging code with backend...");
    var resp = await fetch(API_BASE + "/api/auth/github", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ code: code, clientId: GITHUB_CLIENT_ID })
    });

    if (!resp.ok) {
      var errData = await resp.json().catch(function() { return {}; });
      throw new Error(errData.detail || "GitHub login failed (" + resp.status + ")");
    }

    var data = await resp.json();
    console.log("[GitHubAuth] Login success:", data.login, data.email);

    // Store session
    currentWallet = data.walletAddress;
    walletToken = data.token;
    loginType = "github";
    loginEmail = data.email || data.login;
    localStorage.setItem("wallet_token", data.token);
    localStorage.setItem("wallet_address", data.walletAddress);
    localStorage.setItem("login_type", "github");
    localStorage.setItem("login_email", data.email || data.login);
    localStorage.setItem("github_login", data.login || "");

    updateWalletUI();
    updateRunButtonState();
    loadWalletHistory();
    return true;
  } catch (err) {
    console.error("[GitHubAuth] Login failed:", err);
    alert("GitHub login failed: " + err.message);
    return false;
  }
}

// Handle Google OAuth redirect callback
async function handleGoogleCallback() {
  const hash = window.location.hash;
  if (!hash || hash.length < 2) return false;

  const hashStr = hash.substring(1);
  const params = new URLSearchParams(hashStr);

  // Google returned an error (e.g. access_denied, popup_closed)
  if (params.get("error")) {
    console.error("[GoogleAuth] OAuth error:", params.get("error"), params.get("error_description") || "");
    history.replaceState(null, "", window.location.pathname + window.location.search);
    localStorage.removeItem("google_oauth_redirect");
    return false;
  }

  const accessToken = params.get("access_token");
  if (!accessToken) return false;

  // Clear the hash from URL immediately
  history.replaceState(null, "", window.location.pathname + window.location.search);
  localStorage.removeItem("google_oauth_redirect");

  try {
    // Step 1: Get user info from Google
    console.log("[GoogleAuth] Fetching user info from Google...");
    const userResp = await fetch("https://www.googleapis.com/oauth2/v3/userinfo", {
      headers: { Authorization: `Bearer ${accessToken}` }
    });
    if (!userResp.ok) {
      const errText = await userResp.text().catch(function() { return ""; });
      throw new Error("Google userinfo failed (" + userResp.status + "): " + errText);
    }
    const userInfo = await userResp.json();
    console.log("[GoogleAuth] Got user:", userInfo.email);

    // Step 2: Show email in UI immediately (before backend verification)
    var tempAddr = "0xG" + userInfo.sub.slice(0, 39);
    loginType = "google";
    loginEmail = userInfo.email;
    currentWallet = tempAddr;
    localStorage.setItem("login_type", "google");
    localStorage.setItem("login_email", userInfo.email);
    localStorage.setItem("wallet_address", tempAddr);
    updateWalletUI();
    updateRunButtonState();
    console.log("[GoogleAuth] UI updated, verifying with backend...");

    // Step 3: Verify with backend in background (5s timeout)
    try {
      var abortCtrl = new AbortController();
      var timeoutId = setTimeout(function() { abortCtrl.abort(); }, 5000);
      var verifyResp = await fetch(API_BASE + "/api/auth/google", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        signal: abortCtrl.signal,
        body: JSON.stringify({
          email: userInfo.email,
          name: userInfo.name || "",
          googleId: userInfo.sub,
          accessToken: accessToken
        })
      });
      clearTimeout(timeoutId);

      if (verifyResp.ok) {
        var data = await verifyResp.json();
        if (data.token && data.walletAddress) {
          localStorage.setItem("wallet_token", data.token);
          localStorage.setItem("wallet_address", data.walletAddress);
          walletToken = data.token;
          currentWallet = data.walletAddress;
          console.log("[GoogleAuth] Backend verified, wallet:", data.walletAddress);
        }
      } else {
        console.warn("[GoogleAuth] Backend error:", verifyResp.status);
      }
    } catch (backendErr) {
      console.warn("[GoogleAuth] Backend unreachable:", backendErr.message);
    }

    console.log("[GoogleAuth] Login complete:", userInfo.email);
    loadWalletHistory();
    return true;
  } catch (err) {
    console.error("[GoogleAuth] Login failed:", err);
    alert("Google login failed: " + err.message);
    return false;
  }
}

// ── Wallet Connection ──
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
        <h3>No Wallet Detected</h3>
        <p style="color: var(--text-secondary); font-size: 13px; margin-bottom: 16px;">
          Please install an EVM-compatible wallet extension:
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
        <button class="wallet-modal-close">Close</button>
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
        font-size: 12px;
        font-weight: 700;
      }
      .wallet-option-badge {
        width: 28px;
        height: 28px;
        border-radius: 999px;
        display: inline-flex;
        align-items: center;
        justify-content: center;
        background: rgba(255,255,255,0.08);
        color: #f3f4f6;
        border: 1px solid rgba(255,255,255,0.10);
        font-family: Inter, sans-serif;
        letter-spacing: 0.02em;
      }
      .wallet-option-icon-img {
        width: 28px;
        height: 28px;
        border-radius: 999px;
        object-fit: cover;
        border: 1px solid rgba(255,255,255,0.10);
        background: rgba(255,255,255,0.06);
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
    // 始终显示钱包选择弹窗，让用户明确选择
    selectedProvider = await showWalletSelector(providers);
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
      alert("Please authorize wallet access.");
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
      throw new Error("Verification failed");
    }
    
    const { token } = await verifyResp.json();
    
    // 保存 token 和钱包地址
    localStorage.setItem("wallet_token", token);
    localStorage.setItem("wallet_address", walletAddress);
    localStorage.setItem("login_type", "wallet");
    localStorage.removeItem("login_email");
    walletToken = token;
    currentWallet = walletAddress;
    loginType = "wallet";
    loginEmail = null;

    updateWalletUI();
    updateRunButtonState();
    loadWalletHistory();
    
  } catch (err) {
    console.error("Wallet connection failed:", err);
    alert("Failed to connect wallet: " + err.message);
  }
}

function disconnectWallet() {
  localStorage.removeItem("wallet_token");
  localStorage.removeItem("wallet_address");
  localStorage.removeItem("login_type");
  localStorage.removeItem("login_email");
  localStorage.removeItem("github_login");
  localStorage.removeItem("github_oauth_redirect");
  walletToken = null;
  currentWallet = null;
  loginType = null;
  loginEmail = null;
  updateWalletUI();
  updateRunButtonState();

  // Clear history list
  if (historyList) {
    historyList.innerHTML = '<li class="empty" id="history-empty">' + historyI18n("signInToViewHistory") + '</li>';
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
        // Preserve the visible login state on refresh/reload.
        // A transient backend restart should not immediately sign the user out.
        if (historyList) {
          historyList.innerHTML = '<li class="empty" id="history-empty">' + historyI18n("sessionUnavailable") + '</li>';
        }
        if (historyCount) historyCount.textContent = "0 " + historyI18n("records");
        return;
      }
      throw new Error("Failed to load history");
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
  if (historyCount) historyCount.textContent = tasks.length + " " + historyI18n("records");
}

function renderHistoryPage() {
  if (!historyList) return;
  
  var activeFilterBtn = document.querySelector('.filter-btn.active');
  var activeFilter = activeFilterBtn ? activeFilterBtn.dataset.filter : 'all';
  
  // Create a copy of allHistoryTasks to avoid reference issues
  var filteredTasks = allHistoryTasks.slice();
  if (activeFilter !== 'all') {
    filteredTasks = filteredTasks.filter(function(t) { return t.skillType === activeFilter; });
  }
  
  var totalPages = Math.max(1, Math.ceil(filteredTasks.length / ITEMS_PER_PAGE));
  if (currentPage > totalPages) currentPage = totalPages;
  if (currentPage < 1) currentPage = 1;
  
  var startIndex = (currentPage - 1) * ITEMS_PER_PAGE;
  var endIndex = Math.min(startIndex + ITEMS_PER_PAGE, filteredTasks.length);
  var pageTasks = filteredTasks.slice(startIndex, endIndex);
  
  historyList.innerHTML = '';
  
  if (pageTasks.length === 0) {
    historyList.innerHTML = '<li class="empty">' + historyI18n("noAnalysisRecords") + '</li>';
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
  
  updatePagination(totalPages, filteredTasks.length);
}

function createHistoryItem(task) {
  var li = document.createElement("li");
  li.className = "history-item";
  
  var isCompleted = task.status === "completed";
  var isFailed = task.status === "failed";
  var isProcessing = !isCompleted && !isFailed;
  var statusText = isCompleted ? historyI18n("done") : isFailed ? historyI18n("failed") : historyI18n("processing");
  var statusClass = isCompleted ? "success" : isFailed ? "error" : "processing";
  var skillLabel = SKILL_LABELS[task.skillType] || task.skillType;
  var fullName = task.fileName ? task.fileName + '-' + skillLabel : skillLabel;
  var isTruncated = fullName.length > 20;
  var displayName = isTruncated ? fullName.slice(0, 20) + '....' : fullName;
  if (isTruncated) {
    li.setAttribute('data-tooltip', fullName);
    li.classList.add('has-tooltip');
  }

  li.innerHTML =
    '<div class="history-col1">' +
      '<div class="history-skill">' + displayName + '</div>' +
      '<div class="history-time">' + formatHistoryTime(task.createdAt) + '</div>' +
    '</div>' +
    '<div class="history-col2">' +
      '<span class="history-status ' + statusClass + '">' + statusText + '</span>' +
    '</div>' +
    '<div class="history-col3">' +
      (isCompleted ?
        '<div class="history-row">' +
          '<a href="report.html?task=' + task.taskId + '" target="_blank" class="history-link">' + historyI18n("viewReport") + '</a>' +
          '<button class="history-share-btn" data-task-id="' + task.taskId + '" data-skill-type="' + (task.skillType || '') + '">' + historyI18n("shareToX") + ' <svg width="12" height="12" viewBox="0 0 24 24" fill="currentColor" style="vertical-align:-1px"><path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-5.214-6.817L4.99 21.75H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231zm-1.161 17.52h1.833L7.084 4.126H5.117z"/></svg></button>' +
        '</div>' +
        '<button class="history-dl-btn" data-task-id="' + task.taskId + '" data-skill="' + (task.skillType || 'audit') + '">' + historyI18n("pdfButton") + '</button>' :
        '<span class="history-no-report">-</span>') +
    '</div>';
  
  return li;
}

function updatePagination(totalPages, totalItems) {
  if (!pagePrevBtn || !pageNextBtn || !pageInfoEl) return;
  
  pagePrevBtn.disabled = currentPage <= 1;
  pageNextBtn.disabled = currentPage >= totalPages || totalPages <= 1;
  
  pageInfoEl.textContent = historyI18n("pagePrefix") + currentPage + '/' + totalPages + historyI18n("pageSuffix");
}

function goToPage(page) {
  currentPage = page;
  renderHistoryPage();
}

// 自定义登出 Modal
function showDisconnectModal() {
  const overlay = document.getElementById("disconnect-modal");
  const addrEl  = document.getElementById("modal-addr");
  const cancelBtn  = document.getElementById("modal-cancel");
  const confirmBtn = document.getElementById("modal-confirm");
  if (!overlay) { if (confirm("Logout?")) disconnectWallet(); return; }

  // Show user identifier based on login type
  if (addrEl) {
    if (loginType === "google" && loginEmail) {
      addrEl.textContent = loginEmail;
    } else if (currentWallet) {
      addrEl.textContent = currentWallet.slice(0, 6) + "..." + currentWallet.slice(-4);
    }
  }

  overlay.classList.add("is-open");
  overlay.setAttribute("aria-hidden", "false");

  function close() {
    overlay.classList.remove("is-open");
    overlay.setAttribute("aria-hidden", "true");
    cancelBtn.removeEventListener("click", onCancel);
    confirmBtn.removeEventListener("click", onConfirm);
    overlay.removeEventListener("click", onBackdrop);
    document.removeEventListener("keydown", onEsc);
  }
  function onCancel()  { close(); }
  function onConfirm() { close(); disconnectWallet(); }
  function onBackdrop(e) { if (e.target === overlay) close(); }
  function onEsc(e)    { if (e.key === "Escape") close(); }

  cancelBtn.addEventListener("click", onCancel);
  confirmBtn.addEventListener("click", onConfirm);
  overlay.addEventListener("click", onBackdrop);
  document.addEventListener("keydown", onEsc);
}

// 登录按钮事件
if (walletBtn) {
  walletBtn.addEventListener("click", async function() {
    if (currentWallet) {
      showDisconnectModal();
    } else {
      try {
        const method = await showLoginModal();
        if (method === "google") {
          await loginWithGoogle();
        } else if (method === "github") {
          await loginWithGithub();
        } else if (method === "wallet") {
          await connectWallet();
        }
      } catch (err) {
        if (err.message !== "Cancelled") {
          console.error("Login failed:", err);
          alert("Login failed: " + err.message);
        }
      }
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

// History list — PDF download & Share via event delegation
if (historyList) {
  historyList.addEventListener("click", function(e) {
    // PDF download
    var dlBtn = e.target.closest(".history-dl-btn");
    if (dlBtn) {
      var taskId = dlBtn.dataset.taskId;
      var skill  = dlBtn.dataset.skill || "audit";
      var slug   = skill.replace(/^skill-/, "");
      dlBtn.textContent = "…";
      dlBtn.disabled = true;
      triggerDownload(API_BASE + "/api/tasks/" + taskId + "/report/pdf", slug + "-report.pdf")
        .then(function() { dlBtn.textContent = historyI18n("pdfButton"); dlBtn.disabled = false; })
        .catch(function() { dlBtn.textContent = historyI18n("pdfButton"); dlBtn.disabled = false; });
      return;
    }

    // Share to X
    var shareBtn = e.target.closest(".history-share-btn");
    if (shareBtn) {
      var tid = shareBtn.dataset.taskId;
      var skillType = shareBtn.dataset.skillType;
      fetch(API_BASE + "/api/tasks/" + tid + "/report")
        .then(function(r) { return r.ok ? r.text() : ""; })
        .then(function(text) {
          showShareModal(buildShareText({ taskId: tid, skillType: skillType }, text));
        })
        .catch(function() {
          showShareModal(buildShareText({ taskId: tid, skillType: skillType }, ""));
        });
    }
  });
}

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
    
    var filteredTasks = allHistoryTasks.slice();
    if (activeFilter !== 'all') {
      filteredTasks = filteredTasks.filter(function(t) { return t.skillType === activeFilter; });
    }
    var totalPages = Math.ceil(filteredTasks.length / ITEMS_PER_PAGE);
    if (currentPage < totalPages) {
      goToPage(currentPage + 1);
    }
  });
}

window.addEventListener("codeautrix:langchange", function() {
  if (historyList) renderHistoryPage();
});

// 检查本地存储的登录状态
function initWallet() {
  const savedAddress = localStorage.getItem("wallet_address");
  const savedToken = localStorage.getItem("wallet_token");
  const savedLoginType = localStorage.getItem("login_type");
  const savedEmail = localStorage.getItem("login_email");
  // Wallet login requires both address and token;
  // Google/GitHub login only needs address + email (token is optional if backend was unreachable)
  var isWalletLogin = savedAddress && savedToken && savedLoginType !== "google" && savedLoginType !== "github";
  var isGoogleLogin = savedAddress && savedLoginType === "google" && savedEmail;
  var isGithubLogin = savedAddress && savedLoginType === "github" && savedEmail;
  if (isWalletLogin || isGoogleLogin || isGithubLogin) {
    currentWallet = savedAddress;
    walletToken = savedToken || null;
    loginType = savedLoginType || "wallet";
    loginEmail = savedEmail || null;
    updateWalletUI();
    updateRunButtonState();
    loadWalletHistory();
  }
}

// 页面加载时初始化：先处理 OAuth 回调，再恢复 localStorage
(async function initAuth() {
  const handled = await handleGithubCallback() || await handleGoogleCallback();
  if (!handled) {
    initWallet();
  }
})();
