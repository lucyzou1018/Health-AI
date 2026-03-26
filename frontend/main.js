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

const VALID_TABS = Object.keys(PARAM_SCHEMA);
let activeTab = (function () {
  const hash = window.location.hash.replace("#", "");
  return VALID_TABS.includes(hash) ? hash : "skill-security-audit";
})();

// Wallet State
let currentWallet = null;
let walletToken = localStorage.getItem("wallet_token");
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
// 每个 skill 类型是否有任务正在运行
const runningTabs = {
  "skill-security-audit": false,
  "multichain-contract-vuln": false,
  "skill-stress-lab": false,
};

// Pagination state
let allHistoryTasks = [];
let currentPage = 1;
const ITEMS_PER_PAGE = 10;

historyPanel?.classList.add("is-empty");

const FINAL_STATUSES = new Set(["completed", "failed"]);

// 各 tab 的文件大小上限 (MB)
const MAX_FILE_SIZES = {
  "skill-security-audit":    10,
  "multichain-contract-vuln": 50,
  "skill-stress-lab":         50,
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
const DEFAULT_API = (window.location.hostname === 'localhost' && window.location.port === '3000')
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
    statusBox.textContent = "Not Started";
    statusBox.className = "status";
  }
  if (summaryBox) summaryBox.textContent = "Upload a Skill package to view status and download reports here.";
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
    runBtn.textContent = "Connect Wallet First";
  } else if (!hasFile) {
    runBtn.disabled = true;
    runBtn.textContent = "Start Analysis";
  } else if (activeTab === "skill-stress-lab" && !hasValidParams) {
    runBtn.disabled = true;
    runBtn.textContent = "Start Analysis";
  } else if (isRunning) {
    runBtn.disabled = true;
    runBtn.textContent = "Analyzing...";
  } else {
    runBtn.disabled = false;
    runBtn.textContent = "Start Analysis";
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
    const body = {
      skillType: activeTab,
      codePath: codePathValue || null,
      uploadId: uploadId,
      params,
      walletAddress: currentWallet,
      fileName: currentFile ? currentFile.name : null,
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
        setStatus("In Queue", "running");
        setSummary("A task of this type is already running. Please wait for it to complete before submitting a new one.");
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
      finalTask = await pollTask(task.taskId);
      // pollTask 超时时返回 null，不重置上传区（让用户直接 retry）
      if (finalTask === null) {
        runningTabs[taskTab] = false;
        updateRunButtonState();
        return;
      }
    }
    // 任务结束：原地更新历史记录状态
    if (finalTask) upsertHistoryTask(finalTask);
    // Keep uploaded file visible after completion so the user can see
    // which package was analyzed.  The file will be cleared when a new
    // analysis starts (see clearResults() in runTask).
  } catch (err) {
    setStatus("Failed", "error");
    const message = err instanceof Error ? err.message : String(err);
    setSummary(message);
    artifactBox?.classList.add("hidden");
    // 网络/上传阶段失败才清空，扫描本身失败保留文件方便重试
  } finally {
    runningTabs[taskTab] = false;
    updateRunButtonState();
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
  if (!task) return "Upload a package and run an analysis to see results here.";

  const SKILL_NAMES = {
    "skill-security-audit":    "Security Audit",
    "multichain-contract-vuln": "Contract Audit",
    "skill-stress-lab":         "Stress Test"
  };
  const skillName = SKILL_NAMES[task.skillType] || "Analysis";

  if (task.status === "failed") {
    const raw = task.message || "";

    // Special handling for security pre-check failure (Stress Test)
    if (task.skillType === "skill-stress-lab" && raw.includes("high-risk operations")) {
      return "⚠️ This Skill contains high-risk operations and is not eligible for stress testing. Please resolve the security issues before retrying.";
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
      "skill-security-audit":    "Security scan completed. Your health score report is ready.",
      "multichain-contract-vuln": "Contract audit completed. Vulnerability report is ready.",
      "skill-stress-lab":         "Stress test completed. Performance report is ready."
    };
    return msgs[task.skillType] || `${skillName} completed. Your report is ready to download.`;
  }

  // running / pending
  const runMsgs = {
    "skill-security-audit":    "Scanning your Skill package for vulnerabilities…",
    "multichain-contract-vuln": "Auditing smart contract across chains…",
    "skill-stress-lab":         "Running security pre-check before stress test…"
  };
  return runMsgs[task.skillType] || "Analysis in progress, please wait…";
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

function addHistoryTask(task) {
  upsertHistoryTask(task);
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
    alert(`Download failed: ${err.message}`);
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
    items.push(`<a href="report.html?task=${tid}" target="_blank" rel="noopener">📊 View Report</a>`);
    // Download Report — 下载 PDF
    items.push(`<button class="artifact-dl-btn" data-url="${API_BASE}/api/tasks/${tid}/report/pdf" data-filename="${skillSlug}-report.pdf">📄 Download Report</button>`);
  }

  if (!items.length) {
    artifactBox.classList.add("hidden");
    artifactBox.innerHTML = "";
    return;
  }

  artifactBox.classList.remove("hidden");
  artifactBox.innerHTML = items.join("");

  // 绑定下载按钮事件
  artifactBox.querySelectorAll(".artifact-dl-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      triggerDownload(btn.dataset.url, btn.dataset.filename);
    });
  });
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

    renderTask(task);
    if (FINAL_STATUSES.has(task.status)) return task;

    // 显示进度提示，让用户知道系统还在工作
    const elapsed = Math.round((attempts * POLL_INTERVAL) / 1000);
    if (activeTab === "skill-stress-lab") {
      // Stress Test has a security pre-check phase before the actual stress test
      const phase = elapsed < 30
        ? "Running security pre-check…"
        : "Security pre-check passed, running stress test…";
      setSummary(`${phase} (${elapsed}s elapsed)`);
    } else {
      setSummary(
        `Analyzing… (${elapsed}s elapsed — large packages may take several minutes)`
      );
    }

    await delay(POLL_INTERVAL);
    attempts += 1;
  }

  // 超时：服务可能在处理中，给出明确指引
  setStatus("Timeout", "error");
  setSummary(
    "Analysis is taking longer than expected. " +
    "The server may have restarted — please re-upload your file and try again. " +
    "If this keeps happening, check the server logs."
  );
  // 不 throw，避免触发 catch 再次 clearCurrentFile，让用户可以直接 retry
  return null;
}

function renderTask(task) {
  if (!task) return;
  const variant = task.status === "failed" ? "error" : task.status === "completed" ? "success" : "running";
  const statusLabel = {
    completed: "Scan Complete",
    failed:    "Scan Failed",
    running:   "Analyzing…",
    pending:   "Queued"
  }[task.status] || task.status;
  setStatus(statusLabel, variant);
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
  html += `<div class="stat-card high"><span class="stat-number">${highFindings.length}</span><span class="stat-label">High Risk</span></div>`;
  html += `<div class="stat-card medium"><span class="stat-number">${mediumFindings.length}</span><span class="stat-label">Medium Risk</span></div>`;
  html += `<div class="stat-card low"><span class="stat-number">${otherFindings.length}</span><span class="stat-label">Low Risk</span></div>`;
  html += `<div class="stat-card total"><span class="stat-number">${detectorSummaries.length}</span><span class="stat-label">Total</span></div>`;
  html += `</div>`;

  return html;
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
    if (!scores['Overall']) {
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

    // Supply Chain (replaces Token)
    if (/\|\s*[^\|]*Supply Chain/.test(line)) {
      const m = line.match(/\|\s*[^\|]*Supply Chain[^\|]*\|\s*\*?\*?(\d+)\/100/i);
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

  // Determine score class based on value (higher = safer)
  function getScoreClass(score) {
    if (score >= 80) return 'low';      // 优秀 - 绿色
    if (score >= 60) return 'total';    // 良好 - 蓝色
    if (score >= 40) return 'medium';   // 一般 - 黄色
    return 'high';                      // 需改进 - 红色
  }

  // Build 6 score cards — 3-column grid (2 rows of 3)
  let html = `<div class="report-stats-cards report-stats-cards--6">`;
  html += `<div class="stat-card ${getScoreClass(overallScore)}"><span class="stat-number">${overallScore}</span><span class="stat-label"><span class="stat-icon">📊</span>Overall</span></div>`;
  html += `<div class="stat-card ${getScoreClass(privacyScore)}"><span class="stat-number">${privacyScore}</span><span class="stat-label"><span class="stat-icon">🔏</span>Privacy</span></div>`;
  html += `<div class="stat-card ${getScoreClass(privilegeScore)}"><span class="stat-number">${privilegeScore}</span><span class="stat-label"><span class="stat-icon">🔐</span>Privilege</span></div>`;
  html += `<div class="stat-card ${getScoreClass(integrityScore)}"><span class="stat-number">${integrityScore}</span><span class="stat-label"><span class="stat-icon">🛡️</span>Integrity</span></div>`;
  html += `<div class="stat-card ${getScoreClass(supplyChainScore)}"><span class="stat-number">${supplyChainScore}</span><span class="stat-label"><span class="stat-icon">🔗</span>Supply Chain</span></div>`;
  html += `<div class="stat-card ${getScoreClass(failureScore)}"><span class="stat-number">${failureScore}</span><span class="stat-label"><span class="stat-icon">✅</span>Stability</span></div>`;
  html += `</div>`;

  // Add score legend
  html += `<div style="margin-top: 8px; padding: 8px 12px; background: rgba(99, 102, 241, 0.1); border-radius: 6px; font-size: 12px; color: #94a3b8;">`;
  html += `Score: 80-100 = Excellent 🟢 | 60-79 = Good 🔵 | 40-59 = Fair 🟡 | &lt;40 = Needs Work 🔴`;
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
    if (score >= 80) return 'low';      // Excellent - green
    if (score >= 60) return 'total';    // Good - blue
    if (score >= 40) return 'medium';   // Fair - yellow
    return 'high';                      // Needs Work - red
  }
  
  // Build 6 score cards (overall + 5 dimensions) — 3-column grid (2 rows of 3)
  let html = `<div class="report-stats-cards report-stats-cards--6">`;
  html += `<div class="stat-card ${getScoreClass(overallScore)}"><span class="stat-number">${overallScore}</span><span class="stat-label"><span class="stat-icon">🎯</span>Overall</span></div>`;
  html += `<div class="stat-card ${getScoreClass(stabilityScore)}"><span class="stat-number">${stabilityScore}</span><span class="stat-label"><span class="stat-icon">🛡️</span>Stability</span></div>`;
  html += `<div class="stat-card ${getScoreClass(performanceScore)}"><span class="stat-number">${performanceScore}</span><span class="stat-label"><span class="stat-icon">⚡</span>Performance</span></div>`;
  html += `<div class="stat-card ${getScoreClass(resourceScore)}"><span class="stat-number">${resourceScore}</span><span class="stat-label"><span class="stat-icon">💾</span>Resource</span></div>`;
  html += `<div class="stat-card ${getScoreClass(consistencyScore)}"><span class="stat-number">${consistencyScore}</span><span class="stat-label"><span class="stat-icon">🔄</span>Consistency</span></div>`;
  html += `<div class="stat-card ${getScoreClass(recoveryScore)}"><span class="stat-number">${recoveryScore}</span><span class="stat-label"><span class="stat-icon">🆘</span>Recovery</span></div>`;
  html += `</div>`;

  // Add score legend
  html += `<div style="margin-top: 8px; padding: 8px 12px; background: rgba(99, 102, 241, 0.1); border-radius: 6px; font-size: 12px; color: #94a3b8;">`;
  html += `Score: 80-100 = Excellent 🟢 | 60-79 = Good 🔵 | 40-59 = Fair 🟡 | &lt;40 = Needs Work 🔴`;
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
    `For the ${name} finding, review the related business logic and apply the remediation suggestions in the report.`
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
    walletText.textContent = "Connect Wallet";
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
        <h3>Select Wallet</h3>
        <div class="wallet-list">
          ${providers.map((p, i) => `
            <button class="wallet-option" data-index="${i}">
              <span class="wallet-option-icon">${p.icon}</span>
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
      reject(new Error("Cancelled by user"));
    });

    modal.querySelector(".wallet-modal-backdrop").addEventListener("click", () => {
      document.body.removeChild(modal);
      document.head.removeChild(style);
      reject(new Error("Cancelled by user"));
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
        <h3>No Wallet Detected</h3>
        <p style="color: var(--text-secondary); font-size: 13px; margin-bottom: 16px;">
          Please install one of the following wallets:
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
    walletToken = token;
    currentWallet = walletAddress;
    
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
  walletToken = null;
  currentWallet = null;
  updateWalletUI();
  updateRunButtonState();
  
  // Clear history list
  if (historyList) {
    historyList.innerHTML = '<li class="empty" id="history-empty">Connect wallet to view history</li>';
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
  if (historyCount) historyCount.textContent = tasks.length + " records";
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
    historyList.innerHTML = '<li class="empty">No analysis records found</li>';
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
  var statusText = isCompleted ? "Done" : isFailed ? "Failed" : "Processing";
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
        '<a href="report.html?task=' + task.taskId + '" target="_blank" class="history-link">View Report</a>' +
        '<button class="history-dl-btn" data-task-id="' + task.taskId + '" data-skill="' + (task.skillType || 'audit') + '" title="Download PDF">↓ PDF</button>' :
        '<span class="history-no-report">-</span>') +
    '</div>';
  
  return li;
}

function updatePagination(totalPages, totalItems) {
  if (!pagePrevBtn || !pageNextBtn || !pageInfoEl) return;
  
  pagePrevBtn.disabled = currentPage <= 1;
  pageNextBtn.disabled = currentPage >= totalPages || totalPages <= 1;
  
  pageInfoEl.textContent = 'Page ' + currentPage + '/' + totalPages;
}

function goToPage(page) {
  currentPage = page;
  renderHistoryPage();
}

// 自定义断开钱包 Modal
function showDisconnectModal() {
  const overlay = document.getElementById("disconnect-modal");
  const addrEl  = document.getElementById("modal-addr");
  const cancelBtn  = document.getElementById("modal-cancel");
  const confirmBtn = document.getElementById("modal-confirm");
  if (!overlay) { if (confirm("Disconnect wallet?")) disconnectWallet(); return; }

  // 显示截断地址
  if (addrEl && currentWallet) {
    addrEl.textContent = currentWallet.slice(0, 6) + "..." + currentWallet.slice(-4);
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

// 钱包按钮事件
if (walletBtn) {
  walletBtn.addEventListener("click", function() {
    if (currentWallet) {
      showDisconnectModal();
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

// History list — PDF download via event delegation
if (historyList) {
  historyList.addEventListener("click", function(e) {
    var btn = e.target.closest(".history-dl-btn");
    if (!btn) return;
    var taskId = btn.dataset.taskId;
    var skill  = btn.dataset.skill || "audit";
    var slug   = skill.replace(/^skill-/, "");
    btn.textContent = "…";
    btn.disabled = true;
    triggerDownload(API_BASE + "/api/tasks/" + taskId + "/report/pdf", slug + "-report.pdf")
      .then(function() { btn.textContent = "↓ PDF"; btn.disabled = false; })
      .catch(function() { btn.textContent = "↓ PDF"; btn.disabled = false; });
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

