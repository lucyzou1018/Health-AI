const API_BASE = window.HEALTH_AI_API || "http://127.0.0.1:8000";
const PARAM_SCHEMA = {
  "agent-audit": [],
  "multichain-contract-vuln": [
    { id: "evmAddress", label: "EVM 地址", type: "text", placeholder: "0x...（可选）" },
    { id: "network", label: "EVM 网络", type: "text", placeholder: "mainnet" },
    { id: "chain", label: "链类型", type: "select", options: ["evm", "solana"], placeholder: "evm" },
    { id: "scope", label: "报告前缀", type: "text", placeholder: "health-ai" },
    { id: "runAnchor", label: "运行 anchor test", type: "checkbox" },
    { id: "etherscanApiKey", label: "Etherscan API Key", type: "password", placeholder: "仅在链上抓取时需要" }
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

let activeTab = "agent-audit";
const navButtons = document.querySelectorAll("#nav-tabs button");
const paramContainer = document.getElementById("param-fields");
const statusBox = document.getElementById("task-status");
const outputBox = document.getElementById("task-output");
const runBtn = document.getElementById("run-task");
const codePathInput = document.getElementById("code-path");
const fileInput = document.getElementById("code-upload");

function selectTab(tab) {
  activeTab = tab;
  navButtons.forEach((btn) => btn.classList.toggle("active", btn.dataset.tab === tab));
  renderParamFields();
}

function renderField(field) {
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
  return wrapper;
}

function renderParamFields() {
  paramContainer.innerHTML = "";
  const schema = PARAM_SCHEMA[activeTab] || [];
  schema.forEach((field) => paramContainer.appendChild(renderField(field)));
}

async function uploadFileIfNeeded() {
  const file = fileInput.files[0];
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
      if (!Number.isNaN(value) && value !== undefined) {
        params[field.id] = value;
      }
    } else if (field.type === "select" || field.type === "text" || field.type === "textarea" || field.type === "password") {
      if (el.value) params[field.id] = el.value;
    } else if (field.type === "checkbox") {
      params[field.id] = el.checked;
    } else {
      if (el.value) params[field.id] = el.value;
    }
  });
  return params;
}

async function runTask() {
  try {
    statusBox.textContent = "运行中...";
    outputBox.textContent = "";
    const uploadId = await uploadFileIfNeeded();
    const params = collectParams();
    if (!codePathInput.value && !uploadId) {
      throw new Error("请填写代码路径或上传文件");
    }
    if (activeTab === "skill-stress-lab" && !params.command) {
      throw new Error("Stress Lab 需要命令模板");
    }
    const body = {
      skillType: activeTab,
      codePath: codePathInput.value || null,
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
    const data = await resp.json();
    statusBox.textContent = `状态：${data.status}`;
    outputBox.textContent = JSON.stringify(data, null, 2);
  } catch (err) {
    statusBox.textContent = "失败";
    outputBox.textContent = err instanceof Error ? err.message : String(err);
  }
}

navButtons.forEach((btn) => btn.addEventListener("click", () => selectTab(btn.dataset.tab)));
runBtn.addEventListener("click", runTask);
renderParamFields();
