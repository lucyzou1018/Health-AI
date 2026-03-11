const API_BASE = window.HEALTH_AI_API || "http://127.0.0.1:8000";
const PARAM_SCHEMA = {
  "agent-audit": [
    { id: "notes", label: "备注", type: "text", placeholder: "可选" }
  ],
  "multichain-contract-vuln": [
    { id: "chain", label: "链类型", type: "select", options: ["EVM", "Solana"], placeholder: "EVM" }
  ],
  "skill-stress-lab": [
    { id: "runs", label: "Runs", type: "number", placeholder: "30" },
    { id: "concurrency", label: "Concurrency", type: "number", placeholder: "1" }
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

function renderParamFields() {
  paramContainer.innerHTML = "";
  const schema = PARAM_SCHEMA[activeTab] || [];
  schema.forEach((field) => {
    const wrapper = document.createElement("label");
    wrapper.textContent = field.label;
    let input;
    if (field.type === "select") {
      input = document.createElement("select");
      field.options.forEach((opt) => {
        const option = document.createElement("option");
        option.value = opt;
        option.textContent = opt;
        input.appendChild(option);
      });
    } else {
      input = document.createElement("input");
      input.type = field.type;
      input.placeholder = field.placeholder || "";
    }
    input.id = `param-${field.id}`;
    wrapper.appendChild(input);
    paramContainer.appendChild(wrapper);
  });
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
      if (value) params[field.id] = value;
    } else if (field.type === "select") {
      params[field.id] = el.value;
    } else if (el.value) {
      params[field.id] = el.value;
    }
  });
  return params;
}

async function runTask() {
  statusBox.textContent = "运行中...";
  outputBox.textContent = "";
  try {
    const uploadId = await uploadFileIfNeeded();
    const body = {
      skillType: activeTab,
      codePath: codePathInput.value || null,
      uploadId: uploadId,
      params: collectParams(),
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

navButtons.forEach((btn) => {
  btn.addEventListener("click", () => selectTab(btn.dataset.tab));
});
runBtn.addEventListener("click", runTask);
renderParamFields();
