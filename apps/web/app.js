/* Spigot (DocForge MCP) Local Compiler UI Controller (T20-T21)
 * Zero external dependencies. Renders all untrusted document quotes via textContent.
 */
(function () {
  "use strict";

  const state = {
    capabilityToken: "",
    projectId: window.localStorage.getItem("spigot_active_project_id") || "",
    currentRevision: 1,
    contractHash: "",
    isFrozen: false,
    planHash: "",
    artifactId: "",
    activeJobId: "",
  };

  function showAlert(msg) {
    const el = document.getElementById("global-alert");
    if (!msg) {
      el.classList.add("hidden");
      el.textContent = "";
      return;
    }
    el.textContent = msg;
    el.classList.remove("hidden");
  }

  async function apiFetch(path, options = {}) {
    const headers = Object.assign({}, options.headers || {});
    if (state.capabilityToken) {
      headers["X-Spigot-Token"] = state.capabilityToken;
    }
    if (options.json !== undefined) {
      headers["Content-Type"] = "application/json";
      options.body = JSON.stringify(options.json);
    }
    const resp = await fetch(path, Object.assign({}, options, { headers }));
    const data = await resp.json();
    if (!resp.ok) {
      throw new Error(data.user_message || `HTTP ${resp.status}`);
    }
    return data;
  }

  function switchTab(stepId) {
    document.querySelectorAll(".wizard-panel").forEach((panel) => {
      panel.classList.toggle("hidden", panel.id !== stepId);
    });
    document.querySelectorAll(".step-tab").forEach((tab) => {
      tab.classList.toggle("active", tab.dataset.step === stepId);
    });
  }

  async function bootstrap() {
    try {
      const session = await apiFetch("/api/session");
      state.capabilityToken = session.capability_token;
      document.getElementById("badge-network").textContent =
        `Network: ${session.default_network_profile}`;
      const m = session.local_model;
      document.getElementById("badge-model").textContent = m.available
        ? `Model: ${m.configured_model} (Ready)`
        : `Model: Manual Review Mode (Offline)`;
      if (state.projectId) {
        await refreshProject();
      }
    } catch (err) {
      showAlert(`Session bootstrap failed: ${err.message}`);
    }
  }

  async function refreshProject() {
    if (!state.projectId) return;
    try {
      const proj = await apiFetch(`/api/projects/${state.projectId}`);
      state.currentRevision = proj.current_revision;
      state.isFrozen = Boolean(proj.is_contract_frozen);
      document.getElementById("badge-revision").textContent =
        `Revision: r${proj.current_revision}${state.isFrozen ? " (FROZEN)" : ""}`;

      document.getElementById("project-summary-box").textContent =
        `Project: ${proj.name} (${proj.project_id}) | Sources: ${proj.sources.length} | Revision: r${proj.current_revision}`;

      const srcList = document.getElementById("source-list");
      srcList.textContent = "";
      proj.sources.forEach((s) => {
        const li = document.createElement("li");
        li.className = "item-row";
        li.textContent = `${s.original_name} [${s.media_type}] — SHA256: ${s.content_sha256.slice(0, 12)}...`;
        srcList.appendChild(li);
      });

      if (proj.jobs && proj.jobs.length > 0) {
        const latestJob = proj.jobs[0];
        state.activeJobId = latestJob.job_id;
        document.getElementById("job-status-box").textContent =
          `Latest Job: ${latestJob.job_id} (${latestJob.job_type}) — Status: ${latestJob.status} (${latestJob.progress_pct}%)`;
      }

      if (proj.contract) {
        state.contractHash = proj.contract.canonical_hash;
        renderOperationsChecklist(proj.contract);
        await loadFindings(proj.contract);
      }

      if (proj.tool_plan) {
        state.planHash = proj.tool_plan.plan_hash;
        document.getElementById("plan-summary-box").textContent =
          `Active ToolPlan: ${proj.tool_plan.id} | Selected Tools: ${proj.tool_plan.operation_ids.join(", ")} | Hash: ${state.planHash.slice(0, 16)}...`;
      }

      if (proj.latest_artifact) {
        state.artifactId = proj.latest_artifact.artifact_id;
        const dl = document.getElementById("link-download-zip");
        dl.href = `/api/artifacts/${state.artifactId}/download`;
        dl.classList.remove("hidden");
        document.getElementById("export-summary-box").textContent =
          `Artifact: ${state.artifactId} | ZIP SHA256: ${proj.latest_artifact.zip_sha256}`;
      }

      if (proj.latest_validation) {
        renderValidationBadges(proj.latest_validation);
      }
    } catch (err) {
      window.localStorage.removeItem("spigot_active_project_id");
      state.projectId = "";
    }
  }

  async function loadFindings(contract) {
    if (!state.projectId) return;
    const res = await apiFetch(`/api/projects/${state.projectId}/findings`);
    const container = document.getElementById("findings-list");
    container.textContent = "";
    const ops = (contract && contract.operations) || [];
    if ((!res.findings || res.findings.length === 0) && ops.length > 0) {
      const okBanner = document.createElement("div");
      okBanner.className = "item-row resolved";
      okBanner.textContent = `✅ 0 Open Blockers — ${ops.length} supported endpoint(s) extracted cleanly! Click "Freeze Contract Revision" on the right to proceed to Step 4.`;
      container.appendChild(okBanner);
      ops.forEach((op) => {
        const opRow = document.createElement("div");
        opRow.className = "item-row";
        opRow.tabIndex = 0;
        const paramNames = (op.parameters || []).map((p) => `${p.external_name} (${p.location})`).join(", ");
        opRow.textContent = `[READY] ${op.method} ${op.relative_path} (${op.stable_id}) — Auth: ${op.security_requirement.status} — Params: ${paramNames || "none"}`;
        opRow.addEventListener("click", () => {
          document.getElementById("input-override-op").value = op.stable_id;
          document.getElementById("evidence-viewer").textContent =
            `Operation: ${op.display_name} (${op.stable_id})\nMethod & Path: ${op.method} ${op.relative_path}\nSemantic Effect: ${op.semantic_effect}\nAuth Status: ${op.security_requirement.status}\nParameters: ${JSON.stringify(op.parameters || [], null, 2)}\nRequest Body: ${JSON.stringify(op.request_body || null, null, 2)}`;
        });
        container.appendChild(opRow);
      });
      return;
    }
    if (!res.findings || res.findings.length === 0) {
      container.textContent = "No findings recorded.";
      return;
    }
    res.findings.forEach((f) => {
      const div = document.createElement("div");
      div.className = `item-row ${f.status === "resolved" ? "resolved" : f.severity}`;
      div.tabIndex = 0;
      div.textContent = `[${f.status.toUpperCase()} / ${f.severity.toUpperCase()}] ${f.code} (${f.operation_id || "contract"} -> ${f.affected_field}): ${f.explanation}`;
      div.addEventListener("click", () => {
        document.getElementById("input-override-op").value = f.operation_id || "";
        const evLines = (f.evidence_details || []).map((ev) => {
          const loc = ev.location || {};
          const pageInfo = loc.page_number ? `Page ${loc.page_number}, ` : "";
          return `Source: ${ev.source_id} (${pageInfo}Lines ${loc.start_line}-${loc.end_line})\nHeading: ${(ev.heading_path || []).join(" > ")}\nQuote: "${ev.exact_quote}"`;
        });
        document.getElementById("evidence-viewer").textContent =
          evLines.join("\n\n") || "No direct quote span attached.";
      });
      container.appendChild(div);
    });
  }

  function renderOperationsChecklist(contract) {
    const container = document.getElementById("operations-checklist");
    container.textContent = "";
    (contract.operations || []).forEach((op) => {
      const row = document.createElement("div");
      row.className = "item-row";
      const cb = document.createElement("input");
      cb.type = "checkbox";
      cb.value = op.stable_id;
      cb.checked = op.support_status === "supported";
      cb.disabled = op.support_status === "blocked";
      cb.className = "op-checkbox";
      const lbl = document.createElement("span");
      lbl.textContent = ` ${op.stable_id} [${op.method} ${op.relative_path}] — effect: ${op.semantic_effect} — status: ${op.support_status.toUpperCase()}`;
      row.appendChild(cb);
      row.appendChild(lbl);
      container.appendChild(row);
    });
  }

  function renderValidationBadges(report) {
    const checkMap = {};
    (report.checks || []).forEach((c) => {
      checkMap[c.check_name] = c.status;
    });
    document.querySelectorAll(".v-badge").forEach((badge) => {
      const key = badge.dataset.check;
      const status = checkMap[key] || report[key];
      if (status) {
        const label = badge.textContent.split(":")[0];
        badge.textContent = `${label}: ${String(status).toUpperCase()}`;
      }
    });
  }

  document.querySelectorAll(".step-tab").forEach((tab) => {
    tab.addEventListener("click", () => switchTab(tab.dataset.step));
  });

  document.getElementById("form-create-project").addEventListener("submit", async (e) => {
    e.preventDefault();
    showAlert("");
    try {
      const name = document.getElementById("input-project-name").value.trim();
      const proj = await apiFetch("/api/projects", {
        method: "POST",
        json: { name },
      });
      state.projectId = proj.project_id;
      window.localStorage.setItem("spigot_active_project_id", state.projectId);
      await refreshProject();
    } catch (err) {
      showAlert(err.message);
    }
  });

  document.querySelectorAll(".btn-load-example").forEach((btn) => {
    btn.addEventListener("click", async () => {
      showAlert("");
      const exampleId = btn.dataset.example;
      try {
        if (!state.projectId) {
          const proj = await apiFetch("/api/projects", {
            method: "POST",
            json: { name: `Sample (${exampleId.toUpperCase()}) Project` },
          });
          state.projectId = proj.project_id;
          window.localStorage.setItem("spigot_active_project_id", state.projectId);
        }
        await apiFetch(`/api/projects/${state.projectId}/load-example`, {
          method: "POST",
          json: { example_id: exampleId },
        });
        const job = await apiFetch(`/api/projects/${state.projectId}/extract`, {
          method: "POST",
          json: { use_local_model: false },
        });
        state.activeJobId = job.job_id;
        await refreshProject();
        switchTab("step-review");
      } catch (err) {
        showAlert(err.message);
      }
    });
  });

  const btnClearSources = document.getElementById("btn-clear-sources");
  if (btnClearSources) {
    btnClearSources.addEventListener("click", async () => {
      showAlert("");
      if (!state.projectId) {
        showAlert("No active project to clear.");
        return;
      }
      try {
        await apiFetch(`/api/projects/${state.projectId}/sources/clear`, {
          method: "POST",
          json: {},
        });
        document.getElementById("findings-list").textContent = "";
        document.getElementById("operations-checklist").textContent = "";
        await refreshProject();
      } catch (err) {
        showAlert(err.message);
      }
    });
  }

  document.getElementById("form-upload-sources").addEventListener("submit", async (e) => {
    e.preventDefault();
    showAlert("");
    if (!state.projectId) {
      showAlert("Create a project first.");
      return;
    }
    const fileInput = document.getElementById("input-source-files");
    if (!fileInput.files || fileInput.files.length === 0) {
      showAlert("Select at least one local file.");
      return;
    }
    try {
      const filesPayload = [];
      for (const file of fileInput.files) {
        const buf = await file.arrayBuffer();
        const bytes = new Uint8Array(buf);
        let binary = "";
        for (let i = 0; i < bytes.byteLength; i++) {
          binary += String.fromCharCode(bytes[i]);
        }
        filesPayload.push({
          filename: file.name,
          content_base64: window.btoa(binary),
        });
      }
      await apiFetch(`/api/projects/${state.projectId}/sources`, {
        method: "POST",
        json: { files: filesPayload },
      });
      await refreshProject();
    } catch (err) {
      showAlert(err.message);
    }
  });

  document.getElementById("btn-run-extract").addEventListener("click", async () => {
    showAlert("");
    if (!state.projectId) return;
    try {
      const job = await apiFetch(`/api/projects/${state.projectId}/extract`, {
        method: "POST",
        json: { use_local_model: false },
      });
      state.activeJobId = job.job_id;
      await refreshProject();
      switchTab("step-review");
    } catch (err) {
      showAlert(err.message);
    }
  });

  document.getElementById("form-review-override").addEventListener("submit", async (e) => {
    e.preventDefault();
    showAlert("");
    if (!state.projectId) return;
    try {
      const opId = document.getElementById("input-override-op").value.trim() || null;
      const targetField = document.getElementById("select-override-field").value;
      const rawVal = document.getElementById("input-override-value").value.trim();
      const rationale = document.getElementById("input-override-rationale").value.trim();
      let parsedVal = rawVal;
      if (rawVal.startsWith("{") || rawVal.startsWith("[")) {
        parsedVal = JSON.parse(rawVal);
      }
      await apiFetch(`/api/projects/${state.projectId}/review`, {
        method: "PATCH",
        json: {
          expected_revision: state.currentRevision,
          operation_id: opId,
          target_field: targetField,
          new_value: parsedVal,
          rationale,
        },
      });
      await refreshProject();
    } catch (err) {
      showAlert(err.message);
    }
  });

  document.getElementById("btn-freeze-contract").addEventListener("click", async () => {
    showAlert("");
    if (!state.projectId) return;
    try {
      await apiFetch(`/api/projects/${state.projectId}/contracts/freeze`, {
        method: "POST",
        json: { expected_revision: state.currentRevision },
      });
      await refreshProject();
      switchTab("step-plan");
    } catch (err) {
      showAlert(err.message);
    }
  });

  document.getElementById("form-create-plan").addEventListener("submit", async (e) => {
    e.preventDefault();
    showAlert("");
    if (!state.projectId) return;
    try {
      const selected = [];
      document.querySelectorAll(".op-checkbox:checked").forEach((cb) => {
        selected.push(cb.value);
      });
      const policyMode = document.getElementById("select-policy-mode").value;
      await apiFetch(`/api/projects/${state.projectId}/tool-plans`, {
        method: "POST",
        json: {
          contract_hash: state.contractHash,
          selected_operation_ids: selected,
          policy_mode: policyMode,
        },
      });
      await refreshProject();
      switchTab("step-export");
    } catch (err) {
      showAlert(err.message);
    }
  });

  document.getElementById("btn-generate-server").addEventListener("click", async () => {
    showAlert("");
    if (!state.projectId || !state.planHash) return;
    try {
      await apiFetch(`/api/projects/${state.projectId}/generate`, {
        method: "POST",
        json: { plan_hash: state.planHash },
      });
      await refreshProject();
    } catch (err) {
      showAlert(err.message);
    }
  });

  document.getElementById("btn-validate-artifact").addEventListener("click", async () => {
    showAlert("");
    if (!state.artifactId) return;
    try {
      await apiFetch(`/api/artifacts/${state.artifactId}/validate`, {
        method: "POST",
        json: { suite_profile: "strict_offline" },
      });
      await refreshProject();
    } catch (err) {
      showAlert(err.message);
    }
  });

  bootstrap();
})();
