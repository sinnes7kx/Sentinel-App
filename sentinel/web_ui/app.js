"use strict";

const byId = (id) => document.getElementById(id);
const assessmentForm = byId("assessment-form");
const includeDns = byId("include-dns");
const dns = byId("dns");
const authorized = byId("authorized");
const reportFile = byId("report-file");
const tool = byId("tool");
let selectedId;
let viewRevision = 0;

function element(tag, value) {
  const node = document.createElement(tag);
  node.textContent = value;
  return node;
}

async function request(path, options) {
  const response = await fetch(path, options);
  const body = await response.json();
  if (!response.ok) throw new Error(body.error || "Sentinel could not complete this request.");
  return body;
}

function displayResult(id, result) {
  selectedId = id;
  for (const button of byId("history").querySelectorAll("button")) {
    button.setAttribute("aria-current", String(button.dataset.id === String(id)));
  }
  byId("result-target").textContent = result.target;
  const status = result.status.charAt(0).toUpperCase() + result.status.slice(1);
  const count = result.findings.length;
  const connection = [result.http_status && ("HTTP " + result.http_status), result.tls].filter(Boolean);
  byId("result-summary").textContent = [status, count + (count === 1 ? " observation" : " observations"), ...connection].join(" · ");
  byId("result-error").textContent = result.error;
  byId("result-error").hidden = !result.error;
  const coverage = Object.entries(result.coverage || {}).filter(([, value]) => typeof value === "string");
  byId("result-coverage").textContent = coverage.map(([key, value]) => key.toUpperCase() + " — " + value).join(" · ");
  for (const format of ["html", "json"]) {
    byId("download-" + format).href = "/api/history/" + id + "/" + format;
  }
  byId("findings").replaceChildren(...result.findings.map((finding) => {
    const section = document.createElement("details");
    section.append(
      element("summary", finding.title + " · " + finding.severity),
      element("p", finding.evidence),
      element("p", "How to fix it — " + finding.remediation)
    );
    return section;
  }));
  byId("results").hidden = false;
  byId("results-heading").focus();
}

async function loadHistory() {
  const status = byId("history-status");
  try {
    const history = await request("/api/history");
    status.textContent = history.length ? "" : "Your assessments will appear here.";
    byId("history").replaceChildren(...history.map((entry) => {
      const item = document.createElement("li");
      const button = element("button", entry.target);
      button.type = "button";
      button.dataset.id = entry.id;
      button.setAttribute("aria-current", String(entry.id === selectedId));
      button.append(element("small", new Date(entry.started).toLocaleString() + " · " + entry.status));
      button.addEventListener("click", async () => {
        const revision = ++viewRevision;
        try {
          const result = await request("/api/history/" + entry.id);
          if (revision === viewRevision) {
            status.textContent = "";
            displayResult(entry.id, result);
          }
        } catch (error) {
          if (revision === viewRevision) status.textContent = error.message;
        }
      });
      item.append(button);
      return item;
    }));
  } catch (error) {
    status.textContent = error.message;
  }
}

async function loadOptions() {
  const hint = byId("dns-hint");
  try {
    const options = await request("/api/options");
    includeDns.disabled = !options.dns;
    if (options.dns) return;
    hint.textContent = "Requires dnspython in the Python environment running Sentinel.";
  } catch (error) {
    hint.textContent = "Sentinel could not check DNS availability.";
  }
  hint.hidden = false;
}

assessmentForm.addEventListener("input", (event) => {
  if (event.target !== authorized) authorized.checked = false;
});

includeDns.addEventListener("change", () => {
  byId("dns-field").hidden = !includeDns.checked;
  dns.required = includeDns.checked;
});

assessmentForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const run = byId("run");
  if (run.disabled) return;
  const status = byId("assessment-status");
  const payload = {
    url: byId("url").value.trim(),
    dns: includeDns.checked ? dns.value.trim() : "",
    authorized: authorized.checked,
  };
  if (includeDns.checked && !payload.dns) {
    status.textContent = "Enter the DNS domain you have permission to check.";
    dns.focus();
    return;
  }
  run.disabled = true;
  authorized.checked = false;
  status.classList.remove("error");
  status.textContent = "Checking the website…";
  try {
    const { id, result } = await request("/api/assessment", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    ++viewRevision;
    displayResult(id, result);
    status.textContent = "Saved to recent assessments.";
    await loadHistory();
  } catch (error) {
    status.classList.add("error");
    status.textContent = error.message;
  } finally {
    run.disabled = false;
  }
});

tool.addEventListener("change", () => {
  reportFile.accept = { zap: ".json", nmap: ".xml", wireshark: ".csv" }[tool.value];
  reportFile.value = "";
  byId("review-status").textContent = "";
  byId("review-result").hidden = true;
});

byId("review-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const read = byId("read-report");
  if (read.disabled) return;
  const status = byId("review-status");
  const output = byId("review-result");
  const [file] = reportFile.files;
  if (!file) return;
  output.hidden = true;
  status.classList.remove("error");
  if (file.size === 0 || file.size > 5 * 1024 * 1024) {
    status.classList.add("error");
    status.textContent = "Choose a nonempty report of at most 5 MB.";
    return;
  }
  read.disabled = tool.disabled = reportFile.disabled = true;
  status.textContent = "Reading the report…";
  try {
    const summary = await request("/api/review/" + tool.value, {
      method: "POST",
      headers: { "Content-Type": "application/octet-stream" },
      body: file,
    });
    const rows = [];
    for (const [label, value] of Object.entries(summary)) {
      if (typeof value === "object") {
        for (const [name, count] of Object.entries(value)) {
          rows.push(element("dt", name), element("dd", count));
        }
      } else {
        rows.push(element("dt", label), element("dd", value));
      }
    }
    output.replaceChildren(...rows);
    output.hidden = false;
    status.textContent = "Report summarized.";
  } catch (error) {
    status.classList.add("error");
    status.textContent = error.message;
  } finally {
    read.disabled = tool.disabled = reportFile.disabled = false;
  }
});

loadOptions();
loadHistory();
