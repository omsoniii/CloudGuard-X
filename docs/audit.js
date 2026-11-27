
"use strict";

const $ = id => document.getElementById(id);

const MAX_SIZE = 5 * 1024 * 1024;
const MAX_FINDINGS = 10000;
const VALID_STATUS = ["PASS", "FAIL", "WARN", "INFO"];

let findings = [];
let importVersion = 0;

// =====================================
// REPORT VALIDATION
// =====================================

function validateReport(report) {

    if (!report || typeof report !== "object") {
        throw new Error("Invalid report format.");
    }

    if (
        report.tool !== "CloudGuard X" ||
        report.schema_version !== "1.0"
    ) {
        throw new Error("Unsupported CloudGuard report.");
    }

    if (
        typeof report.region !== "string" ||
        !/^[a-z0-9-]{1,50}$/.test(report.region)
    ) {
        throw new Error("Invalid AWS region.");
    }

    if (
        typeof report.generated_at !== "string" ||
        !Number.isFinite(Date.parse(report.generated_at))
    ) {
        throw new Error("Invalid report timestamp.");
    }

    if (
        !Array.isArray(report.findings) ||
        report.findings.length === 0 ||
        report.findings.length > MAX_FINDINGS
    ) {
        throw new Error("Invalid number of findings.");
    }

    return report.findings.map(item => {

        if (
            !item ||
            !VALID_STATUS.includes(item.status)
        ) {
            throw new Error("Invalid finding status.");
        }

        for (const key of [
            "domain", "resource", "message"
        ]) {
            if (
                typeof item[key] !== "string" ||
                item[key].length > 2000 ||
                !item[key].trim()
            ) {
                throw new Error("Invalid finding data.");
            }
        }

        return {
            domain: item.domain,
            resource: item.resource,
            message: item.message,
            status: item.status
        };
    });
}

// =====================================
// SECURITY STATISTICS
// =====================================

function calculateStats(items) {

    const result = {
        PASS: 0,
        FAIL: 0,
        WARN: 0,
        INFO: 0
    };

    items.forEach(item => {
        result[item.status]++;
    });

    result.total =
        result.PASS + result.FAIL + result.WARN;

    result.score = result.total
        ? (result.PASS / result.total) * 100
        : null;

    return result;
}

// =====================================
// ANIMATED COUNTERS
// =====================================

function animateNumber(id, target) {

    const element = $(id);

    if (
        window.matchMedia(
            "(prefers-reduced-motion: reduce)"
        ).matches
    ) {
        element.textContent = target;
        return;
    }

    const start = performance.now();
    const version = importVersion;

    function update(now) {

        if (version !== importVersion) return;

        const progress = Math.min(
            (now - start) / 900, 1
        );

        element.textContent = Math.round(
            target * progress
        ).toString().padStart(2, "0");

        if (progress < 1) {
            requestAnimationFrame(update);
        }
    }

    requestAnimationFrame(update);
}

// =====================================
// DOMAIN ANALYTICS
// =====================================

function renderDomains() {

    const container = $("domain-chart");
    container.replaceChildren();

    const domains = [
        ...new Set(findings.map(f => f.domain))
    ].sort();

    domains.forEach(name => {

        const items = findings.filter(
            f => f.domain === name
        );

        const stats = calculateStats(items);

        const row = document.createElement("div");
        row.className = "domain-row";

        const heading = document.createElement("div");
        heading.className = "domain-heading";

        const label = document.createElement("span");
        label.textContent = name;

        const value = document.createElement("strong");

        value.textContent = stats.score === null
            ? "Not evaluated"
            : `${stats.PASS}/${stats.total} passed`;

        heading.append(label, value);
        row.appendChild(heading);

        if (stats.score !== null) {

            const progress =
                document.createElement("progress");

            progress.className = "domain-progress";
            progress.max = 100;
            progress.value = stats.score;

            progress.setAttribute(
                "aria-label",
                `${name} pass rate`
            );

            row.appendChild(progress);
        }

        container.appendChild(row);
    });
}

// =====================================
// REMEDIATION RECOMMENDATIONS
// =====================================

function recommendationFor(finding) {

    const message = finding.message.toLowerCase();

    if (message.includes("root mfa")) {
        return "Enable MFA for the AWS root user.";
    }

    if (message.includes("root access keys")) {
        return "Review and securely remove unnecessary root access keys.";
    }

    if (message.includes("unable to verify")) {
        return "Verify audit permissions and repeat the affected check.";
    }

    if (message.includes("public access block")) {
        return "Review S3 public access settings and enable appropriate public access blocking.";
    }

    if (message.includes("ssh open")) {
        return "Restrict inbound TCP port 22 to approved sources or use an authorized private access method.";
    }

    if (message.includes("rdp open")) {
        return "Restrict inbound TCP port 3389 to approved sources.";
    }

    if (message.includes("all traffic open")) {
        return "Review unrestricted security group rules and apply least-privilege network access.";
    }

    if (message.includes("ebs default encryption")) {
        return "Enable EBS encryption by default in the affected AWS region.";
    }

    if (message.includes("volume not encrypted")) {
        return "Plan a safe migration to an encrypted EBS volume.";
    }

    if (message.includes("multi-region")) {
        return "Review whether multi-region CloudTrail coverage is required.";
    }

    if (message.includes("log file validation")) {
        return "Review and enable CloudTrail log file validation where appropriate.";
    }

    if (message.includes("cloudtrail")) {
        return "Review CloudTrail logging coverage and configure or restore logging according to your audit requirements.";
    }

    if (message.includes("administrator")) {
        return "Review administrator permissions and apply the principle of least privilege.";
    }

    if (message.includes("encryption")) {
        return "Review encryption configuration and applicable data protection requirements.";
    }

    return "Review this finding in the AWS console and verify the appropriate security configuration.";
}

function renderRecommendations() {

    const container = $("recommendations");
    container.replaceChildren();

    const issues = findings.filter(
        f => f.status === "FAIL" ||
             f.status === "WARN"
    );

    if (!issues.length) {

        const note = document.createElement("p");

        note.textContent =
            "No failures or warnings recorded in the imported assessment.";

        container.appendChild(note);
        return;
    }

    issues.forEach(finding => {

        const card = document.createElement("article");

        card.className =
            "recommendation " +
            finding.status.toLowerCase();

        const badge = document.createElement("span");

        badge.className =
            "status " + finding.status.toLowerCase();

        badge.textContent = finding.status;

        const title = document.createElement("h3");
        title.textContent = finding.message;

        const resource = document.createElement("p");
        resource.textContent = finding.resource;

        const advice = document.createElement("p");
        advice.textContent = recommendationFor(finding);

        card.append(badge, title, resource, advice);
        container.appendChild(card);
    });
}

// =====================================
// INTERACTIVE AUDIT EXPLORER
// =====================================

function populateDomains() {

    const select = $("domain-filter");
    select.replaceChildren();

    const all = document.createElement("option");

    all.value = "ALL";
    all.textContent = "All domains";
    select.appendChild(all);

    const domains = [
        ...new Set(findings.map(f => f.domain))
    ].sort();

    domains.forEach(name => {

        const option = document.createElement("option");

        option.value = name;
        option.textContent = name;

        select.appendChild(option);
    });
}

function renderTable() {

    const query = $("search").value.toLowerCase();
    const status = $("status-filter").value;
    const domain = $("domain-filter").value;

    const filtered = findings.filter(item =>

        (status === "ALL" || item.status === status) &&

        (domain === "ALL" || item.domain === domain) &&

        Object.values(item)
            .join(" ")
            .toLowerCase()
            .includes(query)
    );

    const table = $("findings-table");
    table.replaceChildren();

    const fragment = document.createDocumentFragment();

    filtered.forEach(item => {

        const row = document.createElement("tr");

        [
            item.domain,
            item.resource,
            item.message
        ].forEach(value => {

            const cell = document.createElement("td");
            cell.textContent = value;
            row.appendChild(cell);
        });

        const cell = document.createElement("td");
        const badge = document.createElement("span");

        badge.className =
            "status " + item.status.toLowerCase();

        badge.textContent = item.status;

        cell.appendChild(badge);
        row.appendChild(cell);
        fragment.appendChild(row);
    });

    table.appendChild(fragment);

    $("result-count").textContent =
        `${filtered.length} of ${findings.length} findings`;
}

// =====================================
// DASHBOARD RENDERING
// =====================================

function renderDashboard(report) {

    const stats = calculateStats(findings);

    $("dashboard").hidden = false;

    $("score").textContent = stats.score === null
        ? "N/A"
        : stats.score.toFixed(2) + "%";

    $("assessment-summary").textContent =
        `${stats.PASS} of ${stats.total} evaluated checks passed`;

    $("report-region").textContent =
        "AWS Region: " + report.region;

    $("report-date").textContent =
        "Assessment: " +
        new Date(report.generated_at).toLocaleString();

    animateNumber("passed", stats.PASS);
    animateNumber("failed", stats.FAIL);
    animateNumber("warnings", stats.WARN);
    animateNumber("info", stats.INFO);

    $("search").value = "";
    $("status-filter").value = "ALL";

    populateDomains();
    renderDomains();
    renderRecommendations();
    renderTable();
}

// =====================================
// JSON FILE IMPORT
// =====================================

function showStatus(message, type) {

    $("import-status").textContent = message;
    $("import-status").className = type;
}

function clearDashboard() {

    findings = [];

    $("dashboard").hidden = true;

    [
        "domain-chart",
        "recommendations",
        "findings-table",
        "result-count",
        "assessment-summary",
        "report-region",
        "report-date"
    ].forEach(id => $(id).replaceChildren());

    $("score").textContent = "--";

    ["passed", "failed", "warnings", "info"]
        .forEach(id => {
            $(id).textContent = "00";
        });

    $("search").value = "";
    $("status-filter").value = "ALL";
    populateDomains();
}

async function importReport(file) {

    if (!file) return;

    const version = ++importVersion;

    clearDashboard();

    try {

        if (file.size > MAX_SIZE) {
            throw new Error(
                "File exceeds the 5 MB size limit."
            );
        }

        if (!file.name.toLowerCase().endsWith(".json")) {
            throw new Error("Please select a JSON file.");
        }

        showStatus("Validating report...", "");

        const content = await file.text();

        if (version !== importVersion) return;

        const report = JSON.parse(content);

        findings = validateReport(report);

        renderDashboard(report);

        showStatus(
            "Report imported successfully. " +
            "Processed locally in your browser.",
            "success"
        );

    } catch (error) {

        if (version !== importVersion) return;

        clearDashboard();

        showStatus(
            "Import failed: " + error.message,
            "error"
        );
    }
}

// =====================================
// EVENT HANDLERS
// =====================================

$("browse-btn").addEventListener("click", () => {
    $("file-input").click();
});

$("file-input").addEventListener("change", event => {

    const file = event.target.files[0];

    event.target.value = "";

    importReport(file);
});

const dropZone = $("drop-zone");

["dragenter", "dragover"].forEach(eventName => {

    dropZone.addEventListener(eventName, event => {

        event.preventDefault();

        dropZone.classList.add("dragover");
    });
});

["dragleave", "drop"].forEach(eventName => {

    dropZone.addEventListener(eventName, event => {

        event.preventDefault();

        dropZone.classList.remove("dragover");
    });
});

dropZone.addEventListener("drop", event => {

    if (event.dataTransfer.files.length !== 1) {

        showStatus(
            "Please import one JSON report at a time.",
            "error"
        );

        return;
    }

    importReport(event.dataTransfer.files[0]);
});

["search", "status-filter", "domain-filter"]
    .forEach(id => {

        $(id).addEventListener("input", renderTable);
    });

$("print-btn").addEventListener("click", () => {

    $("search").value = "";
    $("status-filter").value = "ALL";
    $("domain-filter").value = "ALL";

    renderTable();

    window.print();
});

$("reset-btn").addEventListener("click", () => {

    importVersion++;

    clearDashboard();

    $("file-input").value = "";

    showStatus("Report cleared.", "");
});
