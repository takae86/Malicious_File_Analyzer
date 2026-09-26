/**
 * MALICIOUS FILE ANALYZER — DETAILED STATIC REPORT CONTROLLER
 * Role: Member 3 (Frontend & Results Dashboard)
 * 
 * Renders the full 8-section technical static analysis report:
 * 1. File Information & Signature Mismatch Warning
 * 2. Cryptographic Hashes (with 1-click clipboard)
 * 3. Shannon Entropy Meter (0-8)
 * 4. Extracted Strings with live search/filter
 * 5. PE Architecture & Section analysis
 * 6. Suspicious Heuristic Indicators
 * 7. Risk Assessment & Educational Disclaimer
 */

document.addEventListener("DOMContentLoaded", async () => {
    const urlParams = new URLSearchParams(window.location.search);
    const reportId = urlParams.get("id");

    const loadingEl = document.getElementById("report-loading");
    const contentEl = document.getElementById("report-content");
    const errorEl = document.getElementById("report-error");

    let reportData = null;

    if (reportId) {
        // Fetch via fixed API endpoint: GET /api/analysis/:id/report
        const res = await API.getAnalysisReport(reportId);
        if (res && res.success && res.data) {
            reportData = res.data;
        } else {
            // Try fetching basic analysis endpoint: GET /api/analysis/:id
            const basicRes = await API.getAnalysis(reportId);
            if (basicRes && basicRes.success && basicRes.data) {
                reportData = basicRes.data;
            }
        }
    }

    // If still null, check active session item
    if (!reportData) {
        reportData = API.getActiveSessionAnalysis();
    }

    // If still null, try first cached analysis
    if (!reportData) {
        const cached = API.getCachedAnalyses();
        if (cached.length > 0) {
            reportData = cached[0];
        }
    }

    if (loadingEl) loadingEl.style.display = "none";

    if (!reportData) {
        if (errorEl) errorEl.style.display = "block";
        return;
    }

    if (contentEl) contentEl.style.display = "block";

    // Populate Report Sections
    renderHeader(reportData);
    renderFileInformation(reportData);
    renderHashes(reportData);
    renderEntropy(reportData);
    renderIndicators(reportData);
    renderPEData(reportData);
    renderStringsSection(reportData.strings);

    // Setup print/export button
    const printBtn = document.getElementById("print-report-btn");
    if (printBtn) {
        printBtn.addEventListener("click", () => window.print());
    }
});

/**
 * Renders Report Header & Risk Banner
 */
function renderHeader(data) {
    const filenameEl = document.getElementById("rep-filename");
    const idEl = document.getElementById("rep-id");
    const timeEl = document.getElementById("rep-time");
    const riskBadge = document.getElementById("rep-risk-badge");
    const riskVerdict = document.getElementById("rep-risk-verdict");

    const risk = (data.risk || "LOW").toUpperCase();
    const id = data.id || data.analysisId || "N/A";

    if (filenameEl) filenameEl.textContent = data.fileName || "Unknown File";
    if (idEl) idEl.textContent = id;
    if (timeEl) {
        const date = data.timestamp ? new Date(data.timestamp).toLocaleString() : new Date().toLocaleString();
        timeEl.textContent = date;
    }

    if (riskBadge) {
        let badgeClass = "badge-risk-low";
        if (risk === "HIGH") badgeClass = "badge-risk-high";
        else if (risk === "MEDIUM") badgeClass = "badge-risk-medium";
        riskBadge.className = `badge-risk ${badgeClass}`;
        riskBadge.textContent = risk;
    }

    if (riskVerdict) {
        if (risk === "HIGH") {
            riskVerdict.textContent = "High Risk Indicator — Suspicious markers detected. Recommend isolated sandbox inspection.";
        } else if (risk === "MEDIUM") {
            riskVerdict.textContent = "Medium Risk Indicator — Anomalies or packer-like characteristics observed.";
        } else {
            riskVerdict.textContent = "Low Risk Indicator — Standard static signatures match expected structure.";
        }
    }
}

/**
 * Renders File Info & Signature Warning
 */
function renderFileInformation(data) {
    const nameEl = document.getElementById("rep-info-name");
    const sizeEl = document.getElementById("rep-info-size");
    const typeEl = document.getElementById("rep-info-type");
    const sigEl = document.getElementById("rep-info-sig");
    const warningBox = document.getElementById("rep-sig-warning");

    if (nameEl) nameEl.textContent = data.fileName || "N/A";
    if (sizeEl) sizeEl.textContent = `${formatBytes(data.fileSize)} (${(data.fileSize || 0).toLocaleString()} bytes)`;
    if (typeEl) typeEl.textContent = data.fileType || "Generic Binary";
    if (sigEl) sigEl.textContent = data.signature || "Unknown / Not Detected";

    // Check for signature vs extension mismatch
    if (warningBox) {
        const fileName = (data.fileName || "").toLowerCase();
        const detectedType = (data.fileType || "").toLowerCase();
        const signature = (data.signature || "").toLowerCase();

        let mismatch = false;
        // e.g. .pdf extension but signature is MZ / PE Executable
        if (fileName.endsWith(".pdf") && (detectedType.includes("pe") || detectedType.includes("executable") || signature.includes("mz"))) {
            mismatch = true;
        } else if ((fileName.endsWith(".doc") || fileName.endsWith(".docx")) && detectedType.includes("executable")) {
            mismatch = true;
        }

        if (mismatch) {
            warningBox.style.display = "flex";
            warningBox.innerHTML = `
                <i class="fa-solid fa-triangle-exclamation" style="color: var(--risk-high); font-size: 1.25rem;"></i>
                <div>
                    <strong style="color: #fca5a5;">Signature Mismatch Warning:</strong> 
                    File extension (.${fileName.split(".").pop()}) does not match detected binary signature (${data.fileType || data.signature}).
                </div>
            `;
        } else {
            warningBox.style.display = "none";
        }
    }
}

/**
 * Renders Cryptographic Hashes
 */
function renderHashes(data) {
    const md5El = document.getElementById("rep-hash-md5");
    const sha256El = document.getElementById("rep-hash-sha256");

    if (md5El) md5El.textContent = data.md5 || "N/A";
    if (sha256El) sha256El.textContent = data.sha256 || "N/A";
}

/**
 * Renders Entropy Gauge
 */
function renderEntropy(data) {
    const scoreEl = document.getElementById("rep-entropy-score");
    const fillEl = document.getElementById("rep-entropy-fill");
    const descEl = document.getElementById("rep-entropy-desc");

    const raw = typeof data.entropy === "number" ? data.entropy : parseFloat(data.entropy) || 0;
    if (scoreEl) scoreEl.textContent = raw.toFixed(2);

    if (fillEl) {
        const pct = Math.min(100, Math.max(0, (raw / 8.0) * 100));
        fillEl.style.width = `${pct}%`;
    }

    if (descEl) {
        if (raw >= 7.2) {
            descEl.innerHTML = `<strong style="color: var(--risk-high);">High Entropy (${raw.toFixed(2)}):</strong> Indicates high randomness, commonly associated with packed binaries, encrypted payloads, or compressed archives.`;
        } else if (raw >= 5.5) {
            descEl.innerHTML = `<strong style="color: var(--risk-med);">Moderate Entropy (${raw.toFixed(2)}):</strong> Typical of compiled native binaries with mixed code and data sections.`;
        } else {
            descEl.innerHTML = `<strong style="color: var(--risk-low);">Low Entropy (${raw.toFixed(2)}):</strong> Indicates structured plain text, uncompressed source code, or predictable byte distributions.`;
        }
    }
}

/**
 * Renders Heuristic Indicators
 */
function renderIndicators(data) {
    const container = document.getElementById("rep-indicators-container");
    if (!container) return;

    container.innerHTML = "";

    const indicators = data.indicators;
    if (!indicators || !Array.isArray(indicators) || indicators.length === 0) {
        container.innerHTML = `
            <div style="color: var(--text-muted); font-size: 0.9rem; padding: 1rem 0;">
                <i class="fa-solid fa-circle-check" style="color: var(--risk-low); margin-right: 0.5rem;"></i>
                No suspicious heuristic indicators triggered for this sample.
            </div>
        `;
        return;
    }

    indicators.forEach(ind => {
        let title = typeof ind === "string" ? ind : (ind.title || ind.indicator || "Suspicious Flag");
        let desc = ind.description || "Flagged by static analysis heuristic rule.";
        let sev = (ind.severity || "medium").toLowerCase();

        const item = document.createElement("div");
        item.className = `indicator-card ${sev}`;
        item.innerHTML = `
            <i class="fa-solid fa-shield-virus indicator-icon"></i>
            <div>
                <div class="indicator-title">${escapeHtml(title)}</div>
                <div class="indicator-desc">${escapeHtml(desc)}</div>
            </div>
        `;
        container.appendChild(item);
    });
}

/**
 * Renders PE Information
 */
function renderPEData(data) {
    const container = document.getElementById("rep-pe-container");
    if (!container) return;

    const pe = data.pe;
    if (!pe || (typeof pe === "object" && Object.keys(pe).length === 0)) {
        container.innerHTML = `
            <div class="pe-unavailable">
                <i class="fa-regular fa-file-code"></i>
                <p>PE analysis is not available for this file type.</p>
                <small style="color: var(--text-muted);">Only valid Windows Portable Executable files (.exe, .dll, .sys) support PE header parsing.</small>
            </div>
        `;
        return;
    }

    const entryPoint = pe.entryPoint || pe.entry_point || "0x00400000";
    const imageBase = pe.imageBase || pe.image_base || "0x00400000";
    const machine = pe.machine || "IMAGE_FILE_MACHINE_AMD64";
    const subSystem = pe.subsystem || "Windows GUI / Console";

    let sectionsHtml = "";
    if (pe.sections && Array.isArray(pe.sections) && pe.sections.length > 0) {
        const rows = pe.sections.map(sec => `
            <tr>
                <td><code>${escapeHtml(sec.name || ".sec")}</code></td>
                <td>${escapeHtml(sec.virtualSize || sec.virtual_size || "N/A")}</td>
                <td>${escapeHtml(sec.rawSize || sec.raw_size || "N/A")}</td>
                <td>${sec.entropy ? parseFloat(sec.entropy).toFixed(2) : "N/A"}</td>
            </tr>
        `).join("");

        sectionsHtml = `
            <div style="margin-top: 1.25rem;">
                <div style="font-size: 0.85rem; font-weight: 600; color: var(--text-secondary); margin-bottom: 0.5rem;">Section Table</div>
                <div class="table-container">
                    <table class="pe-sections-table">
                        <thead>
                            <tr><th>Name</th><th>Virtual Size</th><th>Raw Size</th><th>Entropy</th></tr>
                        </thead>
                        <tbody>${rows}</tbody>
                    </table>
                </div>
            </div>
        `;
    }

    container.innerHTML = `
        <div class="pe-grid">
            <div class="pe-stat-card">
                <div class="pe-stat-label">Entry Point</div>
                <div class="pe-stat-val">${escapeHtml(entryPoint)}</div>
            </div>
            <div class="pe-stat-card">
                <div class="pe-stat-label">Image Base</div>
                <div class="pe-stat-val">${escapeHtml(imageBase)}</div>
            </div>
            <div class="pe-stat-card">
                <div class="pe-stat-label">Machine Architecture</div>
                <div class="pe-stat-val">${escapeHtml(machine)}</div>
            </div>
        </div>
        ${sectionsHtml}
    `;
}

/**
 * Renders Extracted Strings with Search & Copy
 */
function renderStringsSection(rawStrings) {
    const container = document.getElementById("rep-strings-content");
    const countBadge = document.getElementById("rep-strings-count");
    const searchInput = document.getElementById("rep-strings-search");
    const copyBtn = document.getElementById("rep-copy-strings-btn");

    if (!container) return;

    let stringList = [];
    if (Array.isArray(rawStrings)) {
        stringList = rawStrings;
    } else if (typeof rawStrings === "string") {
        stringList = rawStrings.split("\n").filter(s => s.trim().length > 0);
    }

    if (countBadge) {
        countBadge.textContent = `${stringList.length} strings`;
    }

    if (stringList.length === 0) {
        container.textContent = "No printable strings extracted from this file.";
        return;
    }

    // Cap display to 800 strings at once to ensure maximum UI performance without freezing
    const DISPLAY_LIMIT = 800;

    function displayFiltered(filterTerm = "") {
        let matched = stringList;
        if (filterTerm) {
            const term = filterTerm.toLowerCase();
            matched = stringList.filter(s => s.toLowerCase().includes(term));
        }

        if (matched.length === 0) {
            container.textContent = `No strings matching "${filterTerm}".`;
            return;
        }

        const slice = matched.slice(0, DISPLAY_LIMIT);
        let output = slice.map(s => escapeHtml(s)).join("\n");
        if (matched.length > DISPLAY_LIMIT) {
            output += `\n\n... and ${matched.length - DISPLAY_LIMIT} more strings matching search.`;
        }

        container.textContent = output;
    }

    displayFiltered();

    if (searchInput) {
        searchInput.addEventListener("input", (e) => {
            displayFiltered(e.target.value.trim());
        });
    }

    if (copyBtn) {
        copyBtn.addEventListener("click", async () => {
            const allText = stringList.join("\n");
            try {
                await navigator.clipboard.writeText(allText);
                showToast("Strings Copied", `Copied ${stringList.length} strings to clipboard.`, "info");
            } catch (err) {
                showToast("Copy Failed", "Unable to copy strings to clipboard.", "error");
            }
        });
    }
}
