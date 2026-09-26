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

/**
 * Normalizes backend responses from either /api/analysis/:id/report (nested)
 * or /api/analysis/:id (flat) or local cache into a unified report data model.
 */
function normalizeReportData(raw) {
    if (!raw || typeof raw !== "object") return null;

    const target = raw.target || {};
    const securitySummary = raw.securitySummary || {};
    const technicalDetails = raw.technicalDetails || {};

    const fileName = target.fileName || raw.fileName || "Unknown File";
    const fileSize = target.fileSize !== undefined ? target.fileSize : (raw.fileSize !== undefined ? raw.fileSize : 0);
    const fileType = target.fileType || raw.fileType || "Generic Binary";
    const signature = target.signature || raw.signature || "Unknown / Not Detected";
    const md5 = target.md5 || raw.md5 || "N/A";
    const sha256 = target.sha256 || raw.sha256 || "N/A";

    const risk = (securitySummary.risk || raw.risk || "LOW").toUpperCase();
    const entropy = securitySummary.entropy !== undefined ? securitySummary.entropy : (raw.entropy !== undefined ? raw.entropy : 0);
    const indicators = securitySummary.indicators || raw.indicators || [];

    const strings = technicalDetails.extractedStringsSample || raw.strings || [];
    const pe = technicalDetails.pe || raw.pe || {};

    const id = raw.reportId || raw.analysisId || raw.id || target.analysisId || "N/A";
    const timestamp = raw.generatedAt || raw.timestamp || new Date().toISOString();

    return {
        id,
        reportId: raw.reportId || id,
        analysisId: raw.analysisId || id,
        fileName,
        fileSize,
        fileType,
        signature,
        md5,
        sha256,
        risk,
        entropy,
        indicators,
        strings,
        pe,
        timestamp,
        disclaimer: raw.disclaimer || ""
    };
}

document.addEventListener("DOMContentLoaded", async () => {
    const urlParams = new URLSearchParams(window.location.search);
    const reportId = urlParams.get("id");

    const loadingEl = document.getElementById("report-loading");
    const contentEl = document.getElementById("report-content");
    const errorEl = document.getElementById("report-error");

    let rawData = null;

    if (reportId) {
        // Fetch via fixed API endpoint: GET /api/analysis/:id/report
        const res = await API.getAnalysisReport(reportId);
        if (res && res.success && res.data) {
            rawData = res.data;
        } else {
            // Try fetching basic analysis endpoint: GET /api/analysis/:id
            const basicRes = await API.getAnalysis(reportId);
            if (basicRes && basicRes.success && basicRes.data) {
                rawData = basicRes.data;
            }
        }
    }

    // If still null, check active session item
    if (!rawData) {
        rawData = API.getActiveSessionAnalysis();
    }

    // If still null, try first cached analysis
    if (!rawData) {
        const cached = API.getCachedAnalyses();
        if (cached.length > 0) {
            rawData = cached[0];
        }
    }

    // If still null, fetch latest analysis from backend API
    if (!rawData) {
        try {
            const allRes = await API.getAnalyses();
            if (allRes && allRes.success && Array.isArray(allRes.data) && allRes.data.length > 0) {
                rawData = allRes.data[0];
                if (rawData && rawData.analysisId) {
                    // Update URL silently so refresh keeps the file
                    const newUrl = `${window.location.pathname}?id=${encodeURIComponent(rawData.analysisId)}`;
                    window.history.replaceState({}, "", newUrl);
                }
            }
        } catch (e) {
            console.warn("Unable to fetch fallback analyses from API:", e);
        }
    }

    if (loadingEl) loadingEl.style.display = "none";

    const reportData = normalizeReportData(rawData);

    if (!reportData || (reportData.fileName === "Unknown File" && reportData.fileSize === 0 && reportData.id === "N/A")) {
        if (errorEl) {
            errorEl.style.display = "block";
            const titleEl = errorEl.querySelector("h2");
            const pEl = errorEl.querySelector("p");
            if (titleEl) titleEl.textContent = "No Report Selected";
            if (pEl) pEl.textContent = "You haven't selected a file report yet. Please choose a file from your Scan History or upload a new file to inspect it.";
        }
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
            riskVerdict.textContent = "High Risk — Dangerous indicators detected! We strongly advise that you do NOT open or run this file on your personal computer.";
        } else if (risk === "MEDIUM") {
            riskVerdict.textContent = "Medium Risk (Suspicious) — Unusual structures or code scrambling observed. Proceed with caution.";
        } else {
            riskVerdict.textContent = "Low Risk (Normal) — File appears clean and matches standard expected format.";
        }
    }
}

/**
 * Friendly translation for technical security indicators
 */
function getFriendlyIndicator(title, desc) {
    const t = (title || "").toLowerCase();
    if (t.includes("double extension") || t.includes("rlo")) {
        return {
            title: "Deceptive Double Extension (e.g. .pdf.exe)",
            desc: desc || "The file uses a sneaky double extension trick to hide that it is an executable program."
        };
    }
    if (t.includes("mismatch")) {
        return {
            title: "Disguised File Type (Fake Extension)",
            desc: desc || "The file extension does not match what is really inside the file."
        };
    }
    if (t.includes("high entropy") || t.includes("entropy")) {
        return {
            title: "Heavily Scrambled Code (High Entropy)",
            desc: desc || "Sections of this file are scrambled, encrypted, or compressed, which malware often uses to hide its true code."
        };
    }
    if (t.includes("powershell") || t.includes("command")) {
        return {
            title: "Suspicious System Commands",
            desc: desc || "Contains commands that attempt to run hidden scripts or modify system settings."
        };
    }
    if (t.includes("shadow copy") || t.includes("ransomware")) {
        return {
            title: "Backup Deletion Command (Ransomware Sign)",
            desc: desc || "Attempts to delete Windows shadow copies to prevent restoring files."
        };
    }
    if (t.includes("credential") || t.includes("dumping") || t.includes("mimikatz")) {
        return {
            title: "Password / Credential Stealing Marker",
            desc: desc || "References known password theft and memory scraping tools."
        };
    }
    if (t.includes("import")) {
        return {
            title: "Sensitive Operating System Functions",
            desc: desc || "The program requests deep Windows permissions often used by malware for memory injection or stealth."
        };
    }
    return { title: title || "Security Alert", desc: desc || "Flagged by static analysis safety checks." };
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
                <i class="fa-solid fa-triangle-exclamation" style="color: var(--risk-high); font-size: 1.35rem;"></i>
                <div>
                    <strong style="color: #fca5a5;">⚠️ Disguised File Warning (Fake Extension):</strong> 
                    This file is named with <code>.${escapeHtml(fileName.split(".").pop())}</code>, but inside it is actually a <strong>${escapeHtml(data.fileType || data.signature)}</strong>! 
                    Attackers often rename dangerous programs to look like harmless documents to trick people into opening them.
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
            descEl.innerHTML = `<strong style="color: var(--risk-high);">High Scrambling (${raw.toFixed(2)} / 8.0):</strong> The file data is heavily randomized. This commonly indicates packed code, encrypted payloads, or hidden malware trying to avoid detection.`;
        } else if (raw >= 5.5) {
            descEl.innerHTML = `<strong style="color: var(--risk-med);">Moderate Scrambling (${raw.toFixed(2)} / 8.0):</strong> Normal for compiled applications containing a mix of code and program resources.`;
        } else {
            descEl.innerHTML = `<strong style="color: var(--risk-low);">Low Scrambling (${raw.toFixed(2)} / 8.0):</strong> The file data is organized and readable, typical of plain text, standard documents, or uncompressed source files.`;
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
                No suspicious security indicators found. The file appears ordinary and clean.
            </div>
        `;
        return;
    }

    indicators.forEach(ind => {
        let rawTitle = typeof ind === "string" ? ind : (ind.title || ind.indicator || "Suspicious Flag");
        let rawDesc = ind.description || "Flagged by static analysis safety checks.";
        let sev = (ind.severity || "medium").toLowerCase();

        const friendly = getFriendlyIndicator(rawTitle, rawDesc);

        const item = document.createElement("div");
        item.className = `indicator-card ${sev}`;
        item.innerHTML = `
            <i class="fa-solid fa-triangle-exclamation indicator-icon"></i>
            <div>
                <div class="indicator-title">${escapeHtml(friendly.title)}</div>
                <div class="indicator-desc">${escapeHtml(friendly.desc)}</div>
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
    if (!pe || (typeof pe === "object" && Object.keys(pe).length === 0) || pe.isPE === false || pe.is_pe === false) {
        const msg = (pe && (pe.message || pe.status)) ? pe.message : "This file is not a Windows executable (.exe, .dll, .sys).";
        container.innerHTML = `
            <div class="pe-unavailable">
                <i class="fa-regular fa-file-code"></i>
                <p>${escapeHtml(msg)}</p>
                <small style="color: var(--text-muted);">Windows executable (PE) analysis only applies to valid, complete Windows executable binaries.</small>
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
