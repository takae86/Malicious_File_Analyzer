/**
 * MALICIOUS FILE ANALYZER — RESULTS & DASHBOARD CONTROLLER
 * Role: Member 3 (Frontend & Results Dashboard)
 * 
 * Handles results rendering, risk badge visualization, metric calculations,
 * copy-to-clipboard micro-interactions, and filterable recent analyses tables.
 */

document.addEventListener("DOMContentLoaded", async () => {
    // Determine page context (results.html vs index.html)
    const isDashboard = document.getElementById("recent-analyses-body") !== null;
    const isResultsPage = document.getElementById("results-hero-section") !== null;

    // Load data from backend API (with fallback to local storage cache)
    const response = await API.getAnalyses();
    let analyses = (response && response.success && Array.isArray(response.data)) ? response.data : [];

    // Check if a specific analysis was requested via URL query param
    const urlParams = new URLSearchParams(window.location.search);
    const targetId = urlParams.get("id");

    let activeAnalysis = null;
    if (targetId) {
        // Fetch specific analysis from API
        const singleRes = await API.getAnalysis(targetId);
        if (singleRes && singleRes.success && singleRes.data) {
            activeAnalysis = singleRes.data;
        }
    }

    if (!activeAnalysis) {
        // Check active session item or pick first item in list
        activeAnalysis = API.getActiveSessionAnalysis() || (analyses.length > 0 ? analyses[0] : null);
    }

    // 1. Update Metrics Cards (both index.html and results.html)
    updateMetricCards(analyses);

    // 2. Render Results Page Hero & Details if on results.html
    if (isResultsPage) {
        renderResultsHeroAndPanels(activeAnalysis);
        setupFilterListeners(analyses);
        renderAnalysesTable("all-results-body", analyses);
    }

    // 3. Render Dashboard Table if on index.html
    if (isDashboard) {
        renderAnalysesTable("recent-analyses-body", analyses.slice(0, 10));
    }

    // Global copy to clipboard listener
    setupClipboardButtons();
});

/**
 * Animates numeric value with a smooth ease-out count-up
 */
function animateCounter(el, target, duration = 600) {
    if (!el) return;
    const finalVal = parseInt(target, 10) || 0;
    if (finalVal === 0) {
        el.textContent = "0";
        return;
    }
    const startTime = performance.now();
    function step(now) {
        const elapsed = now - startTime;
        const progress = Math.min(elapsed / duration, 1);
        const easeOut = 1 - Math.pow(1 - progress, 3);
        const current = Math.floor(finalVal * easeOut);
        el.textContent = current;
        if (progress < 1) {
            requestAnimationFrame(step);
        } else {
            el.textContent = finalVal;
        }
    }
    requestAnimationFrame(step);
}

/**
 * Updates summary metric counters with smooth animated count-up
 */
function updateMetricCards(analyses) {
    const totalEl = document.querySelector("#card-total .card-value") || document.querySelector(".summary-cards .card:nth-child(1) .card-value");
    const highEl = document.querySelector("#card-high .card-value") || document.querySelector(".summary-cards .card:nth-child(2) .card-value");
    const medEl = document.querySelector("#card-med .card-value") || document.querySelector(".summary-cards .card:nth-child(3) .card-value");
    const lowEl = document.querySelector("#card-low .card-value") || document.querySelector(".summary-cards .card:nth-child(4) .card-value");

    let highCount = 0;
    let medCount = 0;
    let lowCount = 0;

    analyses.forEach(item => {
        const risk = (item.risk || "").toUpperCase();
        if (risk === "HIGH") highCount++;
        else if (risk === "MEDIUM") medCount++;
        else if (risk === "LOW") lowCount++;
    });

    if (totalEl) animateCounter(totalEl, analyses.length);
    if (highEl) animateCounter(highEl, highCount);
    if (medEl) animateCounter(medEl, medCount);
    if (lowEl) animateCounter(lowEl, lowCount);
}

/**
 * Renders the top Hero Risk Card and Technical Panels on results.html
 */
function renderResultsHeroAndPanels(data) {
    const heroSection = document.getElementById("results-hero-section");
    const emptyState = document.getElementById("results-empty-state");
    const detailsSection = document.getElementById("results-details-section");

    if (!data) {
        if (heroSection) heroSection.style.display = "none";
        if (detailsSection) detailsSection.style.display = "none";
        if (emptyState) emptyState.style.display = "block";
        return;
    }

    if (emptyState) emptyState.style.display = "none";
    if (heroSection) heroSection.style.display = "block";
    if (detailsSection) detailsSection.style.display = "block";

    const risk = (data.risk || "LOW").toUpperCase();
    const riskBadge = document.getElementById("res-risk-badge");
    const riskText = document.getElementById("res-risk-text");
    const riskSummary = document.getElementById("res-risk-summary");
    const filenameEl = document.getElementById("res-filename");
    const analysisIdEl = document.getElementById("res-analysis-id");
    const viewReportBtn = document.getElementById("res-view-report-btn");

    if (filenameEl) filenameEl.textContent = data.fileName || "Unknown File";
    if (analysisIdEl) analysisIdEl.textContent = data.id || data.analysisId || "N/A";

    if (viewReportBtn) {
        const id = data.id || data.analysisId || "";
        viewReportBtn.href = `report.html?id=${encodeURIComponent(id)}`;
    }

    // Set Risk Badge Color and Explanatory text
    if (riskBadge) {
        riskBadge.className = `risk-score-badge ${risk.toLowerCase()}`;
    }
    if (riskText) {
        riskText.textContent = risk;
    }
    if (riskSummary) {
        if (risk === "HIGH") {
            riskSummary.textContent = "Multiple suspicious heuristic indicators and anomalous patterns detected.";
        } else if (risk === "MEDIUM") {
            riskSummary.textContent = "Potential anomalies or unpacker-like entropy characteristics observed.";
        } else {
            riskSummary.textContent = "Standard static characteristics observed. No elevated heuristic flags.";
        }
    }

    // Populate Overview Cards
    const typeEl = document.getElementById("res-filetype");
    const sizeEl = document.getElementById("res-filesize");
    const sigEl = document.getElementById("res-signature");
    const entropyEl = document.getElementById("res-entropy");

    if (typeEl) typeEl.textContent = data.fileType || "Generic Binary";
    if (sizeEl) sizeEl.textContent = formatBytes(data.fileSize);
    if (sigEl) sigEl.textContent = data.signature || "Unknown";
    
    // Entropy visualization
    const rawEntropy = typeof data.entropy === "number" ? data.entropy : parseFloat(data.entropy) || 0;
    if (entropyEl) entropyEl.textContent = `${rawEntropy.toFixed(2)} / 8.00`;
    
    const entropyFill = document.getElementById("res-entropy-fill");
    if (entropyFill) {
        // Percentage of 8.0
        const pct = Math.min(100, Math.max(0, (rawEntropy / 8.0) * 100));
        entropyFill.style.width = `${pct}%`;
    }

    // Hashes
    const md5El = document.getElementById("res-md5");
    const sha256El = document.getElementById("res-sha256");
    if (md5El) md5El.textContent = data.md5 || "N/A";
    if (sha256El) sha256El.textContent = data.sha256 || "N/A";

    // Indicators List
    renderIndicatorsList(data.indicators);

    // PE Analysis Box
    renderPEPreview(data.pe);
}

/**
 * Renders the heuristic indicators list
 */
function renderIndicatorsList(indicators) {
    const listEl = document.getElementById("res-indicators-list");
    if (!listEl) return;

    listEl.innerHTML = "";

    if (!indicators || !Array.isArray(indicators) || indicators.length === 0) {
        listEl.innerHTML = `
            <div style="color: var(--text-muted); font-size: 0.85rem; padding: 0.5rem 0;">
                <i class="fa-solid fa-circle-check" style="color: var(--risk-low); margin-right: 0.5rem;"></i>
                No suspicious heuristic indicators triggered.
            </div>
        `;
        return;
    }

    indicators.forEach(ind => {
        let title = typeof ind === "string" ? ind : (ind.title || ind.indicator || "Suspicious Flag");
        let desc = ind.description || "";
        let sev = (ind.severity || "medium").toLowerCase();

        const card = document.createElement("div");
        card.className = `indicator-card ${sev}`;
        card.innerHTML = `
            <i class="fa-solid fa-triangle-exclamation indicator-icon"></i>
            <div>
                <div class="indicator-title">${escapeHtml(title)}</div>
                ${desc ? `<div class="indicator-desc">${escapeHtml(desc)}</div>` : ""}
            </div>
        `;
        listEl.appendChild(card);
    });
}

/**
 * Renders PE preview section
 */
function renderPEPreview(pe) {
    const peContainer = document.getElementById("res-pe-container");
    if (!peContainer) return;

    if (!pe || (typeof pe === "object" && Object.keys(pe).length === 0)) {
        peContainer.innerHTML = `
            <div class="pe-unavailable">
                <i class="fa-regular fa-file-code"></i>
                <p>PE analysis is not available for this file type.</p>
            </div>
        `;
        return;
    }

    // Format PE Information
    const entryPoint = pe.entryPoint || pe.entry_point || "N/A";
    const machine = pe.machine || "x86 / x64";
    const sectionCount = pe.sections ? (Array.isArray(pe.sections) ? pe.sections.length : Object.keys(pe.sections).length) : "0";

    peContainer.innerHTML = `
        <div class="pe-grid">
            <div class="pe-stat-card">
                <div class="pe-stat-label">Entry Point</div>
                <div class="pe-stat-val">${escapeHtml(entryPoint)}</div>
            </div>
            <div class="pe-stat-card">
                <div class="pe-stat-label">Machine Architecture</div>
                <div class="pe-stat-val">${escapeHtml(machine)}</div>
            </div>
            <div class="pe-stat-card">
                <div class="pe-stat-label">Sections Detected</div>
                <div class="pe-stat-val">${sectionCount}</div>
            </div>
        </div>
    `;
}

/**
 * Renders the analyses table (used on Dashboard and Results page)
 */
function renderAnalysesTable(tableBodyId, dataList) {
    const tbody = document.getElementById(tableBodyId);
    if (!tbody) return;

    tbody.innerHTML = "";

    if (!dataList || dataList.length === 0) {
        tbody.innerHTML = `
            <tr class="empty-state">
                <td colspan="6">
                    <i class="fa-regular fa-folder-open"></i>
                    No analysis results yet. Upload a file to begin static analysis.
                </td>
            </tr>
        `;
        return;
    }

    dataList.forEach(item => {
        const tr = document.createElement("tr");
        const risk = (item.risk || "LOW").toUpperCase();
        const id = item.id || item.analysisId || "";
        const entropyVal = typeof item.entropy === "number" ? item.entropy.toFixed(2) : (parseFloat(item.entropy) || 0).toFixed(2);

        let riskClass = "badge-risk-low";
        if (risk === "HIGH") riskClass = "badge-risk-high";
        else if (risk === "MEDIUM") riskClass = "badge-risk-medium";

        tr.innerHTML = `
            <td>
                <div class="file-cell">
                    <i class="fa-regular fa-file"></i>
                    <span title="${escapeHtml(item.fileName)}">${escapeHtml(item.fileName)}</span>
                </div>
            </td>
            <td>${escapeHtml(item.fileType || "Binary")}</td>
            <td class="entropy-mono">${entropyVal}</td>
            <td>
                <span class="badge-risk ${riskClass}">
                    ${risk}
                </span>
            </td>
            <td>
                <span style="font-size: 0.8rem; color: var(--text-secondary); display: flex; align-items: center; gap: 0.4rem;">
                    <i class="fa-solid fa-circle-check" style="color: var(--risk-low); font-size: 0.65rem;"></i> Completed
                </span>
            </td>
            <td>
                <a href="report.html?id=${encodeURIComponent(id)}" class="btn btn-secondary btn-sm">
                    <i class="fa-solid fa-arrow-up-right-from-square"></i> View Report
                </a>
            </td>
        `;
        tbody.appendChild(tr);
    });
}

/**
 * Filter and Search listeners for results.html
 */
function setupFilterListeners(allAnalyses) {
    const filterBtns = document.querySelectorAll(".filter-btn");
    const searchInput = document.getElementById("search-results-input");

    let currentFilter = "all";
    let searchTerm = "";

    function applyFilterAndSearch() {
        let filtered = allAnalyses.filter(item => {
            const risk = (item.risk || "").toUpperCase();
            const matchesFilter = currentFilter === "all" || risk === currentFilter.toUpperCase();
            
            const name = (item.fileName || "").toLowerCase();
            const type = (item.fileType || "").toLowerCase();
            const matchesSearch = !searchTerm || name.includes(searchTerm) || type.includes(searchTerm);

            return matchesFilter && matchesSearch;
        });

        renderAnalysesTable("all-results-body", filtered);
    }

    filterBtns.forEach(btn => {
        btn.addEventListener("click", () => {
            filterBtns.forEach(b => b.classList.remove("active"));
            btn.classList.add("active");
            currentFilter = btn.dataset.filter || "all";
            applyFilterAndSearch();
        });
    });

    if (searchInput) {
        searchInput.addEventListener("input", (e) => {
            searchTerm = e.target.value.trim().toLowerCase();
            applyFilterAndSearch();
        });
    }
}

/**
 * Clipboard button interaction handler
 */
function setupClipboardButtons() {
    document.addEventListener("click", async (e) => {
        const copyBtn = e.target.closest(".btn-copy");
        if (!copyBtn) return;

        const targetId = copyBtn.dataset.copyTarget;
        const textToCopy = copyBtn.dataset.copyText || (targetId ? document.getElementById(targetId)?.textContent : "");

        if (!textToCopy) return;

        try {
            await navigator.clipboard.writeText(textToCopy.trim());
            const origHtml = copyBtn.innerHTML;
            copyBtn.innerHTML = `<i class="fa-solid fa-check"></i> Copied!`;
            copyBtn.classList.add("btn-primary");
            copyBtn.classList.remove("btn-secondary");

            setTimeout(() => {
                copyBtn.innerHTML = origHtml;
                copyBtn.classList.remove("btn-primary");
                copyBtn.classList.add("btn-secondary");
            }, 1800);

            showToast("Copied to Clipboard", "Hash copied successfully.", "info", 2000);
        } catch (err) {
            console.error("Clipboard copy failed:", err);
            showToast("Copy Failed", "Please manually highlight and copy.", "error");
        }
    });
}
