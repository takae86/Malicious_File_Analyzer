/**
 * MALICIOUS FILE ANALYZER — API CLIENT & CENTRALIZED NETWORK MODULE
 * Role: Member 3 (Frontend & API Integration)
 * 
 * IMPORTANT:
 * The backend base URL must ONLY exist in this file.
 * All API interactions, response parsing, and error normalization happen here.
 */

// The single source of truth for the API base URL
const API_BASE_URL = "http://localhost:5000/api";

/**
 * Global API Client object
 */
const API = {
    baseUrl: API_BASE_URL,

    /**
     * Checks if the backend analysis engine is online
     * Endpoint: GET /api/health
     * @returns {Promise<{success: boolean, message?: string, data?: any}>}
     */
    async checkHealth() {
        try {
            const response = await fetch(`${API_BASE_URL}/health`, {
                method: "GET",
                headers: { "Accept": "application/json" }
            });
            const data = await response.json();
            return data;
        } catch (error) {
            console.warn("[API] Health check failed:", error.message);
            return {
                success: false,
                message: "Analysis engine is currently offline or unreachable"
            };
        }
    },

    /**
     * Uploads and initiates static file analysis for one or multiple files
     * Endpoint: POST /api/analyze
     * @param {File[]|FileList|File} files 
     * @returns {Promise<{success: boolean, message: string, data?: any}>}
     */
    async analyzeFiles(files) {
        try {
            const formData = new FormData();
            
            if (files instanceof FileList || Array.isArray(files)) {
                for (let i = 0; i < files.length; i++) {
                    formData.append("files", files[i]);
                }
            } else if (files instanceof File) {
                formData.append("files", files);
            } else {
                throw new Error("Invalid file argument passed to analyzeFiles");
            }

            const response = await fetch(`${API_BASE_URL}/analyze`, {
                method: "POST",
                body: formData
            });

            const result = await response.json();
            
            // If the analysis was successful, save to local cache for session persistence
            if (result.success && result.data) {
                API.cacheAnalysis(result.data);
            }

            return result;
        } catch (error) {
            console.error("[API] analyzeFiles error:", error);
            return {
                success: false,
                message: error.message || "Unable to analyze file. Please verify backend connection."
            };
        }
    },

    /**
     * Fetches a specific analysis result by its ID
     * Endpoint: GET /api/analysis/:id
     * @param {string|number} id
     * @returns {Promise<{success: boolean, message: string, data?: any}>}
     */
    async getAnalysis(id) {
        try {
            const response = await fetch(`${API_BASE_URL}/analysis/${encodeURIComponent(id)}`, {
                method: "GET",
                headers: { "Accept": "application/json" }
            });
            const result = await response.json();
            return result;
        } catch (error) {
            console.warn(`[API] getAnalysis(${id}) network error:`, error.message);
            
            // Fallback check in local session cache
            const cached = API.getCachedAnalysisById(id);
            if (cached) {
                return {
                    success: true,
                    message: "Loaded analysis from session storage",
                    data: cached
                };
            }

            return {
                success: false,
                message: "Unable to retrieve analysis details."
            };
        }
    },

    /**
     * Fetches all recent analyses
     * Endpoint: GET /api/analyses
     * @returns {Promise<{success: boolean, message: string, data?: any[]}>}
     */
    async getAnalyses() {
        try {
            const response = await fetch(`${API_BASE_URL}/analyses`, {
                method: "GET",
                headers: { "Accept": "application/json" }
            });
            const result = await response.json();

            // If API responded with valid data array, update local cache
            if (result.success && Array.isArray(result.data)) {
                localStorage.setItem("mfa_cached_analyses", JSON.stringify(result.data));
                return result;
            }
            throw new Error("Invalid response structure from /analyses");
        } catch (error) {
            console.warn("[API] getAnalyses network error:", error.message);
            
            // Check local fallback cache
            const cachedList = API.getCachedAnalyses();
            return {
                success: cachedList.length > 0,
                message: cachedList.length > 0 ? "Loaded from local cache" : "No analysis records available.",
                data: cachedList
            };
        }
    },

    /**
     * Fetches the detailed static report for an analysis ID
     * Endpoint: GET /api/analysis/:id/report
     * @param {string|number} id
     * @returns {Promise<{success: boolean, message: string, data?: any}>}
     */
    async getAnalysisReport(id) {
        try {
            const response = await fetch(`${API_BASE_URL}/analysis/${encodeURIComponent(id)}/report`, {
                method: "GET",
                headers: { "Accept": "application/json" }
            });
            const result = await response.json();
            return result;
        } catch (error) {
            console.warn(`[API] getAnalysisReport(${id}) network error:`, error.message);

            // Fallback to cached item
            const cached = API.getCachedAnalysisById(id);
            if (cached) {
                return {
                    success: true,
                    message: "Loaded report from cache",
                    data: cached
                };
            }

            return {
                success: false,
                message: "Unable to load static analysis report."
            };
        }
    },

    /* ----------------------------------------------------------------------
       Local Session Cache Helpers (Smooth UX during page transitions)
       ---------------------------------------------------------------------- */
    cacheAnalysis(data) {
        try {
            const existing = API.getCachedAnalyses();
            const items = Array.isArray(data) ? data : [data];
            
            items.forEach(item => {
                const id = item.id || item.analysisId || `analysis_${Date.now()}_${Math.random().toString(36).substr(2, 5)}`;
                item.id = id;
                // Add timestamp if not present
                if (!item.timestamp) {
                    item.timestamp = new Date().toISOString();
                }
                const existingIndex = existing.findIndex(e => (e.id === id || e.fileName === item.fileName));
                if (existingIndex >= 0) {
                    existing[existingIndex] = item;
                } else {
                    existing.unshift(item);
                }
            });

            // Store max 50 items
            const trimmed = existing.slice(0, 50);
            localStorage.setItem("mfa_cached_analyses", JSON.stringify(trimmed));
            // Keep latest active in sessionStorage for instant result view
            sessionStorage.setItem("mfa_active_analysis", JSON.stringify(items[0]));
        } catch (e) {
            console.error("Cache storage error:", e);
        }
    },

    getCachedAnalyses() {
        try {
            const raw = localStorage.getItem("mfa_cached_analyses");
            return raw ? JSON.parse(raw) : [];
        } catch {
            return [];
        }
    },

    getCachedAnalysisById(id) {
        const list = API.getCachedAnalyses();
        return list.find(item => item.id == id || item.analysisId == id) || null;
    },

    getActiveSessionAnalysis() {
        try {
            const raw = sessionStorage.getItem("mfa_active_analysis");
            return raw ? JSON.parse(raw) : null;
        } catch {
            return null;
        }
    }
};

/**
 * Toast Notification Utility
 */
function showToast(title, message, type = "info", duration = 4000) {
    let container = document.getElementById("toast-container");
    if (!container) {
        container = document.createElement("div");
        container.id = "toast-container";
        container.className = "toast-container";
        document.body.appendChild(container);
    }

    const toast = document.createElement("div");
    toast.className = `toast toast-${type}`;
    
    let iconClass = "fa-circle-info";
    if (type === "success") iconClass = "fa-circle-check";
    if (type === "error") iconClass = "fa-triangle-exclamation";

    toast.innerHTML = `
        <i class="fas ${iconClass}"></i>
        <div class="toast-body">
            <div class="toast-title">${escapeHtml(title)}</div>
            <div class="toast-message">${escapeHtml(message)}</div>
        </div>
        <button class="toast-close" aria-label="Close notification">&times;</button>
    `;

    const closeBtn = toast.querySelector(".toast-close");
    closeBtn.addEventListener("click", () => {
        toast.style.opacity = "0";
        setTimeout(() => toast.remove(), 200);
    });

    container.appendChild(toast);

    setTimeout(() => {
        if (toast.parentElement) {
            toast.style.opacity = "0";
            setTimeout(() => toast.remove(), 250);
        }
    }, duration);
}

/**
 * Helper to escape HTML characters
 */
function escapeHtml(str) {
    if (!str) return "";
    return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

/**
 * Formats byte size into human readable string
 */
function formatBytes(bytes, decimals = 2) {
    if (!bytes || bytes === 0) return "0 Bytes";
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ["Bytes", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + " " + sizes[i];
}

/**
 * Initializes the navbar system status indicator
 */
function initSystemStatusMonitor() {
    const indicator = document.querySelector(".status-indicator");
    const statusText = document.querySelector(".navbar-status span:last-child");
    
    if (!indicator) return;

    API.checkHealth().then(res => {
        if (res && res.success) {
            indicator.classList.remove("offline");
            if (statusText) statusText.textContent = "ENGINE // ONLINE";
        } else {
            indicator.classList.add("offline");
            if (statusText) statusText.textContent = "ENGINE // OFFLINE";
        }
    }).catch(() => {
        indicator.classList.add("offline");
        if (statusText) statusText.textContent = "ENGINE // OFFLINE";
    });
}

// Auto-run status monitor on DOM load
document.addEventListener("DOMContentLoaded", initSystemStatusMonitor);

// Attach API to window object for global script access
window.API = API;
window.showToast = showToast;
window.formatBytes = formatBytes;
window.escapeHtml = escapeHtml;
