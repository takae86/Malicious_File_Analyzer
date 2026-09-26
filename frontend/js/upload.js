/**
 * MALICIOUS FILE ANALYZER — UPLOAD & QUEUE CONTROLLER
 * Role: Member 3 (Frontend & Results Dashboard)
 * 
 * Handles multi-file drag-and-drop, client-side validation, queue management,
 * animated scanning progression, and backend dispatch via API.analyzeFiles.
 */

document.addEventListener("DOMContentLoaded", () => {
    // DOM Elements
    const dropzone = document.getElementById("dropzone");
    const fileInput = document.getElementById("file-input");
    const browseBtn = document.getElementById("browse-btn");
    const queueSection = document.getElementById("queue-section");
    const queueList = document.getElementById("queue-list");
    const queueCount = document.getElementById("queue-count");
    const startAnalysisBtn = document.getElementById("start-analysis-btn");
    const clearQueueBtn = document.getElementById("clear-queue-btn");

    // Scanning modal elements
    const scanningOverlay = document.getElementById("scanning-overlay");
    const scanningTarget = document.getElementById("scanning-target");
    const scanSteps = document.querySelectorAll(".scan-step");

    // Internal state: list of File objects
    let selectedFiles = [];

    // Helper: Determine file icon by extension
    function getFileIcon(filename) {
        const ext = filename.split(".").pop().toLowerCase();
        switch (ext) {
            case "exe":
            case "dll":
            case "sys":
            case "bin":
                return "fa-brands fa-windows";
            case "pdf":
                return "fa-solid fa-file-pdf";
            case "zip":
            case "rar":
            case "7z":
            case "tar":
            case "gz":
                return "fa-solid fa-file-zipper";
            case "doc":
            case "docx":
                return "fa-solid fa-file-word";
            case "js":
            case "py":
            case "ps1":
            case "bat":
            case "sh":
                return "fa-solid fa-file-code";
            default:
                return "fa-solid fa-file-lines";
        }
    }

    // Helper: Determine category label
    function getCategoryLabel(filename) {
        const ext = filename.split(".").pop().toLowerCase();
        if (["exe", "dll", "sys"].includes(ext)) return "Windows Executable";
        if (["pdf"].includes(ext)) return "PDF Document";
        if (["zip", "rar", "7z", "tar", "gz"].includes(ext)) return "Archive";
        if (["doc", "docx", "xls", "xlsx"].includes(ext)) return "Office Document";
        if (["js", "py", "ps1", "bat", "sh"].includes(ext)) return "Script";
        return "Binary / Data";
    }

    // Render the file queue
    function renderQueue() {
        if (!queueList) return;

        queueList.innerHTML = "";

        if (selectedFiles.length === 0) {
            queueSection.style.display = "none";
            startAnalysisBtn.disabled = true;
            return;
        }

        queueSection.style.display = "block";
        queueCount.textContent = `${selectedFiles.length} file${selectedFiles.length > 1 ? "s" : ""} selected`;
        startAnalysisBtn.disabled = false;

        selectedFiles.forEach((file, index) => {
            const item = document.createElement("div");
            item.className = "queue-item";
            item.innerHTML = `
                <div class="queue-item-info">
                    <div class="queue-item-icon">
                        <i class="${getFileIcon(file.name)}"></i>
                    </div>
                    <div class="queue-item-details">
                        <div class="queue-item-name" title="${escapeHtml(file.name)}">${escapeHtml(file.name)}</div>
                        <div class="queue-item-meta">
                            <span>${getCategoryLabel(file.name)}</span>
                            <span>•</span>
                            <span>${formatBytes(file.size)}</span>
                        </div>
                    </div>
                </div>
                <div class="queue-item-actions">
                    <span class="queue-item-status">
                        <i class="fa-solid fa-check"></i> Ready
                    </span>
                    <button class="btn btn-ghost btn-sm remove-file-btn" data-index="${index}" title="Remove file">
                        <i class="fa-solid fa-xmark"></i>
                    </button>
                </div>
            `;
            queueList.appendChild(item);
        });

        // Attach remove buttons
        document.querySelectorAll(".remove-file-btn").forEach(btn => {
            btn.addEventListener("click", (e) => {
                e.stopPropagation();
                const idx = parseInt(btn.dataset.index, 10);
                selectedFiles.splice(idx, 1);
                renderQueue();
            });
        });
    }

    // Add files with client-side deduplication & check
    function addFiles(files) {
        let addedCount = 0;
        Array.from(files).forEach(file => {
            // Check if already added
            const exists = selectedFiles.some(f => f.name === file.name && f.size === file.size);
            if (!exists) {
                selectedFiles.push(file);
                addedCount++;
            }
        });

        if (addedCount > 0) {
            renderQueue();
            showToast("Files Added", `Added ${addedCount} file(s) to the analysis queue.`, "info");
        }
    }

    // Drag and Drop Event Listeners
    if (dropzone) {
        ["dragenter", "dragover"].forEach(eventName => {
            dropzone.addEventListener(eventName, (e) => {
                e.preventDefault();
                e.stopPropagation();
                dropzone.classList.add("dragover");
            });
        });

        ["dragleave", "drop"].forEach(eventName => {
            dropzone.addEventListener(eventName, (e) => {
                e.preventDefault();
                e.stopPropagation();
                dropzone.classList.remove("dragover");
            });
        });

        dropzone.addEventListener("drop", (e) => {
            if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
                addFiles(e.dataTransfer.files);
            }
        });

        dropzone.addEventListener("click", () => {
            if (fileInput) fileInput.click();
        });
    }

    if (browseBtn) {
        browseBtn.addEventListener("click", (e) => {
            e.stopPropagation();
            if (fileInput) fileInput.click();
        });
    }

    if (fileInput) {
        fileInput.addEventListener("change", (e) => {
            if (e.target.files && e.target.files.length > 0) {
                addFiles(e.target.files);
                fileInput.value = ""; // Reset for re-selection
            }
        });
    }

    if (clearQueueBtn) {
        clearQueueBtn.addEventListener("click", () => {
            selectedFiles = [];
            renderQueue();
            showToast("Queue Cleared", "All files have been removed from the queue.", "info");
        });
    }

    // Step animation controller for the scanning modal
    function runScanStepAnimation(stepIndex, callback) {
        if (!scanSteps || stepIndex >= scanSteps.length) {
            if (callback) callback();
            return;
        }

        scanSteps.forEach((step, idx) => {
            step.classList.remove("active");
            if (idx < stepIndex) {
                step.classList.add("completed");
                step.innerHTML = `<i class="fa-solid fa-check"></i> ${step.dataset.label}`;
            } else if (idx === stepIndex) {
                step.classList.add("active");
                step.innerHTML = `<i class="fa-solid fa-circle-dot"></i> ${step.dataset.label}`;
            } else {
                step.classList.add("pending");
                step.innerHTML = `<i class="fa-regular fa-circle"></i> ${step.dataset.label}`;
            }
        });
    }

    // Start Analysis Handler
    if (startAnalysisBtn) {
        startAnalysisBtn.addEventListener("click", async () => {
            if (selectedFiles.length === 0) {
                showToast("No Files", "Please add at least one file to analyze.", "error");
                return;
            }

            // Set up scanning modal
            if (scanningOverlay) {
                scanningOverlay.classList.add("active");
            }
            if (scanningTarget) {
                const targetText = selectedFiles.length === 1 
                    ? selectedFiles[0].name 
                    : `${selectedFiles[0].name} (+${selectedFiles.length - 1} more)`;
                scanningTarget.textContent = targetText;
            }

            // Reset scan steps
            scanSteps.forEach(step => {
                step.className = "scan-step pending";
                step.innerHTML = `<i class="fa-regular fa-circle"></i> ${step.dataset.label}`;
            });

            // Simulate progress step progression while backend processes
            let currentStep = 0;
            const stepInterval = setInterval(() => {
                if (currentStep < scanSteps.length - 1) {
                    runScanStepAnimation(currentStep);
                    currentStep++;
                }
            }, 300);

            try {
                // Dispatch files to the FastAPI backend API
                const result = await API.analyzeFiles(selectedFiles);

                clearInterval(stepInterval);

                if (result && result.success) {
                    // Mark all steps complete
                    scanSteps.forEach(step => {
                        step.className = "scan-step completed";
                        step.innerHTML = `<i class="fa-solid fa-check"></i> ${step.dataset.label}`;
                    });

                    showToast("Analysis Complete", result.message || "Static file analysis succeeded.", "success");

                    // Brief delay so user sees complete state, then redirect to results
                    setTimeout(() => {
                        if (scanningOverlay) scanningOverlay.classList.remove("active");
                        
                        // If data has an ID or array of items
                        let redirectId = "";
                        if (result.data) {
                            if (Array.isArray(result.data) && result.data.length > 0) {
                                redirectId = result.data[0].id || result.data[0].analysisId || "";
                            } else if (result.data.id || result.data.analysisId) {
                                redirectId = result.data.id || result.data.analysisId;
                            }
                        }

                        if (redirectId) {
                            window.location.href = `results.html?id=${encodeURIComponent(redirectId)}`;
                        } else {
                            window.location.href = "results.html";
                        }
                    }, 600);

                } else {
                    // Backend returned an error response
                    if (scanningOverlay) scanningOverlay.classList.remove("active");
                    const errMessage = result.message || "Unable to analyze file. Please verify upload and try again.";
                    showToast("Analysis Failed", errMessage, "error");
                }
            } catch (err) {
                clearInterval(stepInterval);
                if (scanningOverlay) scanningOverlay.classList.remove("active");
                console.error("Upload error:", err);
                showToast("Connection Error", "Could not reach backend analysis service at " + API.baseUrl, "error");
            }
        });
    }
});
