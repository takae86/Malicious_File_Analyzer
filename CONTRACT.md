# 📜 MALICIOUS FILE ANALYZER — FIXED SKELETON / CONTRACT

## Single Source of Truth

This document is the fixed technical contract for the four-member Malicious File Analyzer website team.  
The purpose of this file is to prevent different developers from independently creating incompatible folder structures, APIs, data formats, or module boundaries.

**Freeze this contract before development begins.**  
If a change to this contract becomes necessary, the team must discuss and approve the change before implementation.

---

## 1. Fixed Project Structure

```text
malicious-file-analyzer/
├── frontend/
│   ├── index.html
│   ├── upload.html
│   ├── results.html
│   ├── report.html
│   ├── css/
│   │   └── style.css
│   └── js/
│       ├── api.js
│       ├── upload.js
│       ├── results.js
│       └── report.js
├── backend/
│   ├── analyzer/
│   │   ├── hashing.py
│   │   ├── file_signature.py
│   │   ├── entropy.py
│   │   ├── strings.py
│   │   ├── pe_analysis.py
│   │   └── file_metadata.py
│   ├── file_processing/
│   │   ├── upload_service.py
│   │   ├── file_manager.py
│   │   └── validation.py
│   ├── risk/
│   │   ├── heuristic_rules.py
│   │   ├── indicators.py
│   │   └── risk_engine.py
│   ├── routes/
│   │   ├── analysisRoutes.py
│   │   └── reportRoutes.py
│   ├── controllers/
│   │   ├── analysisController.py
│   │   └── reportController.py
│   ├── services/
│   │   └── analysisService.py
│   ├── config/
│   │   └── config.py
│   └── app.py
├── tests/
│   ├── test_hashing.py
│   ├── test_signature.py
│   ├── test_entropy.py
│   ├── test_strings.py
│   ├── test_pe_analysis.py
│   ├── test_file_processing.py
│   ├── test_risk_engine.py
│   └── test_api.py
├── reports/
├── .gitignore
├── README.md
├── CONTRACT.md
└── requirements.txt
```

---

## 2. Fixed Ownership

Each member has one primary module.

### Member 1 — Team Lead
**Primary ownership:**
- `backend/analyzer/`
- `CONTRACT.md`
- Core analyzer unit tests (`test_hashing.py`, `test_signature.py`, `test_entropy.py`, `test_strings.py`, `test_pe_analysis.py`)

**Also responsible for:**
- Overall architecture
- Cross-module integration
- Final technical review
- Security-analysis decisions

### Member 2 — File Processing
**Primary ownership:**
- `backend/file_processing/`
- `tests/test_file_processing.py`

**Responsible for:**
- File upload handling
- File validation
- File size validation
- Temporary file management
- Unique analysis IDs
- Upload/processing status
- Passing validated files to the analysis pipeline

### Member 3 — Frontend
**Primary ownership:**
- `frontend/`

**Responsible for:**
- Upload interface
- File queue
- Results dashboard
- Detailed report interface
- Loading/error states
- Frontend presentation

### Member 4 — API + Risk + Testing
**Primary ownership:**
- `backend/routes/`
- `backend/controllers/`
- `backend/services/`
- `backend/risk/`
- `tests/test_api.py`, `tests/test_risk_engine.py`

**Responsible for:**
- FastAPI API
- Controllers
- Backend services
- Risk-engine implementation under the agreed rules
- API tests, Risk-engine tests, Integration tests

---

## 3. Module Boundaries

```text
FRONTEND
   │ HTTP
   ▼
  API
   │
   ▼
FILE PROCESSING
   │ validated file
   ▼
ANALYSIS ENGINE
   │ analysis findings
   ▼
RISK ENGINE
   │ final risk result
   ▼
API RESPONSE
   │
   ▼
FRONTEND
```

---

## 4. Frontend Contract

The frontend is responsible only for:
- User interaction
- File selection
- Upload interface
- Displaying progress/status
- Displaying results
- Displaying reports
- Handling frontend errors

**The frontend must not implement:**
- Hashing algorithms
- Entropy calculations
- PE parsing
- Malware heuristics
- Risk calculations
*(Those belong strictly to the backend)*

---

## 5. File Processing Contract

The file-processing module receives uploaded files and prepares them for analysis:
```text
Receive File -> Validate Request -> Validate File -> Generate Analysis ID -> Create Working Location -> Store/Prepare File -> Pass File to Analysis Pipeline
```

It returns metadata such as:
```json
{
  "analysisId": "A10234",
  "fileName": "sample.exe",
  "fileSize": 248000,
  "status": "QUEUED"
}
```

*The file-processing module must not decide whether a file is malicious.*

---

## 6. Analysis Engine Contract (Member 1 Owned)

The analysis engine performs static analysis without intentional execution.

### `hashing.py`
- **Input:** file path / file bytes
- **Output:** `{"md5": "...", "sha256": "..."}`

### `file_signature.py`
- **Input:** file path / file bytes
- **Output:** detected file type, signature information, extension mismatch warning

### `entropy.py`
- **Input:** file bytes / file path
- **Output:** numeric entropy value (scale 0.00 – 8.00), high entropy flag

### `strings.py`
- **Input:** file path
- **Output:** list of extracted readable strings, categorized patterns (URLs, IPs, commands, paths)

### `pe_analysis.py`
- **Input:** file path
- **Output:** structured PE information (headers, sections, imports).  
*If the file is not a supported PE file, the module must return a controlled result (e.g. `{"isPE": False}`) rather than raising an uncaught exception.*

### `file_metadata.py`
- **Input:** file path, original file name
- **Output:** `{"fileName": "...", "fileSize": ..., "fileType": "..."}`

---

## 7. Risk Engine Contract

The risk engine receives structured findings from the static analysis pipeline and produces heuristic indicators and an overall assessment.

Allowed risk values are strictly:
- `LOW`
- `MEDIUM`
- `HIGH`

Example Input to Risk Engine:
```json
{
  "signatureMismatch": true,
  "highEntropy": true,
  "doubleExtension": true,
  "suspiciousPatterns": []
}
```

Example Risk Engine Output:
```json
{
  "indicators": [
    "Double extension detected (e.g. sample.pdf.exe)",
    "File extension does not match detected type",
    "High entropy detected (7.42/8.00) - potential packing/encryption"
  ],
  "risk": "HIGH"
}
```

---

## 8. Fixed Backend URL

- **Backend:** `http://localhost:5000`
- **API Base:** `http://localhost:5000/api`

---

## 9. Fixed Frontend API Configuration

Only this file contains the common API base URL:
`frontend/js/api.js`

```javascript
const API_BASE_URL = "http://localhost:5000/api";
```

Other frontend files must import and use this shared configuration. Do not hardcode different backend URLs in individual files.

---

## 10. Fixed API Routes

- **Health:**
  - `GET /api/health`
- **Analysis:**
  - `POST /api/analyze`
  - `GET /api/analysis/:id`
  - `GET /api/analyses`
- **Reports:**
  - `GET /api/analysis/:id/report`

Do not create alternative endpoint names without team approval and updating `CONTRACT.md`.

---

## 11. Fixed API Success Response Format

Every successful API response must follow:
```json
{
  "success": true,
  "message": "Analysis completed successfully",
  "data": {}
}
```

---

## 12. Fixed API Error Response Format

Every error response must follow:
```json
{
  "success": false,
  "message": "Unable to analyze file"
}
```

---

## 13. Fixed Analysis Result Format

Every analyzed file must expose:
```json
{
  "fileName": "sample.exe",
  "fileSize": 248000,
  "fileType": "Windows PE Executable",
  "signature": "MZ",
  "md5": "HASH_VALUE",
  "sha256": "HASH_VALUE",
  "entropy": 7.42,
  "strings": [],
  "pe": {},
  "indicators": [],
  "risk": "HIGH"
}
```

---

## 14. Git Branch Structure

```text
main
├── lead-analysis      (Member 1)
├── file-processing    (Member 2)
├── frontend-ui        (Member 3)
└── api-risk-testing   (Member 4)
```

Workflow:
`Create Branch -> Implement -> Test Locally -> Commit -> Push -> Pull Request -> Code Review -> Merge`

No direct experimental development on `main`.

---

## 15. Rules for Developers and AI Tools

1. Read `CONTRACT.md` before coding.
2. Implement only assigned module components.
3. Follow the contract exactly.
4. Do not independently change folder structure, file names, API routes, or data formats.
5. If a change is needed: **STOP -> Explain the problem -> Discuss with team -> Approve contract change -> Update CONTRACT.md -> Implement.**
