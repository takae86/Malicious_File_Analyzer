# 🦠 Malicious File Analyzer

A web-based static file analysis platform for the initial inspection and triage of suspicious files.

## 🎯 Project Goal

Users can upload multiple files and view static-analysis results including file signatures, MD5/SHA-256 hashes, entropy, readable strings, basic Windows PE information, heuristic indicators, and an overall LOW/MEDIUM/HIGH risk level.

> **Safety:** This project performs static analysis only. It does not intentionally execute uploaded files and is not a replacement for professional antivirus software or dynamic sandboxing.

## ✨ Main Features

- 📤 Multi-file upload
- 🔎 File signature / magic-byte detection
- 🔐 MD5 and SHA-256 hashing
- 📊 Shannon entropy calculation
- 🔤 String extraction
- 🧩 Basic PE analysis
- ⚠️ Heuristic detection
- 📈 LOW / MEDIUM / HIGH risk assessment
- 📋 Results dashboard and detailed reports

## 🔄 How It Works

```text
Select Files
    ↓
Upload
    ↓
Static Analysis
 ├─ Signature
 ├─ Hashes
 ├─ Entropy
 ├─ Strings
 └─ PE Analysis
    ↓
Heuristic Risk Engine
    ↓
Results Dashboard
    ↓
Detailed Report
```

## 🏗️ Architecture

```text
             MALICIOUS FILE ANALYZER
                      │
          ┌───────────┴───────────┐
          │                       │
      FRONTEND                  BACKEND
   HTML/CSS/JS              Python + FastAPI
          │                       │
          │            ┌──────────┴──────────┐
          │            │                     │
          │       Analysis Engine       Risk Engine
          │            │                     │
          │       Hash / Signature      Heuristics
          │       Entropy / Strings      Indicators
          │       PE Analysis            Risk Level
          │
          └──────────── API ────────────────►
```

## 🛠️ Technology Stack

### Frontend

- HTML5
- CSS3
- JavaScript

### Backend

- Python 3.8+
- FastAPI

### Core Libraries

- `hashlib`
- `math`
- `re`
- `pefile`

## 📂 Project Structure

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
│   ├── risk/
│   ├── routes/
│   ├── controllers/
│   ├── services/
│   ├── config/
│   └── app.py
├── tests/
├── reports/
├── .gitignore
├── README.md
├── CONTRACT.md
└── requirements.txt
```

The exact fixed structure is defined by `CONTRACT.md`.

## 👥 Team

| Member   | Role                                                      |
| -------- | --------------------------------------------------------- |
| Member 1 | Team Lead — Security Analysis, Architecture & Integration |
| Member 2 | Frontend UI/UX Developer                                  |
| Member 3 | Frontend JavaScript & API Integration Developer           |
| Member 4 | Backend API, Risk Engine Support & Testing                |

The Team Lead owns the core static-analysis architecture and final integration because this role requires the strongest existing knowledge of the field.

## 🔧 Setup & Installation

### 1. Prerequisites

* **Python 3.8+** installed on your system (Python 3.10–3.14 supported).
* `pip` package manager.

---

### 2. Clone the Repository & Navigate to Directory

```bash
git clone <repository-url>
cd malicious-file-analyzer
```

---

### 3. Create & Activate a Virtual Environment

#### Windows (Command Prompt):
```cmd
python -m venv venv
venv\Scripts\activate
```

#### Windows (PowerShell):
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```
*(If PowerShell restricts script execution, run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` first).*

#### Linux / macOS:
```bash
python3 -m venv venv
source venv/bin/activate
```

---

### 4. Install Dependencies

Install all required backend dependencies specified in `requirements.txt`:

```bash
pip install -r requirements.txt
```

#### Packages Installed:
* `fastapi>=0.100.0` — High-performance backend web framework
* `uvicorn>=0.22.0` — Lightning-fast ASGI production server
* `python-multipart>=0.0.6` — Multipart file upload support
* `pefile>=2023.2.7` — Windows Portable Executable (PE) static header parsing
* `pytest>=7.4.0` — Automated unit and integration test suite
* `httpx>=0.24.0` — Async HTTP test client

---

### 5. Run the Backend

You can start the FastAPI backend server using any of the following methods:

#### Method A: Direct Python Script (Recommended)
```bash
python backend/app.py
```

#### Method B: Direct Uvicorn Command
```bash
uvicorn backend.app:app --host 0.0.0.0 --port 5000 --reload
```

#### Method C: One-Click Batch Script (Windows)
Double-click:
```text
start_backend.bat
```

---

### 6. Verify Backend & Access API Documentation

Once started, the backend runs on port `5000`:

* **API Health Check:** [http://localhost:5000/api/health](http://localhost:5000/api/health)
* **Interactive Swagger UI Docs:** [http://localhost:5000/docs](http://localhost:5000/docs)
* **ReDoc Interactive Reference:** [http://localhost:5000/redoc](http://localhost:5000/redoc)

The frontend connects to this backend via the base URL configured in:
```text
frontend/js/api.js
```

---

### 7. Run the Frontend

To view and interact with the user interface:

#### Option A: VS Code Live Server (Recommended)
Right-click `frontend/index.html` in VS Code and select **"Open with Live Server"** (typically serves on `http://127.0.0.1:5500/frontend/index.html`).

#### Option B: Python Simple HTTP Server
```bash
python -m http.server 8000 --directory frontend
```
Then navigate to: [http://localhost:8000/index.html](http://localhost:8000/index.html)

#### Option C: Direct Browser Opening
Double-click `frontend/index.html` directly in your file explorer to open it in your browser.

---

### 8. Run Automated Tests

Run the full 44-test unit test suite covering hashing, signatures, entropy, strings, PE inspection, file validation, risk scoring, and API routes:

#### Via Pytest:
```bash
pytest -v tests/
```

#### Via Windows Batch Script:
Double-click `run_tests.bat`.

---

### 🧪 Safe Test Files

The repository includes 5 non-executable, 100% safe test fixtures in `test_files/` to verify every static analysis component without running real malware:

| File | Size | Purpose | Expected Risk |
| :--- | ---: | :--- | :--- |
| `normal_test.txt` | 215 B | Baseline upload, text metadata, MD5/SHA-256 | **LOW** |
| `normal_test.csv` | 93 B | Non-executable structured document | **LOW** |
| `strings_test.txt` | 213 B | Predictable readable strings & URL extraction | **LOW** |
| `high_entropy_test.bin` | 4,096 B | High Shannon entropy test (~7.96) | **HIGH** |
| `fake_pe_signature_test.bin` | 512 B | `MZ` file signature & graceful PE parser test | **LOW** |

## 🌿 Git & GitHub Workflow

```text
main
├── lead-analysis
├── frontend-ui
├── frontend-js
└── api-risk-testing
```

Recommended workflow:

```text
Branch → Code → Test → Commit → Push → Pull Request → Review → Merge
```

Do not use `main` for experimental development.

## 📜 CONTRACT.md

`CONTRACT.md` is the technical source of truth for the four developers.

It defines:

- Fixed folder structure
- File ownership
- API routes
- Response formats
- Analysis result format
- Risk values
- Shared interfaces
- Port
- Integration rules

Developers and coding AI tools should read `CONTRACT.md` before making changes.

## 🧪 Testing

Testing covers:

- Hashing
- Signature detection
- Entropy
- String extraction
- PE analysis
- Risk engine
- API endpoints
- Error handling

## 🔮 Future Roadmap

Possible future additions:

- YARA integration
- VirusTotal hash lookup
- Advanced PDF/Office analysis
- IOC extraction
- PDF/JSON report export
- Advanced PE analysis
- Analysis history

These are outside the initial MVP.

## 🛡️ Safety

Use suspicious samples only in an isolated testing environment such as a virtual machine or dedicated sandbox.

A LOW risk result does not guarantee that a file is safe, and a HIGH risk result does not by itself prove that a file is malicious.

## 📄 Documentation

| File                                    | Purpose                                               |
| --------------------------------------- | ----------------------------------------------------- |
| `README.md`                             | Project overview, setup, usage, and team information  |
| `PRD_Malicious_File_Analyzer.md`        | Product requirements and scope                        |
| `TEAM_ROLES_Malicious_File_Analyzer.md` | Team responsibilities and ownership                   |
| `CONTRACT.md`                           | Fixed technical architecture and integration contract |

## 📜 License

Distributed under the MIT License.

Educational and research use.
