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

| Member | Role |
|---|---|
| Member 1 | Team Lead — Security Analysis, Architecture & Integration |
| Member 2 | Frontend UI/UX Developer |
| Member 3 | Frontend JavaScript & API Integration Developer |
| Member 4 | Backend API, Risk Engine Support & Testing |

The Team Lead owns the core static-analysis architecture and final integration because this role requires the strongest existing knowledge of the field.

## 🔧 Setup

### 1. Clone

```bash
git clone <repository-url>
cd malicious-file-analyzer
```

### 2. Create Virtual Environment

Windows:

```bash
python -m venv venv
venv\Scripts\activate
```

Linux/macOS:

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Run Backend

```bash
python backend/app.py
```

Backend:

```text
http://localhost:5000
```

API:

```text
http://localhost:5000/api
```

The common API configuration is maintained in:

```text
frontend/js/api.js
```

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

| File | Purpose |
|---|---|
| `README.md` | Project overview, setup, usage, and team information |
| `PRD_Malicious_File_Analyzer.md` | Product requirements and scope |
| `TEAM_ROLES_Malicious_File_Analyzer.md` | Team responsibilities and ownership |
| `CONTRACT.md` | Fixed technical architecture and integration contract |

## 📜 License

Distributed under the MIT License.

Educational and research use.
