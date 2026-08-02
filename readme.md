# 🛡️ PhishGuard — Phishing Risk Assessment Web App

PhishGuard is a beginner-friendly, **rule-based** phishing risk assessment tool built with
**Python, Flask, HTML, CSS, JavaScript, and EasyOCR**. It analyzes screenshots, pasted text
messages, and website URLs, then produces a **Danger Score (0–100%)** using transparent,
weighted cybersecurity heuristics — **no AI/ML, no paid APIs, no login system.**

Built as a Computer Science student project / GitHub portfolio piece.

---

## Project Overview

Users can choose one of three input methods:

1. **Upload Screenshot** — OCR (EasyOCR) extracts text from an image (email, SMS, WhatsApp, DM, banking alert, etc.), which is then analyzed.
2. **Paste Text Message** — Analyze a suspicious message directly.
3. **Paste Website URL** — Analyze a link's structure (no live browsing/fetching of the URL).

Each analysis produces:
- A **Danger Score** (0–100%) and **Risk Level** (Safe / Low / Medium / High)
- A colored progress bar
- A list of **detected indicators**
- Dynamically generated **recommendations**
- Five random **cybersecurity tips**

> ⚠️ **PhishGuard never claims definitive phishing detection.** All results are heuristic risk
> assessments intended for educational purposes only.

---

## Features

- Three analysis modes: Screenshot (OCR), Text, URL
- Rule-based scoring engine — fully transparent, configurable indicator dictionary
- Drag-and-drop screenshot upload with live image preview
- Character counter on the text input box
- Loading spinner while analysis runs
- Colored, animated danger-score progress bar
- Detected indicators + dynamic recommendations + random cybersecurity tips
- Responsive, dark-blue cybersecurity-themed UI
- Friendly error handling (no file, invalid image, empty text, invalid URL, OCR failure, 404, 500)
- Custom 404 and About pages
- No database, no login system, no external paid services

---

## Technologies Used

| Layer | Technology |
|---|---|
| Backend | Python 3, Flask |
| OCR | EasyOCR |
| Image handling | Pillow |
| Frontend | HTML5, CSS3, Vanilla JavaScript |
| Scoring | Pure Python rule-based heuristics (no AI/ML) |

---

## Project Structure

```
phishguard/
├── app.py                  # Main Flask application (routes, error handlers)
├── ocr_module.py            # EasyOCR text extraction from screenshots
├── text_analysis.py         # Rule-based phishing text analyzer + indicator dictionary
├── url_analysis.py          # Rule-based URL structure analyzer
├── tips.py                  # Bank of 25 cybersecurity tips (5 shown at random)
├── requirements.txt         # Python dependencies
├── .gitignore
├── README.md
├── templates/
│   ├── base.html             # Shared layout: navbar + footer + flash messages
│   ├── index.html            # Home page (3 option cards + 3 forms)
│   ├── result.html           # Analysis report page
│   ├── about.html            # About / how-it-works page
│   └── 404.html               # Custom 404 page
├── static/
│   ├── css/style.css          # Full cybersecurity-themed stylesheet
│   └── js/script.js           # Card switching, drag-drop, preview, char counter, spinner
└── uploads/                  # Temporary storage for uploaded screenshots (auto-cleaned)
```

Each concern (OCR, text rules, URL rules, tips) lives in its own module — no code duplication,
each function is commented, and variable names are descriptive.

---

## How the Danger Score Works

**Text analysis** (`text_analysis.py`) scans a message against a configurable dictionary of
16 phishing-indicator categories (urgent language, OTP/password/PIN requests, banking keywords,
prize/gift-card/crypto scams, verification requests, fake support scams, personal-info requests,
etc.). Each matched category contributes weighted points (5–20) to the score. Email addresses
and URLs found inside the text add further points. The URL module's score is also reused when a
URL appears inside a pasted message.

**URL analysis** (`url_analysis.py`) inspects only the **structure** of the URL — it never visits
or fetches the link. It checks:

- HTTP vs HTTPS
- URL length
- Raw IP address as hostname
- Number of subdomains / dots
- Excessive hyphens or digits
- Known URL-shortener domains
- Suspicious top-level domains (`.xyz`, `.top`, `.club`, etc.)
- Suspicious keywords (`login`, `verify`, `secure`, `account`, ...)
- Basic brand-impersonation pattern (brand name inside a non-official domain)
- Unusual special characters (`@`, `%`)

The final score is capped at 100 and mapped to a risk level:

| Score | Risk Level |
|---|---|
| 0–25 | Safe |
| 26–50 | Low Risk |
| 51–75 | Medium Risk |
| 76–100 | High Risk |

---

## Installation

### Prerequisites
- Python 3.9+ installed
- `pip` package manager

### Steps (from an empty folder)

```bash
# 1. Clone or copy the project files into a folder, then move into it
cd phishguard

# 2. (Recommended) Create a virtual environment
python -m venv venv

# Activate it:
# Windows:
venv\Scripts\activate
# macOS / Linux:
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt
```

> **Note on EasyOCR:** the first time you run screenshot analysis, EasyOCR will automatically
> download its English detection/recognition model files (a few hundred MB). This requires an
> internet connection the first time only, and needs a few minutes depending on your connection.
> Text and URL analysis work immediately without this download.

---

## How to Run

```bash
python app.py
```

Then open your browser to:

```
http://127.0.0.1:5000
```

You should see the PhishGuard home page with three option cards: **Analyze Screenshot**,
**Analyze Text**, **Analyze URL**. Click a card to reveal its form, submit it, and you'll be
taken to the Result page with your Danger Score, indicators, and recommendations.

To stop the server, press `CTRL + C` in the terminal.

---

## Screenshots

> _Add your own screenshots here after running the app locally, e.g.:_

```
docs/screenshots/home-page.png
docs/screenshots/text-analysis-result.png
docs/screenshots/url-analysis-result.png
docs/screenshots/screenshot-upload.png
```

---

## Error Handling

PhishGuard handles the following gracefully with friendly messages (no stack traces shown to users):

- No file uploaded / no file selected
- Invalid or corrupted image file
- File exceeding the 8 MB upload limit
- Empty text submitted
- Empty or invalid URL submitted
- OCR failure or no readable text found in an image
- Unknown routes (custom 404 page)
- Unexpected server errors (custom 500 handling, redirects home with a message)

---

## Limitations

- This is a **rule-based heuristic tool**, not a machine-learning or AI classifier — it can
  produce false positives and false negatives.
- URL analysis is based on **structure only**; it does not check live reputation, WHOIS data,
  SSL certificate validity, or blocklists, since no external/paid APIs are used.
- OCR accuracy depends on image clarity, font, and language (English only in this build).
- Brand-impersonation detection is a simple substring check and can miss more advanced
  lookalike/typosquatting techniques (e.g. homoglyphs).
- Not intended to replace dedicated enterprise anti-phishing or email security solutions.

---

## Future Improvements

- Multi-language OCR and text analysis support
- Downloadable PDF security report
- Browser extension version for real-time link checking
- Expandable/community-editable phishing indicator dictionary
- Dark mode toggle
- Basic analytics dashboard (locally stored, no third-party tracking)



---

## Disclaimer

PhishGuard is an **educational project**. The Danger Score is a heuristic risk estimate based on
detected patterns, not a definitive determination of phishing. Always verify suspicious
communications through official channels and use your own judgement.