# CyberShield — Security Log Analyzer

CyberShield is a Python-based web application for analyzing web server access logs and highlighting potentially suspicious activity. It provides a Streamlit dashboard, rule-based threat detection, heuristic risk scoring, IP-wise activity analysis, investigation history, and report exports.

> **Note:** CyberShield is an educational and log-analysis tool. Its risk scores are heuristic indicators, not proof that an IP address or request is malicious.

## Features

- **Log analysis:** Parse supported web server access logs into structured records.
- **Rule-based threat detection:** Identify patterns such as repeated HTTP `401`/`403` responses, requests to sensitive paths, and unusually high request volumes.
- **Risk scoring:** Assign heuristic risk scores and severity levels to detected events.
- **IP analysis:** Summarize suspicious activity by IP address using locally calculated indicators.
- **Interactive dashboard:** Review metrics, charts, detected events, and event details.
- **Filtering and search:** Narrow findings by severity, IP address, HTTP status, date range, and search term where available in the current app.
- **Investigation history:** Store and retrieve investigation records using SQLite.
- **Reports and exports:** Download investigation reports in HTML format and export findings to CSV.
- **Sample data:** Use a sample access log to explore the application without uploading your own file.

## Technology Stack

- Python
- Streamlit
- Pandas
- Plotly
- SQLite
- Regular expressions
- Python `unittest` for automated tests

## Project Structure

```text
CyberShield/
├── app.py
├── core/
│   ├── log_parser.py
│   ├── detector.py
│   ├── ip_reputation.py
│   ├── storage.py
│   └── reporting.py
├── data/
│   └── sample_access.log
├── tests/
│   └── test_day5.py
├── requirements.txt
└── README.md
```

The exact files may vary slightly depending on which project stages have been installed. Keep existing `core/storage.py`, `core/reporting.py`, and `core/log_parser.py` files when adding later-stage features.

## Requirements

- Python 3.10 or a compatible version supported by your installed dependencies
- `pip`
- A terminal such as Windows Command Prompt or PowerShell

## Installation

### 1. Clone or download the project

If the project is hosted on GitHub:

```bash
git clone <your-repository-url>
cd CyberShield
```

Alternatively, download the project ZIP and extract it.

### 2. Create a virtual environment (recommended)

**Windows CMD:**

```cmd
python -m venv .venv
.venv\Scripts\activate
```

**macOS/Linux:**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

If `requirements.txt` is missing, install the packages used by the project:

```bash
pip install streamlit pandas plotly
```

## Run the Application

From the project root directory, run:

```bash
python -m streamlit run app.py
```

Streamlit will print a local URL in the terminal, usually:

```text
http://localhost:8501
```

Open that address in your browser.

## How to Use

1. Start CyberShield with the command above.
2. Upload a supported server access log, or select the sample log if the interface offers that option.
3. Run the analysis.
4. Review dashboard metrics and detected events.
5. Adjust detection thresholds, if available, to explore how they affect results.
6. Filter findings by severity, IP, status code, date, or search term.
7. Inspect individual events and their risk-score explanations.
8. Save the investigation to the local database, if the save option is available.
9. Export findings as CSV or generate an HTML report.

## Detection Overview

CyberShield uses predefined rules to flag patterns that may warrant investigation, including:

- Repeated authentication-related failures, such as HTTP `401` and `403` responses.
- Requests for sensitive paths or endpoints.
- High request volume within the detection window.
- Additional suspicious path or HTTP-method patterns supported by the installed detector.

A flagged event should be reviewed in context. Legitimate users, automated services, vulnerability scanners, and misconfigured clients can also generate unusual log patterns.

## Data Storage and Privacy

- Investigation history is stored locally in a SQLite database when persistence is enabled.
- The database may be created under the project's `data/` directory by the storage module.
- Log files can contain IP addresses, URLs, timestamps, and other operational information. Use test or sanitized logs when possible, and do not publish sensitive logs or database files to a public repository.
- IP analysis uses local log-derived indicators unless an external reputation provider is explicitly added and configured.

## Run Tests

If the Day 5 test file is present, run:

```bash
python -m unittest discover -s tests -p "test_day5.py" -v
```

To check Python syntax for the main modules on Windows CMD:

```cmd
python -m py_compile app.py core\detector.py core\ip_reputation.py
```

Tests and module names can differ by project version. If your repository uses a different test filename, update the command accordingly.

## Limitations

- Detection is rule-based and may produce false positives or miss activity that does not match existing rules.
- Risk scores are heuristic and are not a definitive threat verdict.
- IP risk analysis does not independently verify an IP against an external threat-intelligence database.
- Log formats not supported by the parser may fail to parse correctly.
- CyberShield is not a replacement for a production SIEM, an intrusion prevention system, or a dedicated incident-response platform.

## Future Enhancements

Potential future improvements include:

- Support for more web server log formats.
- Configurable detection rules and thresholds.
- Additional test coverage and sample attack scenarios.
- Improved report customization.
- Optional integration with reputable threat-intelligence sources.
- Authentication and role-based access for multi-user deployments.

## Contributing

1. Fork the repository.
2. Create a feature branch.
3. Make focused changes and add tests where practical.
4. Run the tests before submitting a pull request.

## License

No license has been specified yet. Add a `LICENSE` file before distributing the project if you want to define the terms under which others may use, modify, or redistribute it.
