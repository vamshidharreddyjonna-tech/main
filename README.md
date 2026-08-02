# CDF Shadow AI Hackathon

## Live Application
Live URL: ADD_YOUR_STREAMLIT_URL_HERE

## Project
**Shadow AI Privacy Auditor**

A Streamlit application that scans text for personal information, credentials, financial data, and technical secrets before the text is shared with an AI tool.

## Features
- Detects multiple sensitive-data categories
- Validates credit cards with the Luhn algorithm
- Validates IPv4 addresses
- Shows confidence and risk explanations
- Calculates a simple risk score
- Produces a redacted preview
- Preserves safe text
- Downloads sanitized output
- Runs without an external AI API

## Supported Categories
- Email addresses
- Phone numbers
- Credit-card numbers
- IPv4 addresses
- Aadhaar numbers
- AWS access keys
- API keys
- Passwords
- JWT tokens

## Run Locally

```bash
python -m venv .venv
```

Activate the environment:

### Windows
```bash
.venv\Scripts\activate
```

### macOS/Linux
```bash
source .venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Run the app:

```bash
streamlit run src/app.py
```

## Run Tests

```bash
cd src
pytest -v
```

## Example Risky Input

```text
Please email priya@example.com.
Call me at 415-555-2671.
My test card is 4111 1111 1111 1111.
password=SecretDemo123
```

## Example Safe Input

```text
The engineering team will review the dashboard on Monday.
```

The safe input should remain unchanged.

## Architecture
See `docs/architecture.md`.

## Reflection
See `docs/reflection.md`.

## Walkthrough
See `docs/walkthrough.md`.

## Submission Checklist
- [ ] Add the deployed Streamlit URL above
- [x] Complete planning document
- [x] Working application in `src/`
- [x] At least 10 automated test cases
- [ ] Add walkthrough video URL
- [x] Architecture documentation
- [x] Reflection documentation
- [ ] Confirm deployment works
- [ ] Confirm repository is public or accessible to judges
- [ ] Confirm no secrets or `.env` files are committed

## Important
Use fictional test data only. This demonstration is not a certified data-loss-prevention system.
