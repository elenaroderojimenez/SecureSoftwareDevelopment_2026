# SecureSoftwareDevelopment_2026

This project is a Flask application for authenticated file upload and download.
The current version contains registration, login, logout, password reset,
protected upload and download functionality, and a JSON REST API protected with
short-lived Bearer tokens. The independent OpenRouter chatbot tool for Task
A.4.4 is documented separately and is not part of the Flask application.

## Python environment

The application was developed and tested with Python 3.12.14. The pinned test
dependency requires Python 3.10 or later; Python 3.10+ is therefore required.

Create and activate a virtual environment, then install the dependencies:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Run the application with:

```powershell
python SSD_examen.py
```

The application requires passwords between 8 and 16 characters, including an
uppercase letter, a lowercase letter, a number and a symbol. Five failed login
attempts temporarily lock an existing username for five minutes.

The browser session uses `HttpOnly` and `SameSite=Lax` cookie settings. The
application is configured with `debug=False` when started through
`SSD_examen.py`.

## File storage

Each accepted upload is assigned a server-generated UUID for its on-disk name.
The database stores that internal name together with the original filename and
the owning user. This means users can upload files with identical names without
overwriting one another, while the dashboard and downloaded attachment retain
the sanitised display filename.

The server accepts TXT, PDF and PNG files up to 1 MB. It sanitizes the submitted
filename, restricts uploads through an allowed-extension list and stores files
in the dedicated `uploads` folder.

## Password reset in local development

Select **Forgot password?** on the login page and submit the account email.
For a registered email, the application prints a one-time reset link in the
terminal running Flask. The link expires after 15 minutes. Reset tokens are
stored only as hashes in SQLite and are marked as used after a successful
password change. At most two reset links are created for an email per hour in
the local application. Creating a new reset link invalidates earlier unused
links for the same account. A successful reset also invalidates existing API
tokens for that account.

This is a local development workflow. A deployed application should send the
link through email over HTTPS instead of writing it to the server terminal.

## REST API

The REST API is available under `/api` and returns JSON for authentication and
error responses. Register and obtain a token as follows:

```powershell
curl.exe -X POST http://127.0.0.1:5000/api/auth/register -H "Content-Type: application/json" -d '{"username":"alice","email":"alice@example.com","password":"Password123!"}'

curl.exe -X POST http://127.0.0.1:5000/api/auth/login -H "Content-Type: application/json" -d '{"username":"alice","password":"Password123!"}'
```

Send the returned `access_token` in `Authorization: Bearer <token>` for
`GET /api/files`, `POST /api/files`, `GET /api/files/<id>` and
`POST /api/auth/logout`. This is an opaque Bearer token, not a JWT. Tokens
expire after 60 minutes, are stored only as SHA-256 hashes in SQLite and are
revoked by logout. A token also becomes invalid after the account password is
reset because the account session version changes.

The API returns JSON errors. Registration and login require a JSON object.
Protected endpoints return `401 Unauthorized` with `WWW-Authenticate: Bearer`
when the token is missing, invalid, expired or revoked. `POST /api/files`
expects a multipart field named `file`; it rejects a missing file with `400`, a
disallowed extension with `415`, and a request above 1 MB with `413`.

The application is available at `http://127.0.0.1:5000/`.

## Independent secure chatbot tool

The Task A.4.4 chatbot is a separate local tool in `tools/openrouter_chat.py`.
Set the provider credential only in the process environment. Do not put it in
source code, JSON requests or the ZIP archive:

```powershell
$env:OPENROUTER_API_KEY = "your-key"
$env:OPENROUTER_MODEL = "your-enabled-model"
python tools/openrouter_chat.py
```

The tool authenticates to OpenRouter with the environment key, validates and
limits each question, keeps a bounded conversation history in memory, controls
the model and system context, redacts likely secrets before sending, returns
only the assistant text, avoids logging the API key, and maps provider failures
to generic errors. Type `/exit` or `/quit` to close the chat. The full security
discussion and tests are in `A4_4_CHATBOT_REPORT.md` and
`tests/test_openrouter_chat.py`.

## Tests

Run the automated test suite from the project root:

```powershell
python -m pytest -q tests
```

The suite currently contains 34 tests covering validation, bcrypt password
storage, login lockout, browser-session protection, Bearer-token lifecycle,
password-reset invalidation, file ownership authorization and the independent
chatbot tool with a mocked provider.

## Current structure

- `SSD_examen.py`: application entry point.
- `application/config.py`: application configuration.
- `application/database.py`: SQLite initialization and connections.
- `application/models/`: database access for users and files.
- `application/controllers/`: Flask routes and related application logic.
- `templates/`: HTML views.
- `uploads/`: local upload directory used at runtime.
- `tests/`: pytest tests for authentication, file ownership and the REST API.

The project follows a lightweight MVC organization. Models contain database
operations, controllers handle Flask requests and application logic, and the
templates provide the views. This keeps the structure close to the style of the
course examples while keeping the main responsibilities separated.
