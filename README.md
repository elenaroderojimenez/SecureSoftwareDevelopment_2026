# SecureSoftwareDevelopment_2026

This project is a Flask application for authenticated file upload and download.
The current version contains registration, login, logout, upload and protected
download functionality. It is an initial implementation and will be extended
with password reset, Cerebras integration and security testing in later stages.

## Python environment

The local virtual environment uses Python 3.12.3. Python 3.8 or later is
expected to be compatible with the current assignment code.

Create and activate a virtual environment, then install the dependencies:

```bash
python -m venv venv
venv\Scripts\activate
python -m pip install -r requirements.txt
```

Run the application with:

```bash
python SSD_examen.py
```

The application requires passwords between 8 and 16 characters, including an
uppercase letter, a lowercase letter and a number. Five failed login attempts
temporarily lock the username for five minutes.

## Password reset in local development

Select **Forgot password?** on the login page and submit the account email.
For a registered email, the application prints a one-time reset link in the
terminal running Flask. The link expires after 15 minutes. Reset tokens are
stored only as hashes in SQLite and are marked as used after a successful
password change.

This is a local development workflow. A deployed application should send the
link through email over HTTPS instead of writing it to the server terminal.

The application is available at `http://127.0.0.1:5000/`.

## Current structure

- `SSD_examen.py`: application entry point.
- `application/config.py`: application configuration.
- `application/database.py`: SQLite initialization and connections.
- `application/models/`: database access for users and files.
- `application/controllers/`: Flask routes and related application logic.
- `templates/`: HTML views.
- `uploads/`: local upload directory used at runtime.
- `tests/`: automated tests to be added in a later stage.

The project follows a lightweight MVC organization. Models contain database
operations, controllers handle Flask requests and application logic, and the
templates provide the views. This keeps the structure close to the style of the
course examples while keeping the main responsibilities separated.
