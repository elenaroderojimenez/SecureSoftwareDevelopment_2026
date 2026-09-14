import os
import uuid

from werkzeug.utils import secure_filename
from flask import current_app, flash, redirect, render_template, request, send_from_directory, session, url_for

from ..models.file_model import create_file, find_owned_file, list_user_files
from .auth_controller import login_required


def allowed_file(filename, allowed_extensions):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in allowed_extensions
    )


def sanitise_filename(filename):
    return secure_filename(filename)


def generate_stored_filename(original_name):
    """Keep the user-facing name while making the on-disk name unguessable."""
    return f"{uuid.uuid4().hex}_{original_name}"


def save_file(file, upload_folder, filename):
    os.makedirs(upload_folder, exist_ok=True)
    file.save(os.path.join(upload_folder, filename))


def register_file_routes(app):
    @app.route("/", methods=["GET", "POST"])
    @login_required
    def upload_file():
        if request.method == "POST":
            file = request.files.get("file")

            if not file or file.filename == "":
                flash("No file selected.")
                return redirect(request.url)

            if allowed_file(file.filename, current_app.config["ALLOWED_EXTENSIONS"]):
                original_name = sanitise_filename(file.filename)
                if not original_name:
                    flash("Invalid file name.")
                    return redirect(request.url)

                stored_name = generate_stored_filename(original_name)
                save_file(file, current_app.config["UPLOAD_FOLDER"], stored_name)
                create_file(
                    current_app.config["DATABASE"],
                    original_name,
                    stored_name,
                    session["username"],
                )
                flash(f'File "{original_name}" uploaded successfully.')
            else:
                flash("File type not allowed.")

            return redirect(request.url)

        user_files = list_user_files(
            current_app.config["DATABASE"], session["username"]
        )
        return render_template("upload.html", files=user_files)

    @app.route("/download/<int:file_id>")
    @login_required
    def download_file(file_id):
        record = find_owned_file(
            current_app.config["DATABASE"], file_id, session["username"]
        )

        if record:
            stored_name, original_name = record
            return send_from_directory(
                current_app.config["UPLOAD_FOLDER"],
                stored_name,
                as_attachment=True,
                download_name=original_name,
            )

        flash("Unauthorized: You do not have permission to access this file.")
        return redirect(url_for("upload_file"))

    @app.errorhandler(413)
    def request_entity_too_large(error):
        flash("File exceeds the maximum allowed size (1 MB).")
        return redirect(url_for("upload_file"))
