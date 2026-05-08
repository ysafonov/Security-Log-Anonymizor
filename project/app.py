from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

from flask import Flask, Response, current_app, jsonify, render_template, request
from markupsafe import escape
from werkzeug.datastructures import FileStorage
from werkzeug.utils import secure_filename

import config
import metakeys_config
from functions import Functions
from jsonfile import Process
from regex import Regex


# -----------------------------------------------------------------------------
# Application configuration
# -----------------------------------------------------------------------------

app = Flask(__name__)

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_FOLDER = BASE_DIR / "uploads"
UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)

app.config["UPLOAD_FOLDER"] = str(UPLOAD_FOLDER)
app.config.from_pyfile("config.py")

# Select the SIEM metadata configuration used for JSON anonymization.
# Change this value if you want to anonymize according to another SIEM model.
METAK_KEY_CONFIGURATION = metakeys_config.Elasticsearch
# METAK_KEY_CONFIGURATION = metakeys_config.RSANetWitness
# METAK_KEY_CONFIGURATION = metakeys_config.QRadar

ALLOWED_LOG_EXTENSIONS = {".log"}
ALLOWED_JSON_EXTENSIONS = {".json"}


# Each tuple contains a config flag and the anonymization function that should be
# applied when the flag is enabled in config.py.
LINE_ANONYMIZATION_STEPS: tuple[tuple[str, Callable[[str], str]], ...] = (
    ("EMAIL", Regex.anonymize_email_line),
    ("IPV4", Regex.anonymize_ipv4_line),
    ("IPV6", Regex.anonymize_ipv6_line),
    ("LINKLOCAL", Regex.anonymize_linklocal_line),
    ("DOMAIN", Regex.anonymize_domain_line),
    ("MAC", Regex.anonymize_mac_line),
    ("URL", Regex.anonymize_url_line),
    ("WINDOWS_DIR", Regex.anonymize_windows_line),
)


# -----------------------------------------------------------------------------
# Helper functions
# -----------------------------------------------------------------------------

def get_uploaded_file(field_name: str) -> FileStorage:
    """Return uploaded file from the request or raise a clear validation error."""
    uploaded_file = request.files.get(field_name)

    if uploaded_file is None:
        raise ValueError(f"Missing file field: {field_name}")

    if not uploaded_file.filename:
        raise ValueError("No file selected.")

    return uploaded_file


def get_file_extension(uploaded_file: FileStorage) -> str:
    """Return a normalized lowercase file extension."""
    return Path(uploaded_file.filename or "").suffix.lower()


def get_safe_output_path(original_filename: str, suffix: str, extension: str) -> Path:
    """Create a safe output path inside the configured upload directory."""
    safe_name = secure_filename(original_filename)
    stem = Path(safe_name).stem
    output_filename = f"{stem}{suffix}{extension}"
    return UPLOAD_FOLDER / output_filename


def load_json_from_upload(uploaded_file: FileStorage) -> Any:
    """Load JSON directly from the uploaded file stream."""
    try:
        return json.load(uploaded_file.stream)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON file: {exc}") from exc


def save_text_file(path: Path, content: str) -> None:
    """Persist text content using UTF-8 encoding."""
    path.write_text(content, encoding="utf-8")


def save_json_file(path: Path, data: Any) -> None:
    """Persist JSON output in a readable format."""
    path.write_text(
        json.dumps(data, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def is_reset_requested() -> bool:
    """Return True when the form checkbox requests clearing anonymization state."""
    return request.form.get("checkbox") == "checked"


def clear_anonymization_state_if_requested() -> None:
    """Clear global anonymization dictionaries when requested by the user."""
    if is_reset_requested():
        Functions.clear_dicts()
        current_app.logger.debug(
            "Anonymization dictionaries cleared. Current IPv4 dictionary size: %s",
            len(getattr(Functions, "ip_dictionary", {})),
        )


def anonymize_line_by_enabled_categories(line: str) -> str:
    """Apply only anonymization rules enabled in config.py to one log line."""
    anonymized_line = line

    for config_flag, anonymization_function in LINE_ANONYMIZATION_STEPS:
        if getattr(config, config_flag, False):
            anonymized_line = anonymization_function(anonymized_line)

    return anonymized_line


def anonymize_log_content_by_categories(content: str) -> str:
    """Anonymize raw .log content line by line using selected categories."""
    anonymized_lines = [
        anonymize_line_by_enabled_categories(line)
        for line in content.splitlines()
    ]

    return "\n".join(anonymized_lines) + "\n"


def html_pre_response(content: str) -> Response:
    """Return anonymized text safely wrapped in a HTML <pre> block."""
    return Response(f"<pre>{escape(content)}</pre>", mimetype="text/html")


# -----------------------------------------------------------------------------
# Routes: HTML forms
# -----------------------------------------------------------------------------

@app.route("/")
def upload_form() -> str:
    """Render form for anonymizing raw .log files."""
    return render_template("upload.html")


@app.route("/anonymize/json")
def json_form() -> str:
    """Render form for anonymizing JSON files."""
    return render_template("json.html")


@app.route("/anonymize/singlecategory")
def single_category_form() -> str:
    """Render form for anonymizing only selected categories."""
    return render_template("singlecat.html")


# -----------------------------------------------------------------------------
# Routes: anonymization endpoints
# -----------------------------------------------------------------------------

@app.route("/", methods=["POST"])
def upload_file() -> Response | tuple[str, int]:
    """
    Anonymize a raw .log file using the complete Regex anonymization pipeline.

    This endpoint preserves the original behavior of the root form: it accepts
    only .log files and returns the anonymized result inside a <pre> block.
    """
    try:
        uploaded_file = get_uploaded_file("file")

        if get_file_extension(uploaded_file) not in ALLOWED_LOG_EXTENSIONS:
            return "Error: Unsupported file type. Please upload a .log file.", 400

        anonymized_content = Regex.complete_anonymization(uploaded_file)

        output_path = get_safe_output_path(
            uploaded_file.filename,
            suffix="_anonymized",
            extension=".log",
        )
        save_text_file(output_path, anonymized_content)

        clear_anonymization_state_if_requested()
        return html_pre_response(anonymized_content)

    except ValueError as exc:
        return str(exc), 400


@app.route("/anonymize/json", methods=["POST"])
def anonymize_json_file() -> Response | tuple[str, int]:
    """
    Anonymize a JSON file according to the selected SIEM metadata configuration.
    """
    try:
        uploaded_file = get_uploaded_file("jsonfile")

        if get_file_extension(uploaded_file) not in ALLOWED_JSON_EXTENSIONS:
            return "Error: Unsupported file type. Please upload a .json file.", 400

        data = load_json_from_upload(uploaded_file)
        anonymized_data = Process.anonymize_data(data, METAK_KEY_CONFIGURATION)

        output_path = get_safe_output_path(
            uploaded_file.filename,
            suffix="_anonymized",
            extension=".json",
        )
        save_json_file(output_path, anonymized_data)

        clear_anonymization_state_if_requested()
        return jsonify(anonymized_data)

    except ValueError as exc:
        return str(exc), 400


@app.route("/anonymize/singlecategory", methods=["POST"])
def anonymize_single_category() -> Response | tuple[str, int]:
    """
    Anonymize either .log or .json input using selected anonymization categories.

    For .log files, enabled regex categories are applied line by line.
    For .json files, Process.anonymize_data_single_category is used.
    """
    try:
        uploaded_file = get_uploaded_file("file")
        file_extension = get_file_extension(uploaded_file)

        if file_extension in ALLOWED_LOG_EXTENSIONS:
            content = uploaded_file.read().decode("utf-8")
            anonymized_content = anonymize_log_content_by_categories(content)

            output_path = get_safe_output_path(
                uploaded_file.filename,
                suffix="_anonymized",
                extension=".log",
            )
            save_text_file(output_path, anonymized_content)

            clear_anonymization_state_if_requested()
            return html_pre_response(anonymized_content)

        if file_extension in ALLOWED_JSON_EXTENSIONS:
            data = load_json_from_upload(uploaded_file)
            anonymized_data = Process.anonymize_data_single_category(
                data,
                METAK_KEY_CONFIGURATION,
            )

            output_path = get_safe_output_path(
                uploaded_file.filename,
                suffix="_anonymized",
                extension=".json",
            )
            save_json_file(output_path, anonymized_data)

            clear_anonymization_state_if_requested()
            return jsonify(anonymized_data)

        return "Invalid file format. Please upload a .json or .log file.", 400

    except UnicodeDecodeError:
        return "Invalid text encoding. Please upload a UTF-8 encoded .log file.", 400
    except ValueError as exc:
        return str(exc), 400


if __name__ == "__main__":
    app.run(debug=True)
