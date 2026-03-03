"""REST API server for analyzer."""

import json
import logging
import os
from logging.config import fileConfig
from pathlib import Path
from typing import Tuple

from flask import Flask, Response, jsonify, request
from presidio_analyzer import (
    AnalyzerEngine,
    AnalyzerEngineProvider,
    AnalyzerRequest,
    BatchAnalyzerEngine,
)
from werkzeug.exceptions import HTTPException

from clawdefender import (
    validate_input as claw_validate,
    validate_url as claw_validate_url,
    sanitize as claw_sanitize,
)

DEFAULT_PORT = "3000"
DEFAULT_BATCH_SIZE = "500"
DEFAULT_N_PROCESS = "1"

LOGGING_CONF_FILE = "logging.ini"

WELCOME_MESSAGE = r"""
 _______  _______  _______  _______ _________ ______  _________ _______
(  ____ )(  ____ )(  ____ \(  ____ \\__   __/(  __  \ \__   __/(  ___  )
| (    )|| (    )|| (    \/| (    \/   ) (   | (  \  )   ) (   | (   ) |
| (____)|| (____)|| (__    | (_____    | |   | |   ) |   | |   | |   | |
|  _____)|     __)|  __)   (_____  )   | |   | |   | |   | |   | |   | |
| (      | (\ (   | (            ) |   | |   | |   ) |   | |   | |   | |
| )      | ) \ \__| (____/\/\____) |___) (___| (__/  )___) (___| (___) |
|/       |/   \__/(_______/\_______)\_______/(______/ \_______/(_______)
"""


class Server:
    """HTTP Server for calling Presidio Analyzer."""

    MAX_INPUT_LENGTH = 100_000  # 100KB per text item
    MAX_FILES_PER_SCAN = 50
    MAX_TOTAL_PAYLOAD = 5 * 1024 * 1024  # 5MB
    MAX_FILENAME_LENGTH = 255

    VALID_CHECK_TYPES = {"validate", "url"}

    def __init__(self):
        fileConfig(Path(Path(__file__).parent, LOGGING_CONF_FILE))
        self.logger = logging.getLogger("presidio-analyzer")
        self.logger.setLevel(os.environ.get("LOG_LEVEL", self.logger.level))
        self.app = Flask(__name__)

        analyzer_conf_file = os.environ.get("ANALYZER_CONF_FILE")
        nlp_engine_conf_file = os.environ.get("NLP_CONF_FILE")
        recognizer_registry_conf_file = os.environ.get("RECOGNIZER_REGISTRY_CONF_FILE")

        self.logger.info("Starting analyzer engine")
        self.engine: AnalyzerEngine = AnalyzerEngineProvider(
            analyzer_engine_conf_file=analyzer_conf_file,
            nlp_engine_conf_file=nlp_engine_conf_file,
            recognizer_registry_conf_file=recognizer_registry_conf_file,
        ).create_engine()

        self.batch_engine = BatchAnalyzerEngine(self.engine)
        self.logger.info(WELCOME_MESSAGE)

        @self.app.route("/health")
        def health() -> str:
            """Return basic health probe result."""
            return "Presidio Analyzer service is up"

        @self.app.route("/analyze", methods=["POST"])
        def analyze() -> Tuple[str, int]:
            """Execute the analyzer function."""
            # Parse the request params
            try:
                req_data = AnalyzerRequest(request.get_json())
                if not req_data.text:
                    raise Exception("No text provided")

                batch_request = isinstance(req_data.text, list)
                batch = req_data.text if batch_request else [req_data.text]

                if not req_data.language:
                    raise Exception("No language provided")
                else:
                    # Make sure the language is supported by the engine.
                    self.engine.get_supported_entities(req_data.language)

                iterator = self.batch_engine.analyze_iterator(
                    texts=batch,
                    batch_size=min(
                        len(batch),
                        int(os.environ.get("BATCH_SIZE", DEFAULT_BATCH_SIZE))
                    ),
                    language=req_data.language,
                    correlation_id=req_data.correlation_id,
                    score_threshold=req_data.score_threshold,
                    entities=req_data.entities,
                    return_decision_process=req_data.return_decision_process,
                    ad_hoc_recognizers=req_data.ad_hoc_recognizers,
                    context=req_data.context,
                    allow_list=req_data.allow_list,
                    allow_list_match=req_data.allow_list_match,
                    regex_flags=req_data.regex_flags,
                    n_process=min(
                        len(batch),
                        int(os.environ.get("N_PROCESS", DEFAULT_N_PROCESS))
                    )
                )
                results = []
                for recognizer_result_list in iterator:
                    _exclude_attributes_from_dto(recognizer_result_list)
                    results.append(recognizer_result_list)

                return Response(
                    json.dumps(
                        results if batch_request else results[0],
                        default=lambda o: o.to_dict(),
                        sort_keys=True,
                    ),
                    content_type="application/json",
                )
            except TypeError as te:
                error_msg = (
                    f"Failed to parse /analyze request "
                    f"for AnalyzerEngine.analyze(). {te.args[0]}"
                )
                self.logger.error(error_msg)
                return jsonify(error=error_msg), 400

            except Exception as e:
                self.logger.error(
                    f"A fatal error occurred during execution of "
                    f"AnalyzerEngine.analyze(). {e}"
                )
                return jsonify(error=e.args[0]), 500

        @self.app.route("/recognizers", methods=["GET"])
        def recognizers() -> Tuple[str, int]:
            """Return a list of supported recognizers."""
            language = request.args.get("language")
            try:
                recognizers_list = self.engine.get_recognizers(language)
                names = [o.name for o in recognizers_list]
                return jsonify(names), 200
            except Exception as e:
                self.logger.error(
                    f"A fatal error occurred during execution of "
                    f"AnalyzerEngine.get_recognizers(). {e}"
                )
                return jsonify(error=e.args[0]), 500

        @self.app.route("/supportedentities", methods=["GET"])
        def supported_entities() -> Tuple[str, int]:
            """Return a list of supported entities."""
            language = request.args.get("language")
            try:
                entities_list = self.engine.get_supported_entities(language)
                return jsonify(entities_list), 200
            except Exception as e:
                self.logger.error(
                    f"A fatal error occurred during execution of "
                    f"AnalyzerEngine.supported_entities(). {e}"
                )
                return jsonify(error=e.args[0]), 500

        @self.app.route("/defender/detect", methods=["POST"])
        def detect() -> Tuple[str, int]:
            """Detect malicious content using ClawDefender."""
            try:
                req_data = request.get_json()
                if not req_data or "text" not in req_data:
                    return jsonify(error="No text provided"), 400

                check_type = req_data.get("check_type", "validate")
                if check_type not in self.VALID_CHECK_TYPES:
                    return jsonify(
                        error=f"Invalid check_type. Must be one of: "
                              f"{', '.join(sorted(self.VALID_CHECK_TYPES))}"
                    ), 400

                text = req_data["text"]
                batch_request = isinstance(text, list)
                texts = text if batch_request else [text]

                results = []
                for item in texts:
                    try:
                        item = self._validate_input_text(item)
                    except ValueError as ve:
                        return jsonify(error=str(ve)), 400

                    if check_type == "url":
                        findings = claw_validate_url(item)
                        if not findings:
                            result = {"clean": True, "severity": "clean",
                                      "score": 0, "action": "allow"}
                        else:
                            max_score = max(f.score for f in findings)
                            result = {"clean": False, "severity": "critical",
                                      "score": max_score, "action": "block"}
                    else:
                        scan = claw_validate(item)
                        result = scan.to_dict()
                        result.pop("findings", None)

                    result["text"] = item
                    results.append(result)

                return jsonify(results if batch_request else results[0]), 200

            except Exception as e:
                self.logger.error(f"Error in /detect: {e}")
                return jsonify(error=str(e)), 400

        @self.app.route("/defender/sanitize", methods=["POST"])
        def sanitize() -> Tuple[str, int]:
            """Sanitize input text using ClawDefender."""
            try:
                req_data = request.get_json()
                if not req_data or "text" not in req_data:
                    return jsonify(error="No text provided"), 400

                text = req_data["text"]
                batch_request = isinstance(text, list)
                texts = text if batch_request else [text]

                results = []
                for item in texts:
                    try:
                        item = self._validate_input_text(item)
                    except ValueError as ve:
                        return jsonify(error=str(ve)), 400
                    san_result = claw_sanitize(item)
                    result = {
                        "text": item,
                        "sanitized": san_result.output,
                        "flagged": san_result.flagged,
                    }
                    results.append(result)

                return jsonify(results if batch_request else results[0]), 200

            except Exception as e:
                self.logger.error(f"Error in /sanitize: {e}")
                return jsonify(error=str(e)), 400

        @self.app.route("/defender/scan", methods=["POST"])
        def scan() -> Tuple[str, int]:
            """Scan file contents for malicious content."""
            try:
                req_data = request.get_json()
                error = self._validate_scan_request(req_data)
                if error:
                    return jsonify(error=error), 400

                files = req_data["files"]
                file_results = []
                any_flagged = False

                for file_entry in files:
                    filename = file_entry["filename"]
                    content = file_entry["content"]

                    scan_result = claw_validate(content)
                    result_dict = scan_result.to_dict()
                    result_dict["filename"] = filename
                    file_results.append(result_dict)

                    if not scan_result.clean:
                        any_flagged = True

                clean_count = sum(1 for r in file_results if r["clean"])
                response = {
                    "clean": not any_flagged,
                    "summary": {
                        "total_files": len(files),
                        "clean_files": clean_count,
                        "flagged_files": len(files) - clean_count,
                    },
                    "results": file_results,
                }
                return jsonify(response), 200

            except Exception as e:
                self.logger.error(f"Error in /defender/scan: {e}")
                return jsonify(error=str(e)), 400

        @self.app.errorhandler(HTTPException)
        def http_exception(e):
            return jsonify(error=e.description), e.code

    def _validate_scan_request(self, req_data) -> str | None:
        """Validate a /defender/scan request. Returns error string or None."""
        if not req_data or "files" not in req_data:
            return "Missing 'files' field"

        files = req_data["files"]
        if not isinstance(files, list) or len(files) == 0:
            return "'files' must be a non-empty list"

        if len(files) > self.MAX_FILES_PER_SCAN:
            return (
                f"Too many files. Maximum is {self.MAX_FILES_PER_SCAN}, "
                f"got {len(files)}"
            )

        total_size = 0
        for i, entry in enumerate(files):
            if not isinstance(entry, dict):
                return f"File entry at index {i} must be an object"
            if "filename" not in entry or "content" not in entry:
                return (
                    f"File entry at index {i} must have "
                    f"'filename' and 'content' fields"
                )
            filename = entry["filename"]
            content = entry["content"]

            if not isinstance(filename, str) or len(filename) == 0:
                return f"Filename at index {i} must be a non-empty string"
            if len(filename) > self.MAX_FILENAME_LENGTH:
                return (
                    f"Filename at index {i} exceeds maximum length of "
                    f"{self.MAX_FILENAME_LENGTH} characters"
                )
            if not isinstance(content, str):
                return f"Content at index {i} must be a string"
            if len(content) > self.MAX_INPUT_LENGTH:
                return (
                    f"Content of file '{filename}' exceeds maximum length "
                    f"of {self.MAX_INPUT_LENGTH} characters"
                )
            total_size += len(content.encode("utf-8"))

        if total_size > self.MAX_TOTAL_PAYLOAD:
            return (
                f"Total payload size exceeds maximum of "
                f"{self.MAX_TOTAL_PAYLOAD} bytes"
            )

        return None

    def _validate_input_text(self, text: str) -> str:
        """Validate and sanitize input text."""
        if not isinstance(text, str):
            raise ValueError("Each text item must be a string")
        if len(text) > self.MAX_INPUT_LENGTH:
            raise ValueError(
                f"Text exceeds maximum length of {self.MAX_INPUT_LENGTH} characters"
            )
        return text


def _exclude_attributes_from_dto(recognizer_result_list):
    excluded_attributes = [
        "recognition_metadata",
    ]
    for result in recognizer_result_list:
        for attr in excluded_attributes:
            if hasattr(result, attr):
                delattr(result, attr)


def create_app():  # noqa: D103
    server = Server()
    return server.app


if __name__ == "__main__":
    app = create_app()
    port = int(os.environ.get("PORT", DEFAULT_PORT))
    app.run(host="0.0.0.0", port=port)
