#!/usr/bin/env bash
set -euo pipefail

# Capture the directory where THIS script is located
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)

# Now use that variable to navigate relatively
cd "$SCRIPT_DIR/../"

export ANALYZER_CONF_FILE=presidio_analyzer/conf/gliner_edge_analyzer.yaml
export NLP_CONF_FILE=presidio_analyzer/conf/gliner_edge_nlp.yaml
export RECOGNIZER_REGISTRY_CONF_FILE=presidio_analyzer/conf/gliner_edge_recognizers.yaml
export PORT="${PORT:-3000}"
export WORKERS="${WORKERS:-1}"

poetry run python app.py
