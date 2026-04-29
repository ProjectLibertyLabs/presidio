#!/usr/bin/env bash
set -euo pipefail

MODEL_ID="${PRIVACY_FILTER_MODEL_ID:-openai/privacy-filter}"
MODEL_DIR="${PRIVACY_FILTER_MODEL_PATH:-models/privacy-filter}"
MARKER="${MODEL_DIR}/.download_complete"

if [[ -f "$MARKER" ]]; then
  echo "Model already present at ${MODEL_DIR} (marker ${MARKER}); skipping download."
  exit 0
fi

# Partial / aborted previous download — wipe it so snapshot_download starts clean.
if [[ -d "$MODEL_DIR" ]]; then
  echo "Found ${MODEL_DIR} without completion marker; removing stale contents."
  rm -rf "$MODEL_DIR"
fi

# Resolve a Python that has huggingface_hub installed. Order:
#   1. $PYTHON_BIN if set
#   2. ./.venv/bin/python (project-local venv, used inside Docker)
#   3. `poetry run python` (local dev with poetry-managed venv)
#   4. python3 (last resort; assumes huggingface_hub is on the system path)
RUN_PY=()
if [[ -n "${PYTHON_BIN:-}" ]]; then
  RUN_PY=("$PYTHON_BIN")
elif [[ -x ".venv/bin/python" ]]; then
  RUN_PY=(".venv/bin/python")
elif command -v poetry >/dev/null 2>&1 && [[ -f "pyproject.toml" ]]; then
  RUN_PY=(poetry run python)
else
  RUN_PY=(python3)
fi

"${RUN_PY[@]}" - "$MODEL_ID" "$MODEL_DIR" <<'PY'
import os
import shutil
import sys
from pathlib import Path

from huggingface_hub import snapshot_download

model_id = sys.argv[1]
model_dir = Path(sys.argv[2])
token = os.environ.get("HF_TOKEN") or os.environ.get("HUGGINGFACE_HUB_TOKEN")

snapshot_download(
    repo_id=model_id,
    local_dir=str(model_dir),
    token=token,
    allow_patterns=[
        "onnx/model_q4.onnx",
        "onnx/model_q4.onnx_data",
        "config.json",
        "tokenizer.json",
        "tokenizer_config.json",
    ],
)

# onnxruntime resolves the external-tensor *.onnx_data file relative to the
# .onnx file's directory, so flatten the onnx/ subfolder into the model root
# (where AutoTokenizer/AutoConfig also expect tokenizer/config.json to live).
for name in ("model_q4.onnx", "model_q4.onnx_data"):
    src = model_dir / "onnx" / name
    dst = model_dir / name
    if src.exists() and not dst.exists():
        shutil.copy2(src, dst)

print(f"Model files ready at {model_dir}")
PY

mkdir -p "$MODEL_DIR"
: > "$MARKER"
echo "Wrote completion marker ${MARKER}."
