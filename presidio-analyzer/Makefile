.DEFAULT_GOAL := help
.PHONY: help install install-gliner install-privacy-filter nlp-models run run-gliner run-privacy-filter docker-build docker-run docker-build-gliner docker-run-gliner docker-stop-gliner docker-build-privacy-filter docker-run-privacy-filter docker-stop-privacy-filter download-privacy-filter-model clean

IMAGE_GLINER          ?= presidio-analyzer-gliner:local
IMAGE_PRIVACY_FILTER  ?= presidio-analyzer-privacy-filter:local
IMAGE                 ?= presidio-analyzer:local
PORT                  ?= 3000
WORKERS               ?= 1
CONTAINER             ?= presidio-analyzer-gliner
CONTAINER_PRIVACY_FILTER ?= presidio-analyzer-privacy-filter
PRIVACY_FILTER_MODEL_PATH ?= $(PWD)/models/privacy-filter

help:
	@echo "Targets:"
	@echo "  install                       Install base + server deps via poetry"
	@echo "  install-gliner                Install with [gliner] extra and pinned runtime"
	@echo "  install-privacy-filter        Install runtime deps for privacy-filter profile (shares gliner extra)"
	@echo "  nlp-models                    Download spaCy model for GLiNER edge config"
	@echo "  download-privacy-filter-model Download OpenAI privacy-filter ONNX model into ./models/privacy-filter"
	@echo "  run                           Run analyzer locally (default config) via app.py"
	@echo "  run-gliner                    Run analyzer locally with GLiNER edge config"
	@echo "  run-privacy-filter            Run analyzer locally with privacy-filter config"
	@echo "  docker-build                  Build default analyzer image (Dockerfile)"
	@echo "  docker-run                    Run default analyzer image on PORT ($(PORT))"
	@echo "  docker-build-gliner           Build GLiNER edge image (Dockerfile.gliner-edge)"
	@echo "  docker-run-gliner             Run GLiNER edge image on PORT ($(PORT))"
	@echo "  docker-stop-gliner            Stop & remove the GLiNER edge container"
	@echo "  docker-build-privacy-filter   Build privacy-filter image (Dockerfile.privacy-filter)"
	@echo "  docker-run-privacy-filter     Run privacy-filter image on PORT ($(PORT)); mounts ./models/privacy-filter"
	@echo "  docker-stop-privacy-filter    Stop & remove the privacy-filter container"
	@echo "  clean                         Remove Python caches"

install:
	poetry install -E server

install-gliner:
	poetry install -E server -E gliner
	poetry run pip install "gliner==0.2.24" "onnxruntime==1.23.2"

install-privacy-filter: install-gliner

nlp-models:
	@if poetry run python -c "import en_core_web_lg" >/dev/null 2>&1; then \
	  echo "spaCy model en_core_web_lg already installed; skipping download."; \
	else \
	  poetry run python install_nlp_models.py --conf_file presidio_analyzer/conf/gliner_edge_nlp.yaml; \
	fi

download-privacy-filter-model:
	PRIVACY_FILTER_MODEL_PATH="$(PRIVACY_FILTER_MODEL_PATH)" ./scripts/download_privacy_filter_model.sh

run:
	PORT=$(PORT) WORKERS=$(WORKERS) poetry run python app.py

run-gliner: install-gliner nlp-models
	PORT=$(PORT) WORKERS=$(WORKERS) ./scripts/run_gliner_edge.sh

run-privacy-filter: install-privacy-filter nlp-models download-privacy-filter-model
	PORT=$(PORT) WORKERS=$(WORKERS) PRIVACY_FILTER_MODEL_PATH="$(PRIVACY_FILTER_MODEL_PATH)" ./scripts/run_privacy_filter.sh

docker-build:
	docker build -f Dockerfile -t $(IMAGE) .

docker-run:
	docker run --rm -p $(PORT):$(PORT) -e PORT=$(PORT) -e WORKERS=$(WORKERS) --name presidio-analyzer $(IMAGE)

docker-build-gliner:
	docker build -f Dockerfile.gliner-edge -t $(IMAGE_GLINER) .

docker-run-gliner:
	docker run --rm -p $(PORT):$(PORT) -e PORT=$(PORT) -e WORKERS=$(WORKERS) --name $(CONTAINER) $(IMAGE_GLINER)

docker-stop-gliner:
	-docker stop $(CONTAINER)

docker-build-privacy-filter:
	docker build -f Dockerfile.privacy-filter -t $(IMAGE_PRIVACY_FILTER) .

docker-run-privacy-filter:
	docker run --rm -p $(PORT):$(PORT) \
	  -e PORT=$(PORT) -e WORKERS=$(WORKERS) \
	  -e PRIVACY_FILTER_MODEL_PATH=/models/privacy-filter \
	  -v "$(PRIVACY_FILTER_MODEL_PATH)":/models/privacy-filter:ro \
	  --name $(CONTAINER_PRIVACY_FILTER) $(IMAGE_PRIVACY_FILTER)

docker-stop-privacy-filter:
	-docker stop $(CONTAINER_PRIVACY_FILTER)

clean:
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	find . -type d -name .pytest_cache -prune -exec rm -rf {} +
