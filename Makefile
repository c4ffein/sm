.PHONY: help lint lint-check test install-build-system build-package install-package-uploader upload-package-test upload-package

help:
	@echo "sm - Makefile commands"
	@echo "────────────────────────────────────"
	@echo "  make lint              - Fix linting issues with ruff"
	@echo "  make lint-check        - Check linting without fixing"
	@echo "  make test              - Run tests"
	@echo "  make install-build-system   - Install build tools"
	@echo "  make build-package     - Build source distribution"
	@echo "  make install-package-uploader - Install twine for uploading"
	@echo "  make upload-package-test - Upload to TestPyPI"
	@echo "  make upload-package    - Upload to PyPI"

lint:
	ruff check --fix; ruff format

lint-check:
	ruff check --no-fix && ruff format --check

test:
	python3 test.py

install-build-system:
	python3 -m pip install --upgrade build

build-package:
	python3 -m build --sdist

install-package-uploader:
	python3 -m pip install --upgrade twine

upload-package-test:
	python3 -m twine upload --repository testpypi --verbose dist/*

upload-package:
	python3 -m twine upload --verbose dist/*
