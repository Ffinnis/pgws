.PHONY: build test integration physical-lab zfs-lab host-lab sdk-test classifier-lab classifier-resources check dev-up dev-down dev-status dev-upgrade dev-upgrade-check
build:
	mkdir -p bin
	go build -o bin/pgwsd ./cmd/pgwsd
	go build -o bin/pgws ./cmd/pgws
	go build -o bin/pgws-physical ./cmd/pgws-physical
	go build -o bin/pgws-logical ./cmd/pgws-logical
	go build -o bin/pgws-logical-watchdog ./cmd/pgws-logical-watchdog
	go build -o bin/pgws-discover ./cmd/pgws-discover
	go build -o bin/pgws-features ./cmd/pgws-features
	go build -o bin/pgws-classify ./cmd/pgws-classify
	go build -o bin/pgws-model-pack ./cmd/pgws-model-pack
	go build -o bin/pgws-host ./cmd/pgws-host
	go build -o bin/pgws-guard ./cmd/pgws-guard
	go build -o bin/pgws-watchdog ./cmd/pgws-watchdog
test:
	go test -race ./...
integration:
	python3 scripts/integration.py
physical-lab:
	python3 scripts/physical_lab.py
sdk-test:
	python3 -m unittest discover -s sdk/python
	npm test --prefix sdk/typescript
check: test sdk-test
	go vet ./...
	python3 -m unittest discover -s lab

zfs-lab:
	python3 scripts/zfs_lab.py
host-lab:
	python3 scripts/host_lab.py

dev-up:
	python3 scripts/dev.py up
dev-down:
	python3 scripts/dev.py down
dev-status:
	python3 scripts/dev.py status
dev-upgrade:
	python3 scripts/dev.py upgrade
dev-upgrade-check:
	python3 scripts/dev_upgrade_check.py

CLASSIFIER_PYTHON ?= .local/classifier-venv/bin/python
classifier-lab:
	$(CLASSIFIER_PYTHON) ml/column-classifier/smoke.py

classifier-resources:
	python3 scripts/classifier_resources.py
