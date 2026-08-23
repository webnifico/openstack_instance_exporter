GO ?= go
PROMTOOL ?=
ANSIBLE_PYTHON ?= python3
VERSION ?= v1.3.0
DIST_DIR ?= dist
FUZZTIME ?= 10s
COVERAGE_MIN ?= 85.0

.PHONY: test coverage test-race test-shuffle vet fuzz ansible-syntax ansible-render ansible-test release check

test:
	PROMTOOL="$(PROMTOOL)" $(GO) test -count=1 ./...

coverage:
	GO="$(GO)" PROMTOOL="$(PROMTOOL)" COVERAGE_MIN="$(COVERAGE_MIN)" sh ./scripts/check-coverage.sh

test-race:
	PROMTOOL="$(PROMTOOL)" $(GO) test -race -count=1 ./...

test-shuffle:
	PROMTOOL="$(PROMTOOL)" $(GO) test -shuffle=on -count=10 ./...

vet:
	$(GO) vet ./...

fuzz:
	$(GO) test -run='^$$' -fuzz=FuzzParseConntrackMessageLite -fuzztime=$(FUZZTIME) .
	$(GO) test -run='^$$' -fuzz=FuzzParseConntrackNetlinkDatagram -fuzztime=$(FUZZTIME) .

ansible-syntax:
	ANSIBLE_ROLES_PATH="$(CURDIR)/ansible_role" ansible-playbook ansible_role/openstack_instance_exporter/tests/syntax.yml --syntax-check
	ANSIBLE_ROLES_PATH="$(CURDIR)/ansible_role" ansible-playbook ansible_role/openstack_instance_exporter/tests/render.yml --syntax-check

ansible-render:
	$(ANSIBLE_PYTHON) ansible_role/openstack_instance_exporter/tests/render_test.py

ansible-test: ansible-syntax ansible-render

release:
	GO="$(GO)" ./scripts/build-release.sh "$(VERSION)" "$(DIST_DIR)"

check: vet test coverage test-race test-shuffle fuzz ansible-test release
