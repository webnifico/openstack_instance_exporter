GO ?= go
PROMTOOL ?=
ANSIBLE_PYTHON ?= python3
export ANSIBLE_PYTHON
VERSION ?= v2.0.0
DIST_DIR ?= dist
FUZZTIME ?= 10s
COVERAGE_MIN ?= 85.0
SCALE_COUNT ?= 1
ALERT_EVALUATION_INTERVALS ?= 15s 30s 60s
ALERT_SCRAPE_INTERVALS ?= 15 30 60
ALERT_TIMEOUT ?= 3600

.PHONY: test coverage test-race test-shuffle vet staticcheck deadcode vuln fuzz contracts replay scale docs operator-test alert-test ansible-syntax ansible-render ansible-preflight ansible-test release release-validate release-reproducible check

test:
	PROMTOOL="$(PROMTOOL)" $(GO) test -count=1 ./...

coverage:
	GO="$(GO)" PROMTOOL="$(PROMTOOL)" COVERAGE_MIN="$(COVERAGE_MIN)" sh ./scripts/check-coverage.sh

test-race:
	PROMTOOL="$(PROMTOOL)" $(GO) test -race -count=1 ./...

test-shuffle:
	PROMTOOL="$(PROMTOOL)" $(GO) test -timeout=30m -shuffle=on -count=10 ./...

vet:
	$(GO) vet ./...

staticcheck:
	GOTOOLCHAIN=local $(GO) run honnef.co/go/tools/cmd/staticcheck@v0.8.2 ./...

deadcode:
	GO="$(GO)" sh ./scripts/check-deadcode.sh

vuln:
	GOTOOLCHAIN=local $(GO) run golang.org/x/vuln/cmd/govulncheck@v1.7.0 -show=version ./...

fuzz:
	$(GO) test -run='^$$' -fuzz=FuzzParseConntrackMessageLite -fuzztime=$(FUZZTIME) .
	$(GO) test -run='^$$' -fuzz=FuzzParseConntrackNetlinkDatagram -fuzztime=$(FUZZTIME) .

contracts:
	@test -n "$(PROMTOOL)" && test -x "$(PROMTOOL)" || { echo "PROMTOOL must name an executable for contract validation" >&2; exit 2; }
	PROMTOOL="$(PROMTOOL)" $(GO) test -count=1 -run='^(TestPrometheusAlertExpressionsWithPromtool|TestEveryGrafanaPromQLExpressionWithPromtool|TestAlertValidationEveryBundledAlertHasExecutableLifecycleFixture|TestReleasePublicInterfaces|TestOperationalConfiguration.*|TestDataIntegrityPrometheusEndToEndMetricContract|TestDataIntegrityCLIFlagContract|TestCompatibilityStructuredLogProductionCallsitesMatchExpected|TestDataIntegrityBehaviorStructuredEventContract|TestDataIntegrityMiningStructuredEventContract|TestDataIntegrityThreatStructuredEventContracts|TestThreatIntelligenceStructuredLogAdditionsContract|TestReleaseBuilderRemovesSameVersionStaleARMArtifactAndIsReproducible)$$' .

replay:
	@test -n "$(PROMTOOL)" && test -x "$(PROMTOOL)" || { echo "PROMTOOL must name an executable for replay validation" >&2; exit 2; }
	PROMTOOL="$(PROMTOOL)" $(GO) test -count=1 -run='^TestReplayCalibration' .

scale:
	$(GO) test -count=1 -run='^TestScaling' .
	$(GO) test -run='^$$' -bench='^BenchmarkScaling' -benchmem -benchtime=1x -count=$(SCALE_COUNT) .

docs:
	python3 scripts/check-docs.py
	@test -n "$(PROMTOOL)" && test -x "$(PROMTOOL)" || { echo "PROMTOOL must name an executable for dashboard and documentation" >&2; exit 2; }
	PROMTOOL="$(PROMTOOL)" $(GO) test -count=1 -run='^(TestDashboardDocumentation.*|TestOperationalConfiguration.*|TestEveryGrafana.*Promtool)$$' .

ansible-syntax:
	ANSIBLE_ROLES_PATH="$(CURDIR)/ansible_role" ansible-playbook ansible_role/openstack_instance_exporter/tests/syntax.yml --syntax-check
	ANSIBLE_ROLES_PATH="$(CURDIR)/ansible_role" ansible-playbook ansible_role/openstack_instance_exporter/tests/render.yml --syntax-check
	ANSIBLE_ROLES_PATH="$(CURDIR)/ansible_role" ansible-playbook ansible_role/openstack_instance_exporter/tests/preflight.yml --syntax-check

ansible-render:
	$(ANSIBLE_PYTHON) ansible_role/openstack_instance_exporter/tests/test_configuration.py
	$(ANSIBLE_PYTHON) ansible_role/openstack_instance_exporter/tests/render_test.py

ansible-preflight:
	ANSIBLE_ROLES_PATH="$(CURDIR)/ansible_role" ansible-playbook ansible_role/openstack_instance_exporter/tests/preflight.yml

ansible-test: ansible-syntax ansible-render

operator-test:
	$(ANSIBLE_PYTHON) integration_tests/oie_block_device_inventory_test.py
	$(ANSIBLE_PYTHON) integration_tests/oie_dashboard_startup_state_test.py
	$(ANSIBLE_PYTHON) integration_tests/oie_dashboard_presentation_test.py
	$(ANSIBLE_PYTHON) integration_tests/oie_dashboard_instance_language_test.py
	@test -n "$(PROMTOOL)" && test -x "$(PROMTOOL)" || { echo "PROMTOOL must name an executable for operator validation" >&2; exit 2; }
	PROMTOOL="$(PROMTOOL)" $(ANSIBLE_PYTHON) integration_tests/oie_dashboards_test.py
	PROMTOOL="$(PROMTOOL)" $(ANSIBLE_PYTHON) integration_tests/oie_dashboard_readability_test.py
	PROMTOOL="$(PROMTOOL)" $(ANSIBLE_PYTHON) integration_tests/oie_dashboard_overview_test.py
	PROMTOOL="$(PROMTOOL)" $(ANSIBLE_PYTHON) integration_tests/oie_dashboard_independence_test.py
	PROMTOOL="$(PROMTOOL)" $(ANSIBLE_PYTHON) integration_tests/oie_dashboard_empty_hosts_test.py
	PROMTOOL="$(PROMTOOL)" $(ANSIBLE_PYTHON) integration_tests/oie_dashboard_compact_views_test.py
	PROMTOOL="$(PROMTOOL)" $(ANSIBLE_PYTHON) integration_tests/oie_dashboard_ranking_test.py
	PROMTOOL="$(PROMTOOL)" $(ANSIBLE_PYTHON) integration_tests/oie_dashboard_scale_test.py
	PROMTOOL="$(PROMTOOL)" $(ANSIBLE_PYTHON) integration_tests/oie_dashboard_audit_test.py
	PROMTOOL="$(PROMTOOL)" $(ANSIBLE_PYTHON) integration_tests/oie_storage_latency_test.py
	PROMTOOL="$(PROMTOOL)" $(ANSIBLE_PYTHON) integration_tests/oie_alerts_test.py

alert-test:
	@test -n "$(PROMTOOL)" && test -x "$(PROMTOOL)" || { echo "PROMTOOL must name an executable for native alert validation" >&2; exit 2; }
	$(ANSIBLE_PYTHON) integration_tests/oie_alerts_verify.py --promtool "$(PROMTOOL)" --evaluation-intervals $(ALERT_EVALUATION_INTERVALS) --scrape-intervals $(ALERT_SCRAPE_INTERVALS) --timeout "$(ALERT_TIMEOUT)"

release:
	GO="$(GO)" ./scripts/build-release.sh "$(VERSION)" "$(DIST_DIR)"

release-validate:
	./scripts/validate-release.sh "$(VERSION)" "$(DIST_DIR)"

release-reproducible:
	GO="$(GO)" ./scripts/check-reproducible-release.sh "$(VERSION)"

check: vet staticcheck deadcode test coverage test-race test-shuffle fuzz contracts replay scale docs ansible-test ansible-preflight operator-test alert-test vuln release release-validate release-reproducible
