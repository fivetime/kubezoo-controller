SHELL := bash

GO ?= go
TARGET ?= kubezoo-controller
ENVTEST_K8S_VERSION ?= 1.36.x
SETUP_ENVTEST_VERSION ?= release-0.24

.DEFAULT_GOAL := build

.PHONY: build
build:
	@$(GO) build -o _output/local/bin/$(TARGET) ./cmd/kubezoo-controller

.PHONY: test-unit
test-unit:
	@$(GO) test $$(go list ./... | grep -v '/pkg/controller$$')

.PHONY: envtest
envtest:
	@GOBIN="$(CURDIR)/bin" $(GO) install sigs.k8s.io/controller-runtime/tools/setup-envtest@$(SETUP_ENVTEST_VERSION)

# The controller's tests run against a real apiserver: what they check is what
# it writes into one, and a fake would only confirm the code calls the functions
# it calls. -count=1 because the answer depends on the envtest binaries too.
.PHONY: test-integration
test-integration: envtest
	@KUBEBUILDER_ASSETS="$$($(CURDIR)/bin/setup-envtest use $(ENVTEST_K8S_VERSION) -p path)" \
		$(GO) test -count=1 ./pkg/controller

.PHONY: test
test: test-unit test-integration

IMAGE_REPO ?= ghcr.io/fivetime
IMAGE_TAG ?= $(shell git describe --tags --always --dirty)
TARGET_PLATFORMS ?= linux/amd64

.PHONY: docker-build
docker-build:
	@docker buildx build --load --platform $(TARGET_PLATFORMS) \
		-f build/kubezoo-controller.Dockerfile \
		-t $(IMAGE_REPO)/kubezoo-controller:$(IMAGE_TAG) .
