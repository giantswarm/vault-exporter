DOCKER_IMAGE_NAME ?= grapeshot/vault_exporter
VERSION ?= $(shell git describe --tags)

vault_exporter: main.go
	go build -ldflags "-X main.exporterVersion=$(VERSION)" -o $@ ./

.uptodate: vault_exporter Dockerfile
	docker build -t $(DOCKER_IMAGE_NAME):$(VERSION) .

clean:
	rm -f vault_exporter .uptodate

lint:
	gometalinter --enable-all --vendor --deadline=5m

update-vendor:
	dep ensure
	dep prune
