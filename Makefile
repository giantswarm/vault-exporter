DOCKER_IMAGE_NAME ?= grapeshot/vault_exporter

vault-exporter:
	go build -o $@ ./

.uptodate: vault-exporter
	docker build -t $(DOCKER_IMAGE_NAME):$(shell git rev-parse --short HEAD) .

clean:
	rm -f vault_exporter .uptodate

lint:
	gometalinter --enable-all --vendor --deadline=5m

update-vendor:
	dep ensure
	dep prune
