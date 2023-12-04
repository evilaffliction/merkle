.PHONY: all
all: build

.PHONY: fmt
fmt:
	gofmt -w -s -l .
	goimports -local pow/ -w -l .

.PHONY: lint
lint:
	golint -set_exit_status ./...

.PHONY: build
build:
	mkdir -p ./bin
	go build -o ./bin/server cmd/server/main.go
	go build -o ./bin/client cmd/client/main.go

.PHONY: test
test:
	go test -v ./...

.PHONY: bench
bench:
	go test -v ./... -bench=. -run=xxx

.PHONY: docker
docker:
	docker build -t server_merkle --target server_merkle .
	docker build -t client_merkle --target client_merkle .

.PHONY: run_server
run_server: docker
	docker run --rm -p 8080:8080 server_merkle

.PHONY: run_client
run_client: build
	./bin/client