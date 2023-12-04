# build

FROM golang:1.21 AS builder
RUN mkdir -p /sources
WORKDIR /sources
COPY . .
RUN rm -rf /sources/bin
RUN mkdir -p /sources/bin

ENV GOOS=linux GOPATH=/go
RUN go build -o ./bin/server_bin ./cmd/server/main.go && \
    go build -o ./bin/client_bin .//cmd/client/main.go

# server side
FROM debian as server_merkle
ENV GOPATH=/go
ENV PATH=/go/bin:$PATH

COPY --from=builder /sources/bin/server_bin /go/bin/server_bin
COPY --from=builder /sources/data /data

ENTRYPOINT ["server_bin", "-data-folder=/data/", "-port=8080"]

# client side
FROM debian as client_merkle
ENV GOPATH=/go
ENV PATH=/go/gin:$PATH

COPY --from=builder /sources/bin/client_bin /go/bin/client_bin

ENTRYPOINT ["client_bin"]