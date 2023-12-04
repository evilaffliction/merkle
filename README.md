

# General info
This small repo brings client(prover) <-> server(verifier) communication that is burdended with proof of work on the client's side.
In order to get any useful quote a client should provide proof of work, that should be hard to build on a prover's side, but should be easy to verify on a verifier's side.

The communication is implemented by the HTTP protocol, where a verifier is a web server and a prover is a web client

# TLDR
To start a server one should a command below.
It will start a docker container for a server with portforwarding 8080 port
> `make run_server`

To run a client one should run a command below.
It will execute binary (without docker due to the author didn't have enough time for a docker-compose version) for a client to get exactly 1 wisdom quote.
> `make run_client`

# Other commands
This command builds binary in the `bin` subfolder
> `make build`

This command builds docker images `server_merkle` and `client_merkle`
> `make docker`

Other useful commands
> `make test`
> `make bench`
> `make lint`
> `make fmt`

# Choose of Proof Of Work algorithm
The following algorithms were taken under consideration:

- HashCash
- Hokkaido
- Mekle tree
- Fiat–Shamir

HashCash is a quite primitive algo that doesn't allow you to specify expected volume of work from a prover. Neither by cpu, nor by memory

Hokkaido is quite complex memory based proof of work with no or little customization by CPU load. And it's quite unpopular since no other mentions of this algo were found by simple googling

Fiat-Shamir is badly formulated and also seems to be quite old

Merkle tree looks complex, yet a good explanation is provided by the authors of the algo. Customization by CPU (merkle trees' depth) and slightly by network volume (proof leaves number) is in place that makes this algo to be agile. Also freedom of choice of a hash/crypto function available for it by allowing any robust generic algorithm to be used in the merkle build process.

# Way of communication
There were 2 options for choosing communication between a client a server:
1. A server generates a task that should be solved by a client. A client then sends the solved task in order to make server execute some computation.
2. A client commits for a task on his own and provides a proof of work to a server
For the sake of simplicity of client <-> server communication the option #2 was choosen.

Client generates an access token that consists of 2 values
1. Current time stamp in micros
2. An arbitrary string value of 16 bytes length
An example of access token:
```
type accessToken struct {
    TimeStampMicros int64
    Value           string
}
newToken := accessToken {
    TimeStampMicros: time.Now().UnixMicro(),
    Value:                   "abracadabra",
}
```
An access token with an age more than 5 seconds won't be accepted by a server. That will eliminate possibility of using old access tokent.
A string value is used like unique cache value. 2 access tokens with the same value string won't be accepted by a server. That a token can't be used to get resource from a server several times.
Sever has time cache of recently used access tokens and keeps track of them for a minute interval.

This access token is used to customize any generic hash function in order to guarantee uniqueness of a generated merkle tree.

# Technical part of verification
Any of client's requests should contain `MerkleHeaderName` http header with serialized proof of work. Without it a job won't be accepted
