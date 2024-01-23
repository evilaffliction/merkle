package main

import (
	"flag"
	"fmt"
	"net/http"

	"github.com/evilaffliction/merkle/pkg/middleware"
	"github.com/evilaffliction/merkle/pkg/rest"
)

const version = 0

type clientConfig struct {
	host      string
	port      int
	quotesNum int
}

func main() {
	var clientConfig clientConfig
	flag.StringVar(&clientConfig.host, "host", "localhost", "server's host")
	flag.IntVar(&clientConfig.port, "port", 8080, "server's port")
	flag.IntVar(&clientConfig.quotesNum, "n", 1, "quotes number to extract")
	flag.Parse()

	httpClient := &http.Client{}
	quoteURL := fmt.Sprintf("http://%s:%d/v%d/quote", clientConfig.host, clientConfig.port, version)

	for i := 0; i < clientConfig.quotesNum; i++ {
		merkleHeaderPayload, err := middleware.GenerateMerkleHeader(20, 5, "md5")
		if err != nil {
			panic(fmt.Errorf("failed to generate proof of work for a server, error: %w", err))
		}

		req, err := http.NewRequest("GET", quoteURL, nil)
		if err != nil {
			panic(fmt.Errorf("failed to create http request, error: %w", err))
		}
		req.Header.Set(middleware.MerkleHeaderName, merkleHeaderPayload)

		resp, err := httpClient.Do(req)
		if err != nil {
			panic(fmt.Errorf("failed to get a random quote from %q, error: %w", quoteURL, err))
		}

		var quote string
		if err := rest.ReadResponse(resp, &quote); err != nil {
			panic(fmt.Errorf("failed to read response, error: %w", err))
		}

		fmt.Printf("%v\n", quote)
	}
}
