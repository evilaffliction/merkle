package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/evilaffliction/merkle/pkg/middleware"
	"github.com/evilaffliction/merkle/pkg/quote"
	"github.com/evilaffliction/merkle/pkg/rest"
)

const version = 0

type serverConfig struct {
	dataFolder string
	port       int
}

func main() {
	// args parsing and preparing config
	var serverConfig serverConfig
	flag.StringVar(&serverConfig.dataFolder, "data-folder", "/data/", "folder with quotes to be served")
	flag.IntVar(&serverConfig.port, "port", 8080, "port at which requests will be served")
	flag.Parse()
	fmt.Printf("server config: %v\n", serverConfig)

	// building quote manager that will contain all the data
	var quoteManager quote.Manager
	quoteManager = quote.NewInMemoryManagerImpl(time.Now().Unix())

	// reading all files from a data folder
	files, err := ioutil.ReadDir(serverConfig.dataFolder)
	if err != nil {
		panic(fmt.Errorf("failed to open data folder with quotes, error: %w", err))
	}
	for _, file := range files {
		if file.IsDir() {
			// TODO: add subdir reading
			continue
		}
		fullPath := filepath.Join(serverConfig.dataFolder, file.Name())
		data, err := os.ReadFile(fullPath)
		if err != nil {
			panic(fmt.Errorf("failed to open file %q for reading, error: %w", fullPath, err))
		}
		quoteManager.LoadQuotesFromText(data, []byte{'\n'})
	}

	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(middleware.GetMerkleMiddlware())

	getRandomQuote := func(_ *gin.Context) (any, error) {
		return quoteManager.GetRandomQuote()
	}

	r.GET(fmt.Sprintf("/v%d/quote", version), rest.EndpointWrapper(getRandomQuote))
	r.Run(fmt.Sprintf(":%d", serverConfig.port))
}
