// Package fofa logic
package fofa

import (
	"context"
	"encoding/base64"
	"fmt"
	"github.com/projectdiscovery/gologger"
	"strings"
	"time"

	jsoniter "github.com/json-iterator/go"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

type fofaResponse struct {
	Error   bool     `json:"error"`
	ErrMsg  string   `json:"errmsg"`
	Size    int      `json:"size"`
	Results []string `json:"results"`
}

// Source is the passive scraping agent
type Source struct {
	apiKeys   []apiKey
	timeTaken time.Duration
	errors    int
	results   int
	skipped   bool
}

type apiKey struct {
	username string
	secret   string
}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)
	s.errors = 0
	s.results = 0

	go func() {
		defer func(startTime time.Time) {
			s.timeTaken = time.Since(startTime)
			close(results)
		}(time.Now())

		randomApiKey := subscraping.PickRandom(s.apiKeys, s.Name())
		if randomApiKey.username == "" || randomApiKey.secret == "" {
			s.skipped = true
			return
		}

		// fofa api doc https://fofa.info/static_pages/api_help
		var pages = 1
		var pageSize = 1000
		for currentPage := 1; currentPage <= pages; currentPage++ {
			gologger.Debug().Msgf("Querying %s for %s, currentPage:%d allPage:%d", s.Name(), domain, currentPage, pages)

			qbase64 := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("domain=\"%s\"", domain)))
			resp, err := session.SimpleGet(ctx, fmt.Sprintf("https://fofa.info/api/v1/search/all?full=true&fields=host&page=%d&size=%d&email=%s&key=%s&qbase64=%s", currentPage, pageSize, randomApiKey.username, randomApiKey.secret, qbase64))
			if err != nil && resp == nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				s.errors++
				session.DiscardHTTPResponse(resp)
				return
			}

			var response fofaResponse
			err = jsoniter.NewDecoder(resp.Body).Decode(&response)
			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				s.errors++
				resp.Body.Close()
				return
			}
			resp.Body.Close()

			if response.Error {
				results <- subscraping.Result{
					Source: s.Name(), Type: subscraping.Error, Error: fmt.Errorf("%s", response.ErrMsg),
				}
				s.errors++
				return
			}

			if response.Size > 0 {
				for _, subdomain := range response.Results {
					if strings.HasPrefix(strings.ToLower(subdomain), "http://") || strings.HasPrefix(strings.ToLower(subdomain), "https://") {
						subdomain = subdomain[strings.Index(subdomain, "//")+2:]
					}
					results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: subdomain}
					s.results++
				}
				pages = int(response.Size/pageSize) + 1
			}
		}

	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "fofa"
}

func (s *Source) IsDefault() bool {
	return true
}

func (s *Source) HasRecursiveSupport() bool {
	return false
}

func (s *Source) NeedsKey() bool {
	return true
}

func (s *Source) AddApiKeys(keys []string) {
	s.apiKeys = subscraping.CreateApiKeys(keys, func(k, v string) apiKey {
		return apiKey{k, v}
	})
}

func (s *Source) Statistics() subscraping.Statistics {
	return subscraping.Statistics{
		Errors:    s.errors,
		Results:   s.results,
		TimeTaken: s.timeTaken,
		Skipped:   s.skipped,
	}
}
