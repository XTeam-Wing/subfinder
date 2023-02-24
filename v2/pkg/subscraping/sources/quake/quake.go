// Package quake logic
package quake

import (
	"bytes"
	"context"
	"fmt"
	"github.com/projectdiscovery/gologger"
	"strings"
	"time"

	jsoniter "github.com/json-iterator/go"

	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

type quakeResults struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    []struct {
		Service struct {
			HTTP struct {
				Host string `json:"host"`
			} `json:"http"`
		}
	} `json:"data"`
	Meta struct {
		Pagination struct {
			Total int `json:"total"`
		} `json:"pagination"`
	} `json:"meta"`
}

// Source is the passive scraping agent
type Source struct {
	apiKeys   []string
	timeTaken time.Duration
	errors    int
	results   int
	skipped   bool
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
		if randomApiKey == "" {
			s.skipped = true
			return
		}

		// quake api doc https://quake.360.cn/quake/#/help
		var pages = 1
		var pageSize = 500
		for currentPage := 1; currentPage <= pages; currentPage++ {
			gologger.Debug().Msgf("Querying %s for %s, currentPage:%d allPage:%d", s.Name(), domain, currentPage, pages)
			var requestBody = []byte(fmt.Sprintf(`{"query":"domain: %s", "start":%d, "size":%d,"ignore_cache": false,
"include": ["service.http.host"]}`,
				domain, (currentPage-1)*pageSize, pageSize))
			resp, err := session.Post(ctx, "https://quake.360.net/api/v3/search/quake_service", "", map[string]string{
				"Content-Type": "application/json", "X-QuakeToken": randomApiKey,
			}, bytes.NewReader(requestBody))
			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				s.errors++
				session.DiscardHTTPResponse(resp)
				return
			}

			var response quakeResults
			err = jsoniter.NewDecoder(resp.Body).Decode(&response)
			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				s.errors++
				resp.Body.Close()
				return
			}
			resp.Body.Close()

			if response.Code != 0 {
				results <- subscraping.Result{
					Source: s.Name(), Type: subscraping.Error, Error: fmt.Errorf("%s", response.Message),
				}
				s.errors++
				return
			}

			if response.Meta.Pagination.Total > 0 {
				for _, quakeDomain := range response.Data {
					subdomain := quakeDomain.Service.HTTP.Host
					if strings.ContainsAny(subdomain, "暂无权限") {
						subdomain = ""
					}
					results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: subdomain}
					s.results++
				}
				pages = int(response.Meta.Pagination.Total/pageSize) + 1
			}
			time.Sleep(2 * time.Second)

		}
	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "quake"
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
	s.apiKeys = keys
}

func (s *Source) Statistics() subscraping.Statistics {
	return subscraping.Statistics{
		Errors:    s.errors,
		Results:   s.results,
		TimeTaken: s.timeTaken,
		Skipped:   s.skipped,
	}
}
