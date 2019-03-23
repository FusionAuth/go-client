package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
)

// URIWithSegment returns a string with a "/" delimeter between the uri and segment
func URIWithSegment(uri, segment string) string {
	return uri + "/" + segment
}

// NewRequest creates a new request for the FusionAuth API call
func (c *FusionAuthClient) NewRequest(method, endpoint string, body interface{}) (*http.Request, error) {
	rel := &url.URL{Path: endpoint}
	u := c.BaseURL.ResolveReference(rel)

	var buf io.ReadWriter
	if body != nil {
		buf = new(bytes.Buffer)
		err := json.NewEncoder(buf).Encode(body)
		if err != nil {
			return nil, err
		}
	}

	req, err := http.NewRequest(method, u.String(), buf)
	reqDump, _ := httputil.DumpRequest(req, true)
	fmt.Println(string(reqDump))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", c.APIKey)

	return req, nil
}

// Do makes the request to the FusionAuth API endpoint and decodes the response
func (c *FusionAuthClient) Do(req *http.Request, v interface{}) (*http.Response, error) {
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	err = json.NewDecoder(resp.Body).Decode(v)
	return resp, err
}
