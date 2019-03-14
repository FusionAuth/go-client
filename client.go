package client

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
)

// FusionAuthClient describes the Go Client for interacting with FusionAuth's RESTful API
type FusionAuthClient struct {
	BaseURL    *url.URL
	APIKey     string
	httpClient *http.Client
}

func uriWithSegment(uri, segment string) string {
	return uri + segment
}

func (c *FusionAuthClient) newRequest(method, path string, body interface{}) (*http.Request, error) {
	rel := &url.URL{Path: path}
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
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", c.APIKey)

	return req, nil
}

func (c *FusionAuthClient) do(req *http.Request, v interface{}) (*http.Response, error) {
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	err = json.NewDecoder(resp.Body).Decode(v)
	return resp, err
}

// RetrieveUser retrieves the user for the given userID
func (c *FusionAuthClient) RetrieveUser(userID string) (interface{}, error) {
	req, err := c.newRequest(http.MethodGet, uriWithSegment("api/user", userID), nil)
	var resp interface{}
	_, err = c.do(req, &resp)
	return resp, err
}

// CreateUser creates a user. You can optionally specify an ID for the user, if not provided one will be generated.
func (c *FusionAuthClient) CreateUser(userID string, request interface{}) (interface{}, error) {
	req, err := c.newRequest(http.MethodPost, uriWithSegment("api/user", userID), request)
	var resp interface{}
	_, err = c.do(req, &resp)
	return resp, err
}
