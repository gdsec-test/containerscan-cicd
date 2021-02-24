package main

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"testing"
)

// RoundTripFunc .
type RoundTripFunc func(req *http.Request) *http.Response

// RoundTrip .
func (f RoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req), nil
}

//NewTestClient returns *http.Client with Transport replaced to avoid making real calls
func NewTestClient(fn RoundTripFunc) *http.Client {
	return &http.Client{
		Transport: RoundTripFunc(fn),
	}
}

func TestDoStuffWithRoundTripper(t *testing.T) {

	client := NewTestClient(func(req *http.Request) *http.Response {

		return &http.Response{
			StatusCode: 200,
			// Send response to be tested
			Body: ioutil.NopCloser(bytes.NewBufferString(`OK`)),
			// Must be set to non-nil value or it panics
			Header: make(http.Header),
		}
	})

	api := API{client, "http://example.com", "AAAAA", "GET", nil, nil}
	body := api.getAPIResponse()
	myString := string(body)
	if myString != "OK" {
		t.Error("API call error")
	}

}
