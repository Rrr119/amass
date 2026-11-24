// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"slices"
	"testing"
)

func TestParseCertSpotter(t *testing.T) {
	body := []byte(`[
		{"id":"1","dns_names":["www.example.com","*.example.com"]},
		{"id":"2","dns_names":["mail.example.com"]}
	]`)

	names, last := parseCertSpotter(body)
	if last != "2" {
		t.Errorf("last id = %q, want 2", last)
	}
	if want := []string{"www.example.com", "*.example.com", "mail.example.com"}; !slices.Equal(names, want) {
		t.Errorf("names = %v, want %v", names, want)
	}

	names, last = parseCertSpotter([]byte("not json"))
	if names != nil || last != "" {
		t.Errorf("a bad body returned %v %q", names, last)
	}
}

func TestCertSpotterNames(t *testing.T) {
	body := []byte(`[
		{"id":"1","dns_names":["WWW.Example.com.","*.example.com","outside.example.net"]},
		{"id":"2","dns_names":["mail.example.com","www.example.com"]}
	]`)

	got := certSpotterNames(body, "example.com")
	want := []string{"example.com", "mail.example.com", "www.example.com"}
	if !slices.Equal(got, want) {
		t.Errorf("certSpotterNames() = %v, want %v", got, want)
	}
}
