// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
	amassdns "github.com/owasp-amass/amass/v5/internal/net/dns"
)

func TestParseCrtSh(t *testing.T) {
	arrayBody := []byte(`[
		{"common_name":"www.example.com","name_value":"www.example.com\n*.example.com"},
		{"common_name":"dev.example.com","name_value":"dev.example.com\noutside.example.net"}
	]`)

	got := parseCrtSh(arrayBody, "example.com")
	want := []string{"dev.example.com", "example.com", "www.example.com"}
	if !slices.Equal(got, want) {
		t.Errorf("parseCrtSh() = %v, want %v", got, want)
	}

	objectBody := []byte(`{"certs":[
		{"common_name":"api.example.com","name_value":"api.example.com\nwww.example.com"}
	]}`)
	got = parseCrtSh(objectBody, "example.com")
	want = []string{"api.example.com", "www.example.com"}
	if !slices.Equal(got, want) {
		t.Errorf("parseCrtSh() with an object body = %v, want %v", got, want)
	}

	if got := parseCrtSh([]byte("not json"), "example.com"); got != nil {
		t.Errorf("parseCrtSh() with a bad body = %v, want nil", got)
	}
}

func TestMergeCTNames(t *testing.T) {
	got := mergeCTNames("example.com",
		[]string{"WWW.Example.com.", "*.example.com", "outside.example.net"},
		[]string{"www.example.com", "dev.example.com"},
	)
	want := []string{"dev.example.com", "example.com", "www.example.com"}
	if !slices.Equal(got, want) {
		t.Errorf("mergeCTNames() = %v, want %v", got, want)
	}
}

func TestCTPluginSources(t *testing.T) {
	crt := NewCrtsh().(*crtsh)
	if crt.Name() != "crt.sh" || crt.source.Name != "crt.sh" {
		t.Errorf("crt.sh plugin source = %q/%q, want crt.sh/crt.sh", crt.Name(), crt.source.Name)
	}

	spotter := NewCertSpotter().(*certSpotter)
	if spotter.Name() != "CertSpotter" || spotter.source.Name != "CertSpotter" {
		t.Errorf("CertSpotter plugin source = %q/%q, want CertSpotter/CertSpotter",
			spotter.Name(), spotter.source.Name)
	}
}

// TestThreeDomainsMatchManualEnumeration compares the union of the names from
// an AXFR and two Certificate Transparency responses with a manually checked
// subdomain inventory for each of three domains.
func TestThreeDomainsMatchManualEnumeration(t *testing.T) {
	fixtures := []struct {
		domain       string
		zone         string
		crtSh        string
		certSpotter  string
		manualResult []string
	}{
		{
			domain: "alpha.test",
			zone: `
alpha.test. 300 IN SOA ns1.alpha.test. admin.alpha.test. 1 7200 3600 1209600 300
alpha.test. 300 IN NS ns1.alpha.test.
ns1.alpha.test. 300 IN A 192.0.2.10
www.alpha.test. 300 IN A 192.0.2.11
api.alpha.test. 300 IN A 192.0.2.12
mail.alpha.test. 300 IN MX 10 mail.alpha.test.
alpha.test. 300 IN SOA ns1.alpha.test. admin.alpha.test. 1 7200 3600 1209600 300
`,
			crtSh: `[
				{"common_name":"alpha.test","name_value":"*.alpha.test\nwww.alpha.test\ndev.alpha.test\noutside.alpha.net"}
			]`,
			certSpotter: `[
				{"id":"1","dns_names":["api.alpha.test","*.alpha.test","mail.alpha.test"]}
			]`,
			manualResult: []string{
				"alpha.test",
				"api.alpha.test",
				"dev.alpha.test",
				"mail.alpha.test",
				"ns1.alpha.test",
				"www.alpha.test",
			},
		},
		{
			domain: "beta.test",
			zone: `
beta.test. 300 IN SOA ns1.beta.test. admin.beta.test. 1 7200 3600 1209600 300
beta.test. 300 IN NS ns1.beta.test.
ns1.beta.test. 300 IN A 192.0.2.20
portal.beta.test. 300 IN A 192.0.2.21
auth.beta.test. 300 IN A 192.0.2.22
beta.test. 300 IN SOA ns1.beta.test. admin.beta.test. 1 7200 3600 1209600 300
`,
			crtSh: `[
				{"common_name":"beta.test","name_value":"beta.test\napi.beta.test\nauth.beta.test\nnot.beta.example"}
			]`,
			certSpotter: `[
				{"id":"2","dns_names":["portal.beta.test","cdn.beta.test","api.beta.test"]}
			]`,
			manualResult: []string{
				"api.beta.test",
				"auth.beta.test",
				"beta.test",
				"cdn.beta.test",
				"ns1.beta.test",
				"portal.beta.test",
			},
		},
		{
			domain: "gamma.test",
			zone: `
gamma.test. 300 IN SOA ns1.gamma.test. admin.gamma.test. 1 7200 3600 1209600 300
gamma.test. 300 IN NS ns1.gamma.test.
ns1.gamma.test. 300 IN A 192.0.2.30
cdn.gamma.test. 300 IN A 192.0.2.31
assets.gamma.test. 300 IN CNAME cdn.gamma.test.
gamma.test. 300 IN SOA ns1.gamma.test. admin.gamma.test. 1 7200 3600 1209600 300
`,
			crtSh: `[
				{"common_name":"gamma.test","name_value":"staging.gamma.test\nassets.gamma.test\n*.gamma.test\nevil.gamma.test.example.net"}
			]`,
			certSpotter: `[
				{"id":"3","dns_names":["cdn.gamma.test","admin.gamma.test","staging.gamma.test"]}
			]`,
			manualResult: []string{
				"admin.gamma.test",
				"assets.gamma.test",
				"cdn.gamma.test",
				"gamma.test",
				"ns1.gamma.test",
				"staging.gamma.test",
			},
		},
	}

	for _, fixture := range fixtures {
		t.Run(fixture.domain, func(t *testing.T) {
			var records []mdns.RR
			for _, line := range strings.Split(strings.TrimSpace(fixture.zone), "\n") {
				rr, err := mdns.NewRR(line)
				if err != nil {
					t.Fatalf("failed to parse zone record %q: %v", line, err)
				}
				records = append(records, rr)
			}

			addr, shutdown := ctTestAXFRServer(t, fixture.domain+".", records)
			defer shutdown()

			transferred, ok := amassdns.TransferZone(context.Background(), fixture.domain, addr)
			if !ok {
				t.Fatal("the local AXFR server did not complete the zone transfer")
			}

			axfrNames := amassdns.ZoneNames(transferred, fixture.domain)
			crtShNames := parseCrtSh([]byte(fixture.crtSh), fixture.domain)
			certSpotterNames := certSpotterNames([]byte(fixture.certSpotter), fixture.domain)
			got := mergeCTNames(fixture.domain, axfrNames, crtShNames, certSpotterNames)

			if !slices.Equal(got, fixture.manualResult) {
				t.Errorf("discovered names = %v, manual enumeration = %v", got, fixture.manualResult)
			}
		})
	}
}

func ctTestAXFRServer(t *testing.T, zone string, records []mdns.RR) (string, func()) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	mux := mdns.NewServeMux()
	mux.HandleFunc(zone, func(w mdns.ResponseWriter, r *mdns.Msg) {
		ch := make(chan *mdns.Envelope, 1)
		transfer := new(mdns.Transfer)
		go func() {
			ch <- &mdns.Envelope{RR: records}
			close(ch)
		}()
		_ = transfer.Out(w, r, ch)
	})

	server := &mdns.Server{Listener: listener, Handler: mux}
	go func() { _ = server.ActivateAndServe() }()
	time.Sleep(50 * time.Millisecond)

	return listener.Addr().String(), func() { _ = server.Shutdown() }
}
