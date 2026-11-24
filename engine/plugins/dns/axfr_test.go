// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"net"
	"slices"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestNameInZone(t *testing.T) {
	tests := []struct {
		name string
		zone string
		want bool
	}{
		{"example.com", "example.com", true},
		{"www.example.com", "example.com", true},
		{"a.b.example.com.", "example.com.", true},
		{"example.com", "example.org", false},
		{"notexample.com", "example.com", false},
		{"example.com.evil.com", "example.com", false},
	}

	for _, test := range tests {
		if got := nameInZone(test.name, test.zone); got != test.want {
			t.Errorf("nameInZone(%q, %q) = %v, want %v", test.name, test.zone, got, test.want)
		}
	}
}

func TestZoneNames(t *testing.T) {
	zone := "example.com."
	records := zoneRecords(zone)
	records = append(records,
		mustRR("www.example.com. 300 IN A 192.0.2.2"),
		mustRR("outside.example.net. 300 IN A 192.0.2.3"),
	)

	want := []string{
		"example.com",
		"ns1.example.com",
		"www.example.com",
	}
	if got := zoneNames(records, "example.com"); !slices.Equal(got, want) {
		t.Errorf("zoneNames() = %v, want %v", got, want)
	}
}

func TestTransferZoneAllowed(t *testing.T) {
	zone := "example.com."
	addr, shutdown := axfrServer(t, zone, zoneRecords(zone), true)
	defer shutdown()

	records, ok := transferZone("example.com", addr)
	if !ok {
		t.Fatal("an allowed zone transfer was not reported as successful")
	}
	if len(records) == 0 {
		t.Fatal("the allowed zone transfer returned no records")
	}

	var found bool
	for _, rr := range records {
		if rr.Header().Name == "www.example.com." {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("the transferred records did not include www.example.com: %v", records)
	}
}

func TestTransferZoneRefused(t *testing.T) {
	zone := "example.com."
	addr, shutdown := axfrServer(t, zone, zoneRecords(zone), false)
	defer shutdown()

	if _, ok := transferZone("example.com", addr); ok {
		t.Error("a refused zone transfer was reported as successful")
	}
}

func TestTransferZoneNoServer(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	_ = listener.Close()

	if _, ok := transferZone("example.com", addr); ok {
		t.Error("a failed dial was reported as a successful transfer")
	}
}

// axfrServer starts a TCP DNS server that answers AXFR for zone when allow is
// true and refuses all other transfers.
func axfrServer(t *testing.T, zone string, records []dns.RR, allow bool) (string, func()) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	mux := dns.NewServeMux()
	mux.HandleFunc(zone, func(w dns.ResponseWriter, r *dns.Msg) {
		if r.Question[0].Qtype == dns.TypeAXFR && allow {
			ch := make(chan *dns.Envelope, 1)
			transfer := new(dns.Transfer)
			go func() {
				ch <- &dns.Envelope{RR: records}
				close(ch)
			}()
			_ = transfer.Out(w, r, ch)
			return
		}

		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeRefused)
		_ = w.WriteMsg(m)
	})

	server := &dns.Server{Listener: listener, Handler: mux}
	go func() { _ = server.ActivateAndServe() }()
	time.Sleep(50 * time.Millisecond)

	return listener.Addr().String(), func() { _ = server.Shutdown() }
}

func zoneRecords(zone string) []dns.RR {
	return []dns.RR{
		mustRR(zone + " 300 IN SOA ns1." + zone + " admin." + zone + " 1 7200 3600 1209600 300"),
		mustRR(zone + " 300 IN NS ns1." + zone),
		mustRR("ns1." + zone + " 300 IN A 192.0.2.53"),
		mustRR("www." + zone + " 300 IN A 192.0.2.1"),
		mustRR(zone + " 300 IN SOA ns1." + zone + " admin." + zone + " 1 7200 3600 1209600 300"),
	}
}

func mustRR(value string) dns.RR {
	rr, err := dns.NewRR(value)
	if err != nil {
		panic("failed to create a DNS record: " + err.Error())
	}
	return rr
}
