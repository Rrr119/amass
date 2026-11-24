// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"context"
	"net"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
)

func TestTransferZone(t *testing.T) {
	zone := "example.com."
	records := []mdns.RR{
		newZoneRR(t, zone+" 300 IN SOA ns1."+zone+" admin."+zone+" 1 7200 3600 1209600 300"),
		newZoneRR(t, zone+" 300 IN NS ns1."+zone),
		newZoneRR(t, "ns1."+zone+" 300 IN A 192.0.2.10"),
		newZoneRR(t, "www."+zone+" 300 IN A 192.0.2.11"),
		newZoneRR(t, "api."+zone+" 300 IN A 192.0.2.12"),
		newZoneRR(t, "mail."+zone+" 300 IN MX 10 mail."+zone),
		newZoneRR(t, zone+" 300 IN SOA ns1."+zone+" admin."+zone+" 1 7200 3600 1209600 300"),
	}

	addr, shutdown := zoneTransferServer(t, zone, records)
	defer shutdown()

	transferred, ok := TransferZone(context.Background(), "example.com", addr)
	if !ok {
		t.Fatal("the complete zone transfer was not accepted")
	}
	if got := ZoneNames(transferred, "example.com"); len(got) != 5 {
		t.Errorf("transferred names = %v, want five names", got)
	}
}

func zoneTransferServer(t *testing.T, zone string, records []mdns.RR) (string, func()) {
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

func newZoneRR(t *testing.T, value string) mdns.RR {
	t.Helper()

	rr, err := mdns.NewRR(value)
	if err != nil {
		t.Fatal(err)
	}
	return rr
}
