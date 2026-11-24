// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"context"
	"net"
	"time"

	mdns "github.com/miekg/dns"
)

const maxAXFRRecords = 50000

// TransferZone performs an AXFR against dialAddr. It reports success only for
// a complete transfer with no errors, so a refusal or an interrupted response
// is not mistaken for an exposed zone.
func TransferZone(ctx context.Context, zone, dialAddr string) ([]mdns.RR, bool) {
	m := new(mdns.Msg)
	m.SetAxfr(mdns.Fqdn(zone))

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", dialAddr)
	if err != nil {
		return nil, false
	}

	transfer := &mdns.Transfer{
		Conn:        &mdns.Conn{Conn: conn},
		ReadTimeout: 10 * time.Second,
	}
	defer func() { _ = transfer.Close() }()

	ch, err := transfer.In(m, dialAddr)
	if err != nil {
		return nil, false
	}

	var records []mdns.RR
	ok := true
	for env := range ch {
		if env.Error != nil {
			ok = false
			continue
		}
		if len(records) < maxAXFRRecords {
			records = append(records, env.RR...)
		}
	}

	if !ok || len(records) == 0 {
		return nil, false
	}
	return records, true
}
