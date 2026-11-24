// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"context"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	amassdns "github.com/owasp-amass/amass/v5/internal/net/dns"
	dbt "github.com/owasp-amass/asset-db/types"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"github.com/owasp-amass/open-asset-model/general"
	"github.com/owasp-amass/resolve/utils"
)

const (
	// axfrPort is the TCP port used for zone transfers.
	axfrPort = "53"
)

// queryAXFR attempts a zone transfer against each authoritative nameserver of
// the zone apex. A successful transfer exposes every name in the zone and is
// fed into the normal FQDN pipeline. It is only attempted in active mode.
func (d *dnsSubs) queryAXFR(e *et.Event, apex *dbt.Entity, name string) {
	if apex == nil || !e.Session.Config().Active {
		return
	}

	ns, err := support.PerformQuery(e.Session.Ctx(), name, dns.TypeNS)
	if err != nil || len(ns) == 0 {
		return
	}

	seen := make(map[string]bool)
	for _, rr := range ns {
		record, ok := rr.(*dns.NS)
		if !ok {
			continue
		}

		server := strings.ToLower(strings.TrimSpace(utils.RemoveLastDot(record.Ns)))
		if server == "" || seen[server] {
			continue
		}
		seen[server] = true
		d.attemptAXFR(e, apex, name, server)
	}
}

// attemptAXFR resolves a nameserver and tries the transfer against each of its
// addresses, stopping at the first address that completes one.
func (d *dnsSubs) attemptAXFR(e *et.Event, apex *dbt.Entity, zone, server string) {
	var addrs []string

	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
		rr, err := support.PerformQuery(e.Session.Ctx(), server, qtype)
		if err != nil {
			continue
		}

		for _, record := range rr {
			switch v := record.(type) {
			case *dns.A:
				addrs = append(addrs, v.A.String())
			case *dns.AAAA:
				addrs = append(addrs, v.AAAA.String())
			}
		}
	}

	for _, addr := range addrs {
		records, ok := transferZoneWithContext(e.Session.Ctx(), zone, net.JoinHostPort(addr, axfrPort))
		if !ok {
			continue
		}

		d.recordZoneTransfer(e, apex, zone, server)
		d.ingestZone(e, apex, zone, records)
		e.Session.Log().Info("zone transfer succeeded", "zone", zone, "nameserver", server,
			"records", len(records), slog.Group("plugin", "name", d.plugin.name, "handler", d.name))
		return
	}
}

// transferZone performs an AXFR against dialAddr. It reports success only for
// a complete transfer, so refusals and interrupted transfers are not reported
// as exposures.
func transferZone(zone, dialAddr string) ([]dns.RR, bool) {
	return transferZoneWithContext(context.Background(), zone, dialAddr)
}

func transferZoneWithContext(ctx context.Context, zone, dialAddr string) ([]dns.RR, bool) {
	return amassdns.TransferZone(ctx, zone, dialAddr)
}

// recordZoneTransfer records the nameserver that exposed the zone so the
// finding survives after the active transfer has finished.
func (d *dnsSubs) recordZoneTransfer(e *et.Event, apex *dbt.Entity, zone, server string) {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 10*time.Second)
	defer cancel()

	if _, err := e.Session.DB().CreateEntityProperty(ctx, apex, &general.SimpleProperty{
		PropertyName:  "zone_transfer",
		PropertyValue: server,
	}); err != nil {
		e.Session.Log().Error("failed to store the zone transfer exposure", "zone", zone, "nameserver", server,
			slog.Group("plugin", "name", d.plugin.name, "handler", d.name))
	}
}

// ingestZone turns every owner name in the transferred zone into an in-scope
// FQDN asset and dispatches it through the existing enumeration pipeline.
func (d *dnsSubs) ingestZone(e *et.Event, apex *dbt.Entity, zone string, records []dns.RR) {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	for _, name := range zoneNames(records, zone) {
		fqdn := &oamdns.FQDN{Name: name}
		if a, conf := e.Session.Scope().IsAssetInScope(fqdn, 0); conf == 0 || a == nil {
			continue
		}

		entity, err := e.Session.DB().CreateAsset(ctx, fqdn)
		if err != nil || entity == nil {
			continue
		}

		_, _ = e.Session.DB().CreateEntityProperty(ctx, entity, &general.SourceProperty{
			Source:     d.plugin.source.Name,
			Confidence: d.plugin.source.Confidence,
		})
		d.linkBelow(ctx, e, apex, entity)
		_ = e.Dispatcher.DispatchEvent(&et.Event{
			Name:    name,
			Entity:  entity,
			Session: e.Session,
		})
	}
}

// linkBelow connects a discovered name to the zone apex. This preserves names
// that do not resolve, so they remain visible to the rest of the enumeration.
func (d *dnsSubs) linkBelow(ctx context.Context, e *et.Event, apex, entity *dbt.Entity) {
	if apex == nil || entity == nil || apex.Asset.Key() == entity.Asset.Key() {
		return
	}

	if _, err := e.Session.DB().CreateEdge(ctx, &dbt.Edge{
		Relation:   &general.SimpleRelation{Name: "node"},
		FromEntity: apex,
		ToEntity:   entity,
	}); err != nil {
		e.Session.Log().Debug("failed to link a zone transfer name to the apex",
			"apex", apex.Asset.Key(), "name", entity.Asset.Key())
	}
}

// zoneNames returns the sorted, deduplicated owner names in records that are
// at or below zone. Names from another zone are discarded.
func zoneNames(records []dns.RR, zone string) []string {
	return amassdns.ZoneNames(records, zone)
}

// nameInZone reports whether name is the zone apex or a name below it.
func nameInZone(name, zone string) bool {
	return amassdns.NameInZone(name, zone)
}
