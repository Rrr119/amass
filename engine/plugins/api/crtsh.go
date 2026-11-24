// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/url"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	amasshttp "github.com/owasp-amass/amass/v5/internal/net/http"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"golang.org/x/time/rate"
)

type crtsh struct {
	name   string
	log    *slog.Logger
	rlimit *rate.Limiter
	source *et.Source
}

func NewCrtsh() et.Plugin {
	limit := rate.Every(2 * time.Second)

	return &crtsh{
		name:   "crt.sh",
		rlimit: rate.NewLimiter(limit, 1),
		source: &et.Source{
			Name:       "crt.sh",
			Confidence: 100,
		},
	}
}

func (c *crtsh) Name() string {
	return c.name
}

func (c *crtsh) Start(r et.Registry) error {
	c.log = r.Log().WithGroup("plugin").With("name", c.name)

	if err := r.RegisterHandler(&et.Handler{
		Plugin:       c,
		Name:         c.name + "-Handler",
		Position:     22,
		MaxInstances: support.MidHandlerInstances,
		Transforms:   []string{string(oam.FQDN)},
		EventType:    oam.FQDN,
		Callback:     c.check,
	}); err != nil {
		return err
	}

	c.log.Info("Plugin started")
	return nil
}

func (c *crtsh) Stop() {
	c.log.Info("Plugin stopped")
}

func (c *crtsh) check(e *et.Event) error {
	fqdn, ok := e.Entity.Asset.(*oamdns.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	if !support.HasSLDInScope(e) {
		return nil
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.FQDN), string(oam.FQDN), c.name)
	if err != nil {
		return err
	}

	var names []*dbt.Entity
	if !support.AssetMonitoredWithinTTL(e.Session, e.Entity, c.source, since) {
		names = append(names, c.query(e, fqdn.Name)...)
		support.MarkAssetMonitored(e.Session, e.Entity, c.source)
	}

	if len(names) > 0 {
		c.process(e, names)
	}
	return nil
}

func (c *crtsh) query(e *et.Event, name string) []*dbt.Entity {
	_ = c.rlimit.Wait(e.Session.Ctx())
	e.Session.NetSem().Acquire()

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	resp, err := amasshttp.RequestWebPage(ctx, e.Session.Clients().General, &amasshttp.Request{
		URL: "https://crt.sh/?q=" + url.QueryEscape(name) + "&output=json&exclude=expired&deduplicate=Y",
	})
	e.Session.NetSem().Release()
	if err != nil {
		return nil
	}

	var names []string
	for _, n := range parseCrtSh([]byte(resp.Body), name) {
		if _, conf := e.Session.Scope().IsAssetInScope(&oamdns.FQDN{Name: n}, 0); conf > 0 {
			names = append(names, n)
		}
	}

	return c.store(e, names)
}

// parseCrtSh returns the normalized names below domain from a crt.sh JSON
// response. The object form is accepted as well as crt.sh's usual array.
func parseCrtSh(body []byte, domain string) []string {
	type cert struct {
		CommonName string `json:"common_name"`
		NameValue  string `json:"name_value"`
	}

	var certs []cert
	if err := json.Unmarshal(body, &certs); err != nil {
		var result struct {
			Certs []cert `json:"certs"`
		}
		if err := json.Unmarshal(body, &result); err != nil {
			return nil
		}
		certs = result.Certs
	}

	var names []string
	for _, entry := range certs {
		for _, value := range []string{entry.CommonName, entry.NameValue} {
			for _, name := range splitCTNames(value) {
				names = append(names, name)
			}
		}
	}
	return mergeCTNames(domain, names)
}

func (c *crtsh) store(e *et.Event, names []string) []*dbt.Entity {
	return support.StoreFQDNsWithSource(e.Session, names, c.source, c.name, c.name+"-Handler")
}

func (c *crtsh) process(e *et.Event, assets []*dbt.Entity) {
	support.ProcessFQDNsWithSource(e, assets, c.source)
}
