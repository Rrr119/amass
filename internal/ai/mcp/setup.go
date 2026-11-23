// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/owasp-amass/amass/v5/config"
	client "github.com/owasp-amass/amass/v5/engine/api/client/v1"
	"github.com/owasp-amass/amass/v5/internal/ai"
	"github.com/owasp-amass/amass/v5/internal/collect"
	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/graph/oamrepo"
	"github.com/owasp-amass/amass/v5/internal/review"
)

// OperatorOptions configures NewOperator.
type OperatorOptions struct {
	// Dir and ConfigFile load a fresh configuration for each enumeration.
	Dir, ConfigFile string
	// RunJournal records enumeration runs (JSON lines); empty keeps them in
	// memory only.
	RunJournal string
	// WatchFile keeps scheduled enumerations; empty disables watches.
	WatchFile string
	// PublicURL is how a user's browser reaches the HTTP server, for
	// data source key links; empty disables them.
	PublicURL           string
	RequireConfirmation bool
	// MaxRunning, IdleTimeout and MaxDuration bound enumerations; zero
	// keeps the collect package's defaults.
	MaxRunning  int
	IdleTimeout time.Duration
	MaxDuration time.Duration
}

// NewOperator builds the operator tools' dependencies from a loaded
// configuration: an engine client, a supervising enumeration manager that
// resumes earlier runs, the review journal and the datasources file. The
// returned function releases them.
func NewOperator(cfg *config.Config, g oamrepo.Adapter, opts OperatorOptions) (*Operator, func(), error) {
	c, err := client.NewClient(collect.EngineURL(cfg))
	if err != nil {
		return nil, nil, fmt.Errorf("engine API client: %w", err)
	}

	_, journal, err := cfg.AIAttribution(os.LookupEnv)
	if err != nil {
		c.Close()
		return nil, nil, err
	}

	m := &collect.Manager{
		Engine: c,
		Config: func() (*config.Config, error) {
			fresh := config.NewConfig()
			if err := config.AcquireConfig(opts.Dir, opts.ConfigFile, fresh); err != nil {
				return nil, err
			}

			return fresh, nil
		},
		Journal:     opts.RunJournal,
		MaxRunning:  opts.MaxRunning,
		IdleTimeout: opts.IdleTimeout,
		MaxDuration: opts.MaxDuration,
	}
	// options.ai.documents.hold bounds how long a run is kept open for the
	// documents left to read; 0 keeps none open
	hold := collect.DefaultHoldLimit
	if v, ok := cfg.AI.Documents.HoldDuration(); ok {
		hold = v
	}
	if hold == 0 {
		m.HoldLimit = -1
	} else {
		m.HoldLimit = hold
	}
	// With a document model, it reads the documents each run collects while
	// the run goes on and gives the run the organizations they name as leads.
	if cfg.AI.DocumentModelEnabled() && journal != "" && g.Repo != nil {
		model, modelID, timeout, err := ai.DocumentModel(cfg.AI.Documents)
		if err != nil {
			c.Close()
			return nil, nil, err
		}

		dg := g
		dg.WithholdDocumentText = false
		m.Companions = append(m.Companions, &ai.DocumentCompanion{Graph: dg, Store: g.Repo,
			Journal: &review.Journal{Path: journal}, Model: model, ModelID: modelID, ModelTimeout: timeout,
			ChunkChars: cfg.AI.Documents.ChunkChars, MaxLeads: cfg.AI.Documents.MaxLeads, Hold: hold,
			MaxChunks: cfg.AI.Documents.MaxChunks, DocumentTimeout: cfg.AI.Documents.DocumentTimeoutDuration()})
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		_ = m.Resume(ctx)
	}()

	op := &Operator{Collect: m, Graph: g, Journal: journal, RequireConfirmation: opts.RequireConfirmation,
		AnnounceDecisions: cfg.AnnounceAIDecisions(os.LookupEnv)}
	if cfg.AI != nil {
		op.Documents, op.ShareDocuments = cfg.AI.Documents, cfg.AI.DocumentsShared()
	}
	stopWatches := func() {}
	if opts.WatchFile != "" {
		runner := ai.ToolRunner{Graph: g, Catalog: oamrepo.Catalog{}, Limits: graph.DefaultLimits()}
		op.Watches = &collect.Watches{Manager: m, Path: opts.WatchFile,
			Summarize: func(ctx context.Context, run collect.Run) string {
				if s, ok := foundSince(ctx, runner, run).(string); ok {
					return s
				}

				return ""
			}}
		ctx, cancel := context.WithCancel(context.Background())
		go op.Watches.Run(ctx)
		stopWatches = cancel
	}
	if opts.PublicURL != "" {
		op.Approvals = &ApprovalLinks{BaseURL: opts.PublicURL}
	}
	if path, err := collect.DataSourcesPath(cfg); err == nil {
		op.DataSources = path
		if opts.PublicURL != "" {
			op.KeyLinks = &KeyLinks{BaseURL: opts.PublicURL, Path: path}
		}
	}

	return op, func() { stopWatches(); m.Close(); c.Close() }, nil
}
