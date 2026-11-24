// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"sort"
	"strings"

	amassdns "github.com/owasp-amass/amass/v5/internal/net/dns"
)

// normalizeCTName canonicalizes a name returned by a Certificate
// Transparency service. Wildcard labels are removed and names below another
// domain are rejected by mergeCTNames.
func normalizeCTName(name string) string {
	name = strings.TrimSpace(amassdns.RemoveAsteriskLabel(name))
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if name == "" || strings.ContainsAny(name, " \t\r\n") {
		return ""
	}
	return name
}

// mergeCTNames combines names from one or more CT responses, keeps only names
// at or below domain, removes duplicates, and returns a stable sorted list.
func mergeCTNames(domain string, sets ...[]string) []string {
	domain = normalizeCTName(domain)
	seen := make(map[string]struct{})

	for _, set := range sets {
		for _, raw := range set {
			name := normalizeCTName(raw)
			if name == "" || !nameUnderDomain(name, domain) {
				continue
			}
			seen[name] = struct{}{}
		}
	}

	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func nameUnderDomain(name, domain string) bool {
	return name == domain || strings.HasSuffix(name, "."+domain)
}

func splitCTNames(value string) []string {
	return strings.FieldsFunc(value, func(r rune) bool {
		return r == '\n' || r == '\r' || r == ','
	})
}
