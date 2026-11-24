// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"sort"
	"strings"

	mdns "github.com/miekg/dns"
	"github.com/owasp-amass/resolve/utils"
)

// NameInZone reports whether name is the zone apex or a name below it.
func NameInZone(name, zone string) bool {
	zone = strings.ToLower(strings.TrimSuffix(zone, "."))
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	return name == zone || strings.HasSuffix(name, "."+zone)
}

// ZoneNames returns the sorted, deduplicated owner names in records that are
// at or below zone. Names belonging to another zone are discarded.
func ZoneNames(records []mdns.RR, zone string) []string {
	seen := make(map[string]struct{})
	for _, rr := range records {
		name := strings.ToLower(strings.TrimSpace(utils.RemoveLastDot(rr.Header().Name)))
		if name == "" || !NameInZone(name, zone) {
			continue
		}
		seen[name] = struct{}{}
	}

	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
