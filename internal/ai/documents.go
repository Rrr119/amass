// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/owasp-amass/amass/v5/internal/ai/llm"
	"github.com/owasp-amass/amass/v5/internal/lens"
	"github.com/owasp-amass/amass/v5/internal/review"
	"github.com/owasp-amass/amass/v5/internal/semantics"
)

// Document reading limits.
const (
	// DefaultDocumentChunk is how many characters of a document one model
	// request reads; a document is read whole, chunk by chunk.
	DefaultDocumentChunk = 12000
	// chunkOverlap repeats the end of a chunk at the start of the next, so a
	// sentence cut by a chunk boundary is read whole in one of them.
	chunkOverlap = 400
	// maxChunkFindings bounds each list in one chunk's reply.
	maxChunkFindings = 80
	// maxStatementTerm bounds a name, value or detail.
	maxStatementTerm = 200
	// quoteWindow is how far around a quote the names it relates may be
	// written, for a quote the model shortened.
	quoteWindow = 300
	// negationLead is how far before the first name a negation still counts.
	negationLead = 40
)

// Finding kinds.
const (
	// FindingAsset is an asset the document names: an organization, a host,
	// an address, a product.
	FindingAsset = "asset"
	// FindingRelation is a relationship the document states between two
	// assets.
	FindingRelation = "relation"
	// FindingAttribute is a value the document gives for one of an asset's
	// OAM fields (an organization's founding date, a product's type).
	FindingAttribute = "attribute"
)

// DocumentStatement is one thing a document states, as the document model
// read it and Go validated it against the document's own text and the Open
// Asset Model: the quote occurs word for word in the document, every name and
// value is written near it, types and relations are ones OAM (or the
// statement catalog) allows, and a relation is not negated.
type DocumentStatement struct {
	Kind        string `json:"kind"`
	Subject     string `json:"subject"`
	SubjectType string `json:"subject_type"`
	Predicate   string `json:"predicate,omitempty"`
	Object      string `json:"object,omitempty"`
	ObjectType  string `json:"object_type,omitempty"`
	Field       string `json:"field,omitempty"`
	Detail      string `json:"detail,omitempty"`
	Quote       string `json:"quote"`
	Model       string `json:"model"`
}

// DocumentReading is what the document model found in one document: its
// category, the findings that passed validation, why the others were
// rejected, and how many chunks it read.
type DocumentReading struct {
	Category   string              `json:"category,omitempty"`
	Statements []DocumentStatement `json:"statements"`
	Rejected   []string            `json:"rejected,omitempty"`
	Chunks     int                 `json:"chunks"`
	// Through is where in the cleaned text a reading stopped at its part or
	// time limit (readLimits), so the next reading starts there; 0 when the
	// reading reached the end of the document.
	Through int `json:"through,omitempty"`
}

// chunkReply is the model's reply for one chunk.
type chunkReply struct {
	Category string `json:"category"`
	Assets   []struct {
		Type  string `json:"type"`
		Value string `json:"value"`
		Quote string `json:"quote"`
	} `json:"assets"`
	Statements []struct {
		Subject     string `json:"subject"`
		SubjectType string `json:"subject_type"`
		Predicate   string `json:"predicate"`
		Object      string `json:"object"`
		ObjectType  string `json:"object_type"`
		Detail      string `json:"detail"`
		Quote       string `json:"quote"`
	} `json:"statements"`
	Attributes []struct {
		Subject     string `json:"subject"`
		SubjectType string `json:"subject_type"`
		Field       string `json:"field"`
		Value       string `json:"value"`
		Quote       string `json:"quote"`
	} `json:"attributes"`
}

// ReadDocument has the document model read all of a document's text, chunk by
// chunk, and keeps only the findings that pass validation. The model is the
// one the user named in options.ai.documents; nothing it says is trusted
// until checked here against the text itself.
func ReadDocument(ctx context.Context, model llm.Model, modelID, url, text string, chunkChars int) (DocumentReading,
	error) {
	return readDocument(ctx, model, modelID, url, text, chunkChars, readLimits{}, nil)
}

// readLimits bound one reading of a document. The zero value reads the whole
// document from its start.
type readLimits struct {
	// from is the offset of the cleaned text the reading starts at, where an
	// earlier reading stopped.
	from int
	// maxChunks caps the chunks read (options.ai.documents.max_chunks).
	maxChunks int
	// timeout caps the time spent on the document
	// (options.ai.documents.document_timeout): past it, no further chunk is
	// started. A chunk already started finishes, within model_timeout.
	timeout time.Duration
}

// readDocument is ReadDocument within limits, calling onChunk after each chunk
// is read. A reading that stops at a limit before the end of the document says
// where (Through), so a later reading continues there.
func readDocument(ctx context.Context, model llm.Model, modelID, url, text string, chunkChars int, limits readLimits,
	onChunk func()) (DocumentReading, error) {
	var out DocumentReading
	if model == nil {
		return out, errors.New("no document model is configured (options.ai.documents)")
	}
	if chunkChars <= 0 {
		chunkChars = DefaultDocumentChunk
	}

	clean := cleanText(text)
	spans := chunkSpans(clean, chunkChars)
	first := 0
	for first < len(spans) && spans[first].start < limits.from {
		first++
	}
	if first >= len(spans) {
		return out, nil
	}
	started := time.Now()

	v := documentVocabulary()
	system := documentPrompt(v)
	schema := documentSchema(v)
	seen := map[string]bool{}
	categories := map[string]int{}
	for i := first; i < len(spans); i++ {
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
		// past a limit, the rest is left for the next reading, which starts
		// at this chunk
		if i > first && ((limits.maxChunks > 0 && i-first >= limits.maxChunks) ||
			(limits.timeout > 0 && time.Since(started) >= limits.timeout)) {
			out.Through = spans[i].start
			break
		}
		chunk := clean[spans[i].start:spans[i].end]
		history := []llm.Message{
			{Role: "system", Text: system},
			{Role: "user", Text: fmt.Sprintf("Document: %s\nPart %d of %d:\n%s", url, i+1, len(spans), chunk)},
		}
		resp, err := generateJSON(ctx, model, history, schema)
		if errors.Is(err, llm.ErrReplyLength) {
			// a reply cut off at the token cap is incomplete JSON, most
			// often a model repeating itself: skip the part, keep reading
			out.Chunks++
			out.Rejected = append(out.Rejected, fmt.Sprintf("part %d: reply cut off at the token limit", i+1))
			if onChunk != nil {
				onChunk()
			}
			continue
		}
		if err != nil {
			return out, &documentError{kind: modelFailure(err),
				err: fmt.Errorf("part %d of %d: %w", i+1, len(spans), err)}
		}
		out.Chunks++
		if onChunk != nil {
			onChunk()
		}

		var reply chunkReply
		if err := json.NewDecoder(strings.NewReader(llm.ModelJSON(resp.Text))).Decode(&reply); err != nil {
			out.Rejected = append(out.Rejected, fmt.Sprintf("part %d: unreadable reply", i+1))
			continue
		}
		if v.rules.IsCategory(reply.Category) {
			categories[reply.Category]++
		}

		keep := func(s DocumentStatement, reason string) {
			if reason != "" {
				out.Rejected = append(out.Rejected, reason)
				return
			}
			s.Model = modelID
			key := strings.ToLower(strings.Join([]string{s.Kind, s.SubjectType, s.Subject, s.Predicate, s.Field,
				s.ObjectType, s.Object}, "\x00"))
			if !seen[key] {
				seen[key] = true
				out.Statements = append(out.Statements, s)
			}
		}
		for _, a := range limit(reply.Assets) {
			s := DocumentStatement{Kind: FindingAsset, Subject: collapse(a.Value), SubjectType: a.Type,
				Quote: collapse(a.Quote)}
			keep(s, v.validateAsset(s, chunk))
		}
		for _, r := range limit(reply.Statements) {
			s := DocumentStatement{Kind: FindingRelation, Subject: collapse(r.Subject), SubjectType: r.SubjectType,
				Predicate: r.Predicate, Object: collapse(r.Object), ObjectType: r.ObjectType,
				Detail: collapse(r.Detail), Quote: collapse(r.Quote)}
			if s.Object == lens.DocumentPublisher {
				// implied by where the document is published, not stated
				// in a sentence naming both
				s.Detail = "a unit of the document's publisher"
			}
			keep(s, v.validateRelation(s, chunk))
		}
		for _, a := range limit(reply.Attributes) {
			s := DocumentStatement{Kind: FindingAttribute, Subject: collapse(a.Subject), SubjectType: a.SubjectType,
				Field: a.Field, Object: collapse(a.Value), Quote: collapse(a.Quote)}
			keep(s, v.validateAttribute(s, chunk))
		}
	}

	out.Category = topCategory(categories)
	return out, nil
}

// limit bounds the items of one list in a chunk's reply.
func limit[T any](items []T) []T {
	if len(items) > maxChunkFindings {
		return items[:maxChunkFindings]
	}
	return items
}

// topCategory returns the category the most chunks gave, ties broken by name.
func topCategory(counts map[string]int) string {
	best, n := "", 0
	for c, k := range counts {
		if k > n || (k == n && c < best) {
			best, n = c, k
		}
	}
	return best
}

// chunkText splits text into chunks of at most size bytes, each ending at a
// sentence or line end where one is near, overlapping by chunkOverlap.
func chunkText(text string, size int) []string {
	var out []string
	for _, s := range chunkSpans(text, size) {
		out = append(out, text[s.start:s.end])
	}
	return out
}

// span is a chunk's place in the text: text[start:end].
type span struct{ start, end int }

// chunkSpans is chunkText as offsets into text, so a reading can say where it
// stopped and a later one start there. The same text and size always give the
// same spans.
func chunkSpans(text string, size int) []span {
	end := len(strings.TrimRightFunc(text, unicode.IsSpace))
	pos := skipSpace(text, 0)

	var out []span
	for end-pos > size {
		cut := pos + size
		if i := strings.LastIndexAny(text[pos:pos+size], ".!?\n"); i > size/2 {
			cut = pos + i + 1
		}
		cut = runeStart(text, cut)
		out = append(out, span{start: pos, end: pos + len(strings.TrimRightFunc(text[pos:cut], unicode.IsSpace))})

		next := runeStart(text, max(cut-chunkOverlap, pos+1))
		if next <= pos {
			next = cut
		}
		pos = skipSpace(text, next)
	}
	if pos < end {
		out = append(out, span{start: pos, end: end})
	}
	return out
}

// skipSpace returns the offset of the first character at or after i that is
// not white space.
func skipSpace(text string, i int) int {
	return i + len(text[i:]) - len(strings.TrimLeftFunc(text[i:], unicode.IsSpace))
}

// runeStart moves i back to the start of the UTF-8 sequence it falls in.
func runeStart(s string, i int) int {
	for i > 0 && i < len(s) && !utf8.RuneStart(s[i]) {
		i--
	}
	return i
}

// quoteSite is where a quote was found: the text around it, in lower case,
// and the quote's span within that text.
type quoteSite struct {
	text       string
	start, end int
}

// located finds the quote in the chunk and returns the text around it, where
// the names it relates must be written. ok is false when the quote is not in
// the chunk.
func located(quote, chunk string) (site quoteSite, ok bool) {
	q, text := strings.ToLower(collapse(quote)), strings.ToLower(collapse(chunk))
	if q == "" {
		return site, false
	}
	at := strings.Index(text, q)
	if at < 0 {
		return site, false
	}
	start := runeStart(text, max(0, at-quoteWindow))
	end := min(len(text), at+len(q)+quoteWindow)
	for end < len(text) && !utf8.RuneStart(text[end]) {
		end++
	}
	return quoteSite{text: text[start:end], start: at - start, end: at - start + len(q)}, true
}

// find returns where name is written near the quote: within the quote when it
// is there, otherwise its first place around it; -1 when it is not written.
func (q quoteSite) find(name string) int {
	name = strings.ToLower(name)
	if i := strings.Index(q.text[q.start:q.end], name); i >= 0 {
		return q.start + i
	}
	return strings.Index(q.text, name)
}

// has reports whether name is written near the quote.
func (q quoteSite) has(name string) bool { return q.find(name) >= 0 }

// validateAsset returns why an asset finding is rejected, or "".
func (v *docVocabulary) validateAsset(s DocumentStatement, chunk string) string {
	if s.Subject == lens.DocumentPublisher {
		return "asset: the publisher placeholder is no asset"
	}
	if !v.assetTypes[s.SubjectType] {
		return fmt.Sprintf("asset: %q is not a type documents are read for", s.SubjectType)
	}
	if reason := checkValue(s.SubjectType, s.Subject); reason != "" {
		return "asset: " + reason
	}
	site, ok := located(s.Quote, chunk)
	if !ok {
		return fmt.Sprintf("asset %s: the quote is not in the document", s.SubjectType)
	}
	if !site.has(s.Subject) {
		return fmt.Sprintf("asset %s: the value is not written where it is quoted", s.SubjectType)
	}
	return ""
}

// validateRelation returns why a relation finding is rejected, or "".
func (v *docVocabulary) validateRelation(s DocumentStatement, chunk string) string {
	if s.Subject == lens.DocumentPublisher || s.Object == lens.DocumentPublisher {
		return v.validatePublisherUnit(s, chunk)
	}
	if !v.allows(s.SubjectType, s.Predicate, s.ObjectType) {
		return fmt.Sprintf("%s does not relate %s to %s", s.Predicate, s.SubjectType, s.ObjectType)
	}
	if strings.EqualFold(s.Subject, s.Object) || len(s.Detail) > maxStatementTerm {
		return fmt.Sprintf("%s: identical ends or overlong detail", s.Predicate)
	}
	for _, end := range []struct{ typ, value string }{{s.SubjectType, s.Subject}, {s.ObjectType, s.Object}} {
		if reason := checkValue(end.typ, end.value); reason != "" {
			return s.Predicate + ": " + reason
		}
	}

	site, ok := located(s.Quote, chunk)
	if !ok {
		return fmt.Sprintf("%s: the quote is not in the document", s.Predicate)
	}
	si, oi := site.find(s.Subject), site.find(s.Object)
	if si < 0 || oi < 0 {
		return fmt.Sprintf("%s: subject or object not written where it is quoted", s.Predicate)
	}
	// a negation around the two names ("who are not sponsored by") states
	// the opposite, or nothing
	if negated(site.text, si, si+len(strings.ToLower(s.Subject)), oi, oi+len(strings.ToLower(s.Object))) {
		return fmt.Sprintf("%s: the document negates it", s.Predicate)
	}
	return ""
}

// validatePublisherUnit returns why a finding that names the document's
// publisher (lens.DocumentPublisher) is rejected, or "". The placeholder may
// only be the parent of a unit_of finding; the unit's own name must be
// written where it is quoted, and not negated there.
func (v *docVocabulary) validatePublisherUnit(s DocumentStatement, chunk string) string {
	if s.Predicate != "unit_of" || s.SubjectType != "Organization" || s.ObjectType != "Organization" ||
		s.Object != lens.DocumentPublisher || s.Subject == lens.DocumentPublisher {
		return "the publisher placeholder is only the parent of a unit_of finding"
	}
	if reason := checkValue(s.SubjectType, s.Subject); reason != "" {
		return "unit_of: " + reason
	}
	site, ok := located(s.Quote, chunk)
	if !ok {
		return "unit_of: the quote is not in the document"
	}
	si := site.find(s.Subject)
	if si < 0 {
		return "unit_of: the unit is not written where it is quoted"
	}
	end := si + len(strings.ToLower(s.Subject))
	if negated(site.text, si, end, si, end) {
		return "unit_of: the document negates it"
	}
	return ""
}

// validateAttribute returns why an attribute finding is rejected, or "".
func (v *docVocabulary) validateAttribute(s DocumentStatement, chunk string) string {
	if !slices.Contains(v.fields[s.SubjectType], s.Field) {
		return fmt.Sprintf("attribute: %s has no field %q", s.SubjectType, s.Field)
	}
	if reason := checkValue(s.SubjectType, s.Subject); reason != "" {
		return "attribute: " + reason
	}
	if s.Object == "" || len(s.Object) > maxStatementTerm {
		return fmt.Sprintf("attribute %s: empty or overlong value", s.Field)
	}
	site, ok := located(s.Quote, chunk)
	if !ok {
		return fmt.Sprintf("attribute %s: the quote is not in the document", s.Field)
	}
	if !site.has(s.Subject) || !site.has(s.Object) {
		return fmt.Sprintf("attribute %s: the asset or value is not written where it is quoted", s.Field)
	}
	return ""
}

// negationWords are the words that make a passage deny a relationship.
var negationWords = map[string]bool{"not": true, "no": true, "never": true, "neither": true, "nor": true,
	"without": true, "cannot": true, "none": true, "nonaffiliated": true, "unaffiliated": true}

// negated reports whether the text spanning two names in lower, from a little
// before the first to the end of the second, holds a negation.
func negated(lower string, s1, e1, s2, e2 int) bool {
	first, end := min(s1, s2), max(e1, e2)
	start := runeStart(lower, max(0, first-negationLead))
	// the lead stays within the sentence the first name is in
	if i := strings.LastIndexAny(lower[start:first], ".!?;"); i >= 0 {
		start += i + 1
	}
	words := strings.FieldsFunc(lower[start:end], func(r rune) bool {
		return !unicode.IsLetter(r) && r != '\'' && r != '’'
	})
	for _, w := range words {
		if negationWords[w] || strings.HasSuffix(w, "n't") || strings.HasSuffix(w, "n’t") {
			return true
		}
	}
	return false
}

// properName reports whether s reads as a name rather than a common noun
// phrase ("third parties"): it holds an uppercase letter or a digit.
func properName(s string) bool {
	return strings.IndexFunc(s, func(r rune) bool { return unicode.IsUpper(r) || unicode.IsDigit(r) }) >= 0 &&
		!fragmented(s)
}

// nameParticles are the short lowercase words proper names hold: "Bank of
// America", "Universidad de la Sabana", "Ludwig van Beethoven".
var nameParticles = map[string]bool{"of": true, "de": true, "la": true, "le": true, "du": true, "da": true,
	"di": true, "do": true, "y": true, "e": true, "et": true, "en": true, "at": true, "by": true, "in": true,
	"on": true, "to": true, "an": true, "al": true, "el": true, "a": true, "i": true, "o": true}

// fragmented reports whether a name holds a piece of a word split apart when
// the document's text was extracted ("MV CC Theat er"): a lowercase word of
// one or two letters that is not a name particle.
func fragmented(s string) bool {
	for _, w := range strings.Fields(s) {
		w = strings.Trim(w, ".,;:&'\"()-")
		if w == "" || utf8.RuneCountInString(w) > 2 || strings.ToLower(w) != w ||
			strings.IndexFunc(w, func(r rune) bool { return !unicode.IsLetter(r) }) >= 0 {
			continue
		}
		if !nameParticles[w] {
			return true
		}
	}
	return false
}

// cleanText replaces the control characters extracted document text can hold
// (form feeds, NULs, escape codes) with spaces, keeping newlines and tabs. A
// model whose reply must match a JSON schema cannot copy them into a quote,
// since JSON strings forbid them raw, and the constrained reply fails partway
// through; the quotes are checked against the cleaned text, so they still
// match it verbatim.
func cleanText(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' || !unicode.IsControl(r) {
			return r
		}
		return ' '
	}, s)
}

// collapse trims s and joins its whitespace runs into single spaces.
func collapse(s string) string { return strings.Join(strings.Fields(s), " ") }

// documentPrompt instructs the document model, listing what it may report.
func documentPrompt(v *docVocabulary) string {
	var b strings.Builder
	b.WriteString(`You read one part of a published document and report what it states about organizations, people, systems and places, for an attack-surface inventory built on the Open Asset Model (OAM).
Rules:
- Report only what the text states explicitly. Never infer, guess or use outside knowledge.
- quote must be copied exactly from the text: the sentence or phrase that states the finding.
- Names and values must be written in the text near the quote, copied as written. Names must be proper names: never pronouns, roles or groups such as "third parties", "students" or "the vendor".
- Leave out anything the text denies or excludes ("not", "never", "no longer", "without").
- assets: every asset the text names, with its OAM type.
- statements: relationships between two assets, using a relation listed below for those two types.
- attributes: a value the text gives for one of an asset's fields listed below.
- category is what the whole document appears to be.
- The organization that published the document runs the site in the Document line. When the text names an office, department, campus, program, center or other unit of that organization, give a unit_of statement with the unit as subject (an Organization) and object "` + lens.DocumentPublisher + `" (object_type Organization), and quote the line that names the unit. Use "` + lens.DocumentPublisher + `" for nothing else, and never for an organization the text presents as separate from the publisher: a contractor, a vendor, an agency, a partner or a funder.
Asset types and the values to give:
`)
	for _, t := range v.types {
		fmt.Fprintf(&b, "- %s: %s\n", t, assetHints[t])
	}
	b.WriteString("Relations (subject type -[relation]-> object type: meaning):\n")
	for _, r := range v.relationLines {
		b.WriteString("- " + r + "\n")
	}
	b.WriteString("Attribute fields:\n")
	for _, t := range v.types {
		if fields := v.fields[t]; len(fields) > 0 {
			fmt.Fprintf(&b, "- %s: %s\n", t, strings.Join(fields, ", "))
		}
	}
	b.WriteString("Categories:\n")
	for _, c := range v.rules.Categories {
		fmt.Fprintf(&b, "- %s: %s\n", c.Name, c.Description)
	}
	b.WriteString(`Reply with JSON only: {"category": "...", "assets": [{"type": "...", "value": "...", "quote": "..."}], "statements": [{"subject": "...", "subject_type": "...", "predicate": "...", "object": "...", "object_type": "...", "detail": "...", "quote": "..."}], "attributes": [{"subject": "...", "subject_type": "...", "field": "...", "value": "...", "quote": "..."}]}. Use empty lists when the text states nothing of a kind.`)
	return b.String()
}

// documentSchema constrains the reply to the vocabulary, where the provider
// supports it.
func documentSchema(v *docVocabulary) llm.JSONSchema {
	var categories, fields []string
	for _, c := range v.rules.Categories {
		categories = append(categories, c.Name)
	}
	fieldSet := map[string]bool{}
	for _, fs := range v.fields {
		for _, f := range fs {
			fieldSet[f] = true
		}
	}
	for f := range fieldSet {
		fields = append(fields, f)
	}
	sort.Strings(fields)

	str := map[string]any{"type": "string"}
	types := map[string]any{"type": "string", "enum": v.types}
	list := func(props map[string]any, required ...string) map[string]any {
		return map[string]any{"type": "array", "maxItems": maxChunkFindings, "items": map[string]any{
			"type": "object", "properties": props, "required": required, "additionalProperties": false}}
	}
	return llm.JSONSchema{
		Name:        "document_findings",
		Description: "The category of the document and the assets, relationships and attributes its text states.",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"category": map[string]any{"type": "string", "enum": categories},
				"assets":   list(map[string]any{"type": types, "value": str, "quote": str}, "type", "value", "quote"),
				"statements": list(map[string]any{"subject": str, "subject_type": types,
					"predicate": map[string]any{"type": "string", "enum": v.predicates}, "object": str,
					"object_type": types, "detail": str, "quote": str},
					"subject", "subject_type", "predicate", "object", "object_type", "quote"),
				"attributes": list(map[string]any{"subject": str, "subject_type": types,
					"field": map[string]any{"type": "string", "enum": fields}, "value": str, "quote": str},
					"subject", "subject_type", "field", "value", "quote"),
			},
			"required":             []string{"category", "assets", "statements", "attributes"},
			"additionalProperties": false,
		},
	}
}

// Stored returns the reading as the statements stored on the document's File:
// its findings, and its category as File is_a <category>. sha256 names the
// version of the document read.
func (r DocumentReading) Stored(url, sha256 string) []review.StoredStatement {
	var out []review.StoredStatement
	// "other" says nothing about the document, so it is not stored
	if r.Category != "" && r.Category != "other" {
		out = append(out, review.StoredStatement{Kind: FindingAttribute, Subject: url, SubjectType: "File",
			Predicate: review.PredicateIsA, Object: r.Category, SHA256: sha256})
	}
	for _, s := range r.Statements {
		out = append(out, review.StoredStatement{Kind: s.Kind, Subject: s.Subject, SubjectType: s.SubjectType,
			Predicate: s.Predicate, Object: s.Object, ObjectType: s.ObjectType, Field: s.Field, Detail: s.Detail,
			Quote: s.Quote, Model: s.Model, SHA256: sha256})
	}
	return out
}

// statementRules returns the statement catalog (semantics), kept for its
// natural-reading predicates and the document categories.
func statementRules() semantics.StatementPredicates { return semantics.StatementPredicateRules() }
