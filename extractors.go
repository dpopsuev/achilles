package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// GovulncheckExtractor parses govulncheck -json streaming output into
// a structured ScanResult containing config, OSV entries, and findings.
//
// Input: string (raw govulncheck JSON stream)
// Output: *ScanResult
type GovulncheckExtractor struct{}

func (e *GovulncheckExtractor) Name() string { return "govulncheck-v1" }

func (e *GovulncheckExtractor) Extract(_ context.Context, input any) (any, error) {
	raw, ok := input.(string)
	if !ok {
		return nil, fmt.Errorf("govulncheck extractor: expected string, got %T", input)
	}
	return parseGovulncheckStream(raw)
}

// ScanResult holds the parsed govulncheck output.
type ScanResult struct {
	ScannerVersion string
	GoVersion      string
	ScanLevel      string
	TotalModules   int
	OSVEntries     map[string]OSVEntry
	Findings       []FindingEntry
}

func parseGovulncheckStream(raw string) (*ScanResult, error) {
	result := &ScanResult{
		OSVEntries: make(map[string]OSVEntry),
	}

	decoder := json.NewDecoder(strings.NewReader(raw))
	for decoder.More() {
		var msg map[string]json.RawMessage
		if err := decoder.Decode(&msg); err != nil {
			break
		}

		if configRaw, ok := msg["config"]; ok {
			var cfg struct {
				ScannerVersion string `json:"scanner_version"`
				GoVersion      string `json:"go_version"`
				ScanLevel      string `json:"scan_level"`
			}
			if err := json.Unmarshal(configRaw, &cfg); err == nil {
				result.ScannerVersion = cfg.ScannerVersion
				result.GoVersion = cfg.GoVersion
				result.ScanLevel = cfg.ScanLevel
			}
		}

		if sbomRaw, ok := msg["SBOM"]; ok {
			var sbom struct {
				Modules []struct {
					Path    string `json:"path"`
					Version string `json:"version"`
				} `json:"modules"`
			}
			if err := json.Unmarshal(sbomRaw, &sbom); err == nil {
				result.TotalModules = len(sbom.Modules)
			}
		}

		if osvRaw, ok := msg["osv"]; ok {
			var entry OSVEntry
			if err := json.Unmarshal(osvRaw, &entry); err == nil {
				result.OSVEntries[entry.ID] = entry
			}
		}

		if findingRaw, ok := msg["finding"]; ok {
			var f FindingEntry
			if err := json.Unmarshal(findingRaw, &f); err == nil {
				result.Findings = append(result.Findings, f)
			}
		}
	}

	return result, nil
}

// ClassifyExtractor takes a *ScanResult and produces []Finding with severity assigned.
//
// Input: *ScanResult
// Output: []Finding
type ClassifyExtractor struct{}

func (e *ClassifyExtractor) Name() string { return "classify-v1" }

func (e *ClassifyExtractor) Extract(_ context.Context, input any) (any, error) {
	sr, ok := input.(*ScanResult)
	if !ok {
		return nil, fmt.Errorf("classify extractor: expected *ScanResult, got %T", input)
	}
	return classifyFindings(sr), nil
}

func classifyFindings(sr *ScanResult) []Finding {
	// Deduplicate: keep the most specific finding per OSV ID
	// (symbol > package > module level).
	best := make(map[string]FindingEntry)
	for _, f := range sr.Findings {
		existing, seen := best[f.OSV]
		if !seen || traceDepth(f) > traceDepth(existing) {
			best[f.OSV] = f
		}
	}

	var findings []Finding
	for _, fe := range best {
		osv := sr.OSVEntries[fe.OSV]
		f := Finding{
			OSVID:        fe.OSV,
			Aliases:      osv.Aliases,
			Summary:      osv.Summary,
			FixedVersion: fe.FixedVersion,
			ScanLevel:    determineScanLevel(fe),
		}

		if len(fe.Trace) > 0 {
			f.Module = fe.Trace[0].Module
			f.Version = fe.Trace[0].Version
			f.Package = fe.Trace[0].Package
			f.Function = fe.Trace[0].Function
			if fe.Trace[0].Position != nil {
				f.CallSite = fmt.Sprintf("%s:%d",
					fe.Trace[0].Position.Filename, fe.Trace[0].Position.Line)
			}
		}

		f.Severity = inferSeverity(osv, fe)
		findings = append(findings, f)
	}

	return findings
}

func traceDepth(fe FindingEntry) int {
	if len(fe.Trace) == 0 {
		return 0
	}
	top := fe.Trace[0]
	if top.Function != "" {
		return 3
	}
	if top.Package != "" {
		return 2
	}
	return 1
}

func determineScanLevel(fe FindingEntry) ScanLevel {
	if len(fe.Trace) == 0 {
		return ScanLevelModule
	}
	top := fe.Trace[0]
	if top.Function != "" {
		return ScanLevelSymbol
	}
	if top.Package != "" {
		return ScanLevelPackage
	}
	return ScanLevelModule
}

// inferSeverity assigns severity based on summary keywords and call-depth.
// Symbol-level findings that are actually called are critical/high;
// module-level findings are lower because the vulnerable code may not be reachable.
func inferSeverity(osv OSVEntry, fe FindingEntry) Severity {
	summary := strings.ToLower(osv.Summary)
	depth := traceDepth(fe)

	hasCriticalKeyword := strings.Contains(summary, "remote code") ||
		strings.Contains(summary, "arbitrary code") ||
		strings.Contains(summary, "privilege escalation")

	hasDOSKeyword := strings.Contains(summary, "denial of service") ||
		strings.Contains(summary, "infinite loop") ||
		strings.Contains(summary, "memory exhaustion") ||
		strings.Contains(summary, "excessive") ||
		strings.Contains(summary, "stack exhaustion") ||
		strings.Contains(summary, "unbounded")

	switch {
	case hasCriticalKeyword && depth >= 2:
		return SeverityCritical
	case hasCriticalKeyword:
		return SeverityHigh
	case depth == 3:
		if hasDOSKeyword {
			return SeverityHigh
		}
		return SeverityMedium
	case depth == 2:
		return SeverityMedium
	default:
		return SeverityLow
	}
}
