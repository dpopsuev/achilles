package main

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"sort"
	"strings"
	"time"

	fw "github.com/dpopsuev/origami"
)

// --- Artifacts ---

type scanArtifact struct {
	raw        *ScanResult
	confidence float64
}

func (a *scanArtifact) Type() string       { return "scan" }
func (a *scanArtifact) Confidence() float64 { return a.confidence }
func (a *scanArtifact) Raw() any            { return a.raw }

type classifyArtifact struct {
	findings   []Finding
	confidence float64
}

func (a *classifyArtifact) Type() string       { return "classify" }
func (a *classifyArtifact) Confidence() float64 { return a.confidence }
func (a *classifyArtifact) Raw() any            { return a.findings }

type assessArtifact struct {
	assessment *Assessment
	confidence float64
}

func (a *assessArtifact) Type() string       { return "assess" }
func (a *assessArtifact) Confidence() float64 { return a.confidence }
func (a *assessArtifact) Raw() any            { return a.assessment }

type reportArtifact struct {
	report     string
	confidence float64
}

func (a *reportArtifact) Type() string       { return "report" }
func (a *reportArtifact) Confidence() float64 { return a.confidence }
func (a *reportArtifact) Raw() any            { return a.report }

// --- Nodes ---

// scanNode shells out to govulncheck and parses the JSON output.
type scanNode struct {
	repoPath  string
	extractor *GovulncheckExtractor
}

func (n *scanNode) Name() string              { return "scan" }
func (n *scanNode) ElementAffinity() fw.Element { return fw.ElementEarth }

func (n *scanNode) Process(ctx context.Context, _ fw.NodeContext) (fw.Artifact, error) {
	raw, err := runGovulncheck(ctx, n.repoPath)
	if err != nil {
		return nil, fmt.Errorf("govulncheck: %w", err)
	}

	result, err := n.extractor.Extract(ctx, raw)
	if err != nil {
		return nil, err
	}

	sr := result.(*ScanResult)
	conf := 1.0
	if sr.ScanLevel != "symbol" {
		conf = 0.7
	}

	return &scanArtifact{raw: sr, confidence: conf}, nil
}

func runGovulncheck(ctx context.Context, repoPath string) (string, error) {
	cmd := exec.CommandContext(ctx, "govulncheck", "-json", "./...")
	cmd.Dir = repoPath

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	// govulncheck exits 3 when vulnerabilities are found — that's a success for us.
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 3 {
			return stdout.String(), nil
		}
		return "", fmt.Errorf("govulncheck failed (exit %v): %s", err, stderr.String())
	}
	return stdout.String(), nil
}

// classifyNode takes scan output and produces deduplicated, severity-tagged findings.
type classifyNode struct {
	extractor *ClassifyExtractor
}

func (n *classifyNode) Name() string              { return "classify" }
func (n *classifyNode) ElementAffinity() fw.Element { return fw.ElementFire }

func (n *classifyNode) Process(ctx context.Context, nc fw.NodeContext) (fw.Artifact, error) {
	if nc.PriorArtifact == nil {
		return nil, fmt.Errorf("classify: no prior artifact")
	}
	sr, ok := nc.PriorArtifact.Raw().(*ScanResult)
	if !ok {
		return nil, fmt.Errorf("classify: expected *ScanResult, got %T", nc.PriorArtifact.Raw())
	}

	result, err := n.extractor.Extract(ctx, sr)
	if err != nil {
		return nil, err
	}

	findings := result.([]Finding)
	conf := 1.0
	if len(findings) == 0 {
		conf = 1.0
	}

	return &classifyArtifact{findings: findings, confidence: conf}, nil
}

// assessNode computes an overall risk score from classified findings.
type assessNode struct {
	repoPath string
}

func (n *assessNode) Name() string              { return "assess" }
func (n *assessNode) ElementAffinity() fw.Element { return fw.ElementDiamond }

func (n *assessNode) Process(_ context.Context, nc fw.NodeContext) (fw.Artifact, error) {
	if nc.PriorArtifact == nil {
		return nil, fmt.Errorf("assess: no prior artifact")
	}
	findings, ok := nc.PriorArtifact.Raw().([]Finding)
	if !ok {
		return nil, fmt.Errorf("assess: expected []Finding, got %T", nc.PriorArtifact.Raw())
	}

	assessment := buildAssessment(n.repoPath, findings)

	var conf float64
	switch {
	case assessment.RiskScore >= 0.8:
		conf = 0.95
	case assessment.RiskScore >= 0.5:
		conf = 0.85
	default:
		conf = 1.0
	}

	return &assessArtifact{assessment: assessment, confidence: conf}, nil
}

func buildAssessment(repoPath string, findings []Finding) *Assessment {
	a := &Assessment{
		RepoPath:   repoPath,
		ScanTime:   time.Now(),
		Findings:   findings,
		BySeverity: make(map[Severity][]Finding),
	}

	for _, f := range findings {
		a.BySeverity[f.Severity] = append(a.BySeverity[f.Severity], f)
	}

	// Risk score: weighted by severity and call-depth.
	var score float64
	for _, f := range findings {
		weight := 0.1
		switch f.Severity {
		case SeverityCritical:
			weight = 1.0
		case SeverityHigh:
			weight = 0.6
		case SeverityMedium:
			weight = 0.3
		}
		if f.ScanLevel == ScanLevelSymbol {
			weight *= 1.5
		}
		score += weight
	}
	if score > 1.0 {
		score = 1.0
	}
	a.RiskScore = score

	// Top risks: critical and high-severity findings.
	for _, sev := range []Severity{SeverityCritical, SeverityHigh} {
		for _, f := range a.BySeverity[sev] {
			a.TopRisks = append(a.TopRisks, fmt.Sprintf("[%s] %s: %s", sev, f.OSVID, f.Summary))
		}
	}

	return a
}

// reportNode formats the assessment as a colored terminal report.
type reportNode struct {
	repoPath string
}

func (n *reportNode) Name() string              { return "report" }
func (n *reportNode) ElementAffinity() fw.Element { return fw.ElementAir }

func (n *reportNode) Process(_ context.Context, nc fw.NodeContext) (fw.Artifact, error) {
	if nc.PriorArtifact == nil {
		return nil, fmt.Errorf("report: no prior artifact")
	}

	var assessment *Assessment
	switch v := nc.PriorArtifact.Raw().(type) {
	case *Assessment:
		assessment = v
	case *ScanResult:
		// Shortcut path: scan found zero vulns, skipped classify+assess.
		assessment = buildAssessment(n.repoPath, nil)
		assessment.ScannerVersion = v.ScannerVersion
		assessment.GoVersion = v.GoVersion
		assessment.TotalModules = v.TotalModules
	default:
		return nil, fmt.Errorf("report: expected *Assessment or *ScanResult, got %T", nc.PriorArtifact.Raw())
	}

	report := formatReport(assessment)
	return &reportArtifact{report: report, confidence: 1.0}, nil
}

const (
	reset  = "\033[0m"
	bold   = "\033[1m"
	dim    = "\033[2m"
	red    = "\033[31m"
	green  = "\033[32m"
	yellow = "\033[33m"
	blue   = "\033[34m"
	cyan   = "\033[36m"
	white  = "\033[37m"
)

func severityColor(s Severity) string {
	switch s {
	case SeverityCritical:
		return red
	case SeverityHigh:
		return yellow
	case SeverityMedium:
		return blue
	case SeverityLow:
		return dim
	default:
		return white
	}
}

func formatReport(a *Assessment) string {
	var b strings.Builder

	b.WriteString(fmt.Sprintf("\n%s%s=== Achilles Security Assessment ===%s\n\n", bold, cyan, reset))
	b.WriteString(fmt.Sprintf("  Repository:  %s%s%s\n", bold, a.RepoPath, reset))
	b.WriteString(fmt.Sprintf("  Scan time:   %s\n", a.ScanTime.Format(time.RFC3339)))
	b.WriteString(fmt.Sprintf("  Risk score:  %s%.2f%s\n", riskColor(a.RiskScore), a.RiskScore, reset))
	b.WriteString(fmt.Sprintf("  Total vulns: %d\n", len(a.Findings)))

	b.WriteString(fmt.Sprintf("\n%s%s--- Severity Breakdown ---%s\n\n", bold, yellow, reset))
	for _, sev := range []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow} {
		count := len(a.BySeverity[sev])
		if count > 0 {
			b.WriteString(fmt.Sprintf("  %s%-10s%s %d\n", severityColor(sev), sev, reset, count))
		}
	}

	if len(a.TopRisks) > 0 {
		b.WriteString(fmt.Sprintf("\n%s%s--- Top Risks ---%s\n\n", bold, red, reset))
		for _, r := range a.TopRisks {
			b.WriteString(fmt.Sprintf("  %s%s%s\n", red, r, reset))
		}
	}

	if len(a.Findings) > 0 {
		b.WriteString(fmt.Sprintf("\n%s%s--- Findings ---%s\n\n", bold, yellow, reset))

		sorted := make([]Finding, len(a.Findings))
		copy(sorted, a.Findings)
		sort.Slice(sorted, func(i, j int) bool {
			return sorted[i].Severity > sorted[j].Severity
		})

		for _, f := range sorted {
			sc := severityColor(f.Severity)
			b.WriteString(fmt.Sprintf("  %s%-10s%s %s%-20s%s %s\n",
				sc, f.Severity, reset, bold, f.OSVID, reset, f.Summary))

			b.WriteString(fmt.Sprintf("             module=%s@%s  fixed=%s",
				f.Module, f.Version, f.FixedVersion))

			if f.Package != "" {
				b.WriteString(fmt.Sprintf("  pkg=%s", f.Package))
			}
			if f.Function != "" {
				b.WriteString(fmt.Sprintf("  fn=%s", f.Function))
			}
			if f.CallSite != "" {
				b.WriteString(fmt.Sprintf("  at=%s", f.CallSite))
			}
			b.WriteString("\n")

			if len(f.Aliases) > 0 {
				b.WriteString(fmt.Sprintf("             %saliases: %s%s\n",
					dim, strings.Join(f.Aliases, ", "), reset))
			}
			b.WriteString("\n")
		}
	}

	if len(a.Findings) == 0 {
		b.WriteString(fmt.Sprintf("\n  %s%sNo vulnerabilities found. Clean bill of health.%s\n", bold, green, reset))
	}

	b.WriteString(fmt.Sprintf("\n%s%s=== End of Assessment ===%s\n", bold, cyan, reset))
	return b.String()
}

func riskColor(score float64) string {
	switch {
	case score >= 0.8:
		return bold + red
	case score >= 0.5:
		return bold + yellow
	case score >= 0.2:
		return bold + blue
	default:
		return bold + green
	}
}

// NodeRegistry builds the framework NodeRegistry for the achilles pipeline.
func NodeRegistry(repoPath string) fw.NodeRegistry {
	govulnExt := &GovulncheckExtractor{}
	classifyExt := &ClassifyExtractor{}

	return fw.NodeRegistry{
		"scan":     func(_ fw.NodeDef) fw.Node { return &scanNode{repoPath: repoPath, extractor: govulnExt} },
		"classify": func(_ fw.NodeDef) fw.Node { return &classifyNode{extractor: classifyExt} },
		"assess":   func(_ fw.NodeDef) fw.Node { return &assessNode{repoPath: repoPath} },
		"report":   func(_ fw.NodeDef) fw.Node { return &reportNode{repoPath: repoPath} },
	}
}
