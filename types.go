package main

import "time"

// Severity classifies a vulnerability's impact.
type Severity int

const (
	SeverityLow Severity = iota
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

func (s Severity) String() string {
	switch s {
	case SeverityLow:
		return "LOW"
	case SeverityMedium:
		return "MEDIUM"
	case SeverityHigh:
		return "HIGH"
	case SeverityCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

// ScanLevel indicates how deeply govulncheck analyzed the code.
type ScanLevel string

const (
	ScanLevelModule  ScanLevel = "module"
	ScanLevelPackage ScanLevel = "package"
	ScanLevelSymbol  ScanLevel = "symbol"
)

// --- govulncheck JSON message types ---

// GovulnConfig is the first message in the govulncheck JSON stream.
type GovulnConfig struct {
	Config struct {
		ProtocolVersion string `json:"protocol_version"`
		ScannerName     string `json:"scanner_name"`
		ScannerVersion  string `json:"scanner_version"`
		DB              string `json:"db"`
		DBLastModified  string `json:"db_last_modified"`
		GoVersion       string `json:"go_version"`
		ScanLevel       string `json:"scan_level"`
		ScanMode        string `json:"scan_mode"`
	} `json:"config"`
}

// GovulnOSV carries an OSV entry from the vulnerability database.
type GovulnOSV struct {
	OSV OSVEntry `json:"osv"`
}

// OSVEntry is a subset of the OSV schema relevant to our assessment.
type OSVEntry struct {
	ID       string        `json:"id"`
	Aliases  []string      `json:"aliases"`
	Summary  string        `json:"summary"`
	Details  string        `json:"details"`
	Affected []OSVAffected `json:"affected"`
}

// OSVAffected describes which package versions are affected.
type OSVAffected struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Ranges []OSVRange `json:"ranges"`
}

// OSVRange defines the version range for a vulnerability.
type OSVRange struct {
	Type   string     `json:"type"`
	Events []OSVEvent `json:"events"`
}

// OSVEvent is a semver introduced/fixed boundary.
type OSVEvent struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
}

// GovulnFinding carries a single vulnerability finding.
type GovulnFinding struct {
	Finding FindingEntry `json:"finding"`
}

// FindingEntry is a single vulnerability detection.
type FindingEntry struct {
	OSV          string       `json:"osv"`
	FixedVersion string       `json:"fixed_version"`
	Trace        []TraceFrame `json:"trace"`
}

// TraceFrame describes one frame in a finding's call trace.
type TraceFrame struct {
	Module   string `json:"module"`
	Version  string `json:"version,omitempty"`
	Package  string `json:"package,omitempty"`
	Function string `json:"function,omitempty"`
	Position *struct {
		Filename string `json:"filename"`
		Line     int    `json:"line"`
		Column   int    `json:"column"`
	} `json:"position,omitempty"`
}

// GovulnMessage is a union type for decoding the govulncheck JSON stream.
// Only one field is non-nil per message.
type GovulnMessage struct {
	Config  *GovulnConfig  `json:"-"`
	OSV     *GovulnOSV     `json:"-"`
	Finding *GovulnFinding `json:"-"`
}

// --- Domain types (achilles's own model) ---

// Finding is achilles's normalized representation of a vulnerability.
type Finding struct {
	OSVID        string
	Aliases      []string
	Summary      string
	Module       string
	Version      string
	FixedVersion string
	Severity     Severity
	ScanLevel    ScanLevel
	Package      string
	Function     string
	CallSite     string
}

// Assessment is the final output of the achilles circuit.
type Assessment struct {
	RepoPath       string
	ScanTime       time.Time
	ScannerVersion string
	GoVersion      string
	TotalModules   int
	Findings       []Finding
	BySeverity     map[Severity][]Finding
	RiskScore      float64
	TopRisks       []string
}
