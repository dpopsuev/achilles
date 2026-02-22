package main

import fw "github.com/dpopsuev/origami"

// EdgeFactory builds the framework EdgeFactory for the achilles pipeline.
func EdgeFactory() fw.EdgeFactory {
	return fw.EdgeFactory{
		"V1": func(d fw.EdgeDef) fw.Edge { return &vulnEdge{def: d} },
		"V2": func(d fw.EdgeDef) fw.Edge { return &vulnEdge{def: d} },
		"V3": func(d fw.EdgeDef) fw.Edge { return &vulnEdge{def: d} },
		"V4": func(d fw.EdgeDef) fw.Edge { return &vulnEdge{def: d} },
		"V5": func(d fw.EdgeDef) fw.Edge { return &vulnEdge{def: d} },
		"V6": func(d fw.EdgeDef) fw.Edge { return &vulnEdge{def: d} },
	}
}

type vulnEdge struct {
	def fw.EdgeDef
}

func (e *vulnEdge) ID() string       { return e.def.ID }
func (e *vulnEdge) From() string     { return e.def.From }
func (e *vulnEdge) To() string       { return e.def.To }
func (e *vulnEdge) IsShortcut() bool { return e.def.Shortcut }
func (e *vulnEdge) IsLoop() bool     { return e.def.Loop }

func (e *vulnEdge) Evaluate(a fw.Artifact, s *fw.WalkerState) *fw.Transition {
	switch e.def.ID {
	case "V1": // scan -> classify: findings exist
		if sa, ok := a.Raw().(*ScanResult); ok && len(sa.Findings) > 0 {
			return &fw.Transition{NextNode: e.def.To, Explanation: "findings detected"}
		}
		return nil

	case "V2": // scan -> report (shortcut): zero findings
		if sa, ok := a.Raw().(*ScanResult); ok && len(sa.Findings) == 0 {
			return &fw.Transition{NextNode: e.def.To, Explanation: "clean scan — no vulnerabilities"}
		}
		return nil

	case "V3": // classify -> assess
		if a.Type() == "classify" {
			return &fw.Transition{NextNode: e.def.To, Explanation: "findings classified"}
		}
		return nil

	case "V4": // assess -> report
		if a.Type() == "assess" {
			return &fw.Transition{NextNode: e.def.To, Explanation: "assessment complete"}
		}
		return nil

	case "V5": // assess -> scan (loop): rescan for transitive deps
		// Disabled in v1 — always proceed to report.
		return nil

	case "V6": // report -> done
		if a.Type() == "report" {
			return &fw.Transition{NextNode: e.def.To, Explanation: "done"}
		}
		return nil
	}
	return nil
}
