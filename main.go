// Achilles — Go vulnerability scanner built on the Origami agentic circuit framework.
//
// Second reference implementation proving Origami works for any domain.
// Zero Asterisk-domain imports. Uses only github.com/dpopsuev/origami and stdlib.
//
// Run it:
//
//	go run . analyze .
//	go run . analyze /path/to/any/go/repo
//	go run . circuit render circuits/achilles.yaml
//	go run . circuit validate circuits/achilles.yaml
package main

import (
	"context"
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/dpopsuev/origami/circuit"
	origamicli "github.com/dpopsuev/origami/cli"
	"github.com/dpopsuev/origami/engine"
)

//go:embed circuits/achilles.yaml
var circuitYAML []byte

func init() {
	circuit.RegisterEmbeddedCircuit("achilles", circuitYAML)
}

func main() {
	c, err := origamicli.NewCLI("achilles", "Go vulnerability scanner — powered by Origami").
		WithAnalyze(runScan).
		WithCircuit("circuits/achilles.yaml").
		Build()
	if err != nil {
		fmt.Fprintf(os.Stderr, "build CLI: %v\n", err)
		os.Exit(1)
	}

	root := c.Root()
	root.Long = `Achilles scans Go repositories for known vulnerabilities using govulncheck,
classifies findings by severity, and produces a security assessment.

Built on the Origami agentic circuit framework — the same DSL, graph walk,
elements, and extractors that power Asterisk's root cause analysis engine.`

	if err := c.Execute(); err != nil {
		os.Exit(1)
	}
}

func resolveCircuit() (*circuit.CircuitDef, error) {
	data, err := circuit.ResolveCircuitPath("achilles")
	if err != nil {
		return nil, fmt.Errorf("resolve circuit: %w", err)
	}
	def, err := circuit.LoadCircuit(data)
	if err != nil {
		return nil, fmt.Errorf("parse circuit: %w", err)
	}
	return def, nil
}

func runScan(ctx context.Context, args []string) error {
	repoPath := "."
	if len(args) > 0 {
		repoPath = args[0]
	}

	abs, err := filepath.Abs(repoPath)
	if err != nil {
		return fmt.Errorf("resolve path: %w", err)
	}

	if _, err := os.Stat(filepath.Join(abs, "go.mod")); err != nil {
		return fmt.Errorf("%s does not contain a go.mod file", abs)
	}

	walker := engine.DefaultWalker()
	obs, capture := engine.NewCapture()

	observer := circuit.WalkObserverFunc(func(e *circuit.WalkEvent) {
		switch e.Type {
		case circuit.EventNodeEnter:
			fmt.Printf("  %s[%s]%s entering %s%s%s...\n",
				dim, walker.Identity().PersonaName, reset,
				bold, e.Node, reset)
		case circuit.EventNodeExit:
			if e.Error != nil {
				fmt.Printf("  %s[%s]%s %s%s failed: %v%s\n",
					dim, walker.Identity().PersonaName, reset,
					red, e.Node, e.Error, reset)
			} else {
				fmt.Printf("  %s[%s]%s %s%s%s complete (%s)\n",
					dim, walker.Identity().PersonaName, reset,
					green, e.Node, reset, e.Elapsed)
			}
		case circuit.EventTransition:
			fmt.Printf("  %s→ %s%s\n", dim, e.Edge, reset)
		}
	})

	fmt.Printf("\n%s%s=== Achilles — Origami Circuit ===%s\n\n", bold, cyan, reset)
	fmt.Printf("  Repository: %s%s%s\n", bold, abs, reset)
	fmt.Printf("  Circuit:   achilles (4 nodes, 6 edges)\n")
	fmt.Printf("  Walker:     %s (element=%s)\n\n",
		walker.Identity().PersonaName, walker.Identity().Element)

	def, err := resolveCircuit()
	if err != nil {
		return err
	}

	reg := &engine.GraphRegistries{Nodes: NodeRegistry(abs, def)}
	runner, err := engine.NewRunnerWith(def, reg)
	if err != nil {
		return fmt.Errorf("build runner: %w", err)
	}

	runner.Graph.(*engine.DefaultGraph).SetObserver(circuit.MultiObserver{observer, obs})

	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	if err := runner.Walk(ctx, walker, string(def.Start)); err != nil {
		return fmt.Errorf("circuit: %w", err)
	}

	if report, ok := capture.ArtifactAt("report"); ok {
		if text, ok := report.Raw().(string); ok {
			fmt.Print(text)
		}
	}

	return nil
}
