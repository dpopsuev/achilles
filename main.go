// Achilles — Go vulnerability scanner built on the Origami agentic pipeline framework.
//
// Second reference implementation proving Origami works for any domain.
// Zero imports from internal/ (Asterisk domain). Uses only pkg/framework/ and stdlib.
//
// Run it:
//
//	go run . scan .
//	go run . scan /path/to/any/go/repo
//	go run . render
//	go run . validate
package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	fw "github.com/dpopsuev/origami"

	"github.com/spf13/cobra"
)

func main() {
	root := &cobra.Command{
		Use:   "achilles",
		Short: "Go vulnerability scanner — powered by Origami",
		Long: `Achilles scans Go repositories for known vulnerabilities using govulncheck,
classifies findings by severity, and produces a security assessment.

Built on the Origami agentic pipeline framework — the same DSL, graph walk,
elements, and extractors that power Asterisk's root cause analysis engine.`,
	}

	scanCmd := &cobra.Command{
		Use:   "scan [repo-path]",
		Short: "Scan a Go repository for vulnerabilities",
		Args:  cobra.MaximumNArgs(1),
		RunE:  runScan,
	}

	renderCmd := &cobra.Command{
		Use:   "render",
		Short: "Render the achilles pipeline as a Mermaid diagram",
		RunE:  runRender,
	}

	validateCmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate the pipeline YAML without executing",
		RunE:  runValidate,
	}

	root.AddCommand(scanCmd, renderCmd, validateCmd)

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func pipelinePath() string {
	_, thisFile, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(thisFile), "pipelines", "achilles.yaml")
}

func runScan(_ *cobra.Command, args []string) error {
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

	persona, _ := fw.PersonaByName("Herald")
	walker := &achillesWalker{
		identity: persona.Identity,
		state:    fw.NewWalkerState("achilles-1"),
	}

	observer := fw.WalkObserverFunc(func(e fw.WalkEvent) {
		switch e.Type {
		case fw.EventNodeEnter:
			fmt.Printf("  %s[%s]%s entering %s%s%s...\n",
				dim, walker.identity.PersonaName, reset,
				bold, e.Node, reset)
		case fw.EventNodeExit:
			if e.Error != nil {
				fmt.Printf("  %s[%s]%s %s%s failed: %v%s\n",
					dim, walker.identity.PersonaName, reset,
					red, e.Node, e.Error, reset)
			} else {
				fmt.Printf("  %s[%s]%s %s%s%s complete (%s)\n",
					dim, walker.identity.PersonaName, reset,
					green, e.Node, reset, e.Elapsed)
			}
		case fw.EventTransition:
			fmt.Printf("  %s→ %s%s\n", dim, e.Edge, reset)
		}
	})

	fmt.Printf("\n%s%s=== Achilles — Origami Pipeline ===%s\n\n", bold, cyan, reset)
	fmt.Printf("  Repository: %s%s%s\n", bold, abs, reset)
	fmt.Printf("  Pipeline:   achilles (4 nodes, 6 edges)\n")
	fmt.Printf("  Walker:     %s (element=%s)\n\n", persona.Identity.PersonaName, persona.Identity.Element)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	err = fw.Run(ctx, pipelinePath(), nil,
		fw.WithNodes(NodeRegistry(abs)),
		fw.WithWalker(walker),
		fw.WithRunObserver(observer),
	)
	if err != nil {
		return fmt.Errorf("pipeline: %w", err)
	}

	if report, ok := walker.state.Context["report"]; ok {
		fmt.Print(report)
	}

	return nil
}

func runRender(_ *cobra.Command, _ []string) error {
	data, err := os.ReadFile(pipelinePath())
	if err != nil {
		return fmt.Errorf("read pipeline: %w", err)
	}
	def, err := fw.LoadPipeline(data)
	if err != nil {
		return fmt.Errorf("parse pipeline: %w", err)
	}
	fmt.Println(fw.Render(def))
	return nil
}

func runValidate(_ *cobra.Command, _ []string) error {
	if err := fw.Validate(pipelinePath(), fw.WithNodes(NodeRegistry("."))); err != nil {
		return err
	}
	fmt.Println("OK: pipeline is valid")
	return nil
}

// achillesWalker implements framework.Walker for the vulnerability scan pipeline.
type achillesWalker struct {
	identity fw.AgentIdentity
	state    *fw.WalkerState
}

func (w *achillesWalker) Identity() fw.AgentIdentity { return w.identity }
func (w *achillesWalker) State() *fw.WalkerState     { return w.state }

func (w *achillesWalker) Handle(ctx context.Context, node fw.Node, nc fw.NodeContext) (fw.Artifact, error) {
	artifact, err := node.Process(ctx, nc)
	if err != nil {
		return nil, err
	}

	if node.Name() == "report" {
		if ra, ok := artifact.Raw().(string); ok {
			w.state.Context["report"] = ra
		}
	}

	return artifact, nil
}
