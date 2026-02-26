// Achilles — Go vulnerability scanner built on the Origami agentic pipeline framework.
//
// Second reference implementation proving Origami works for any domain.
// Zero Asterisk-domain imports. Uses only github.com/dpopsuev/origami and stdlib.
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
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"time"

	fw "github.com/dpopsuev/origami"

	"github.com/spf13/cobra"
)

//go:embed pipelines/achilles.yaml
var pipelineYAML []byte

func init() {
	fw.RegisterEmbeddedPipeline("achilles", pipelineYAML)
}

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

func resolvePipeline() (*fw.PipelineDef, error) {
	data, err := fw.ResolvePipelinePath("achilles")
	if err != nil {
		return nil, fmt.Errorf("resolve pipeline: %w", err)
	}
	def, err := fw.LoadPipeline(data)
	if err != nil {
		return nil, fmt.Errorf("parse pipeline: %w", err)
	}
	return def, nil
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

	walker := fw.DefaultWalker()
	capture := fw.NewOutputCapture()

	observer := fw.WalkObserverFunc(func(e fw.WalkEvent) {
		switch e.Type {
		case fw.EventNodeEnter:
			fmt.Printf("  %s[%s]%s entering %s%s%s...\n",
				dim, walker.Identity().PersonaName, reset,
				bold, e.Node, reset)
		case fw.EventNodeExit:
			if e.Error != nil {
				fmt.Printf("  %s[%s]%s %s%s failed: %v%s\n",
					dim, walker.Identity().PersonaName, reset,
					red, e.Node, e.Error, reset)
			} else {
				fmt.Printf("  %s[%s]%s %s%s%s complete (%s)\n",
					dim, walker.Identity().PersonaName, reset,
					green, e.Node, reset, e.Elapsed)
			}
		case fw.EventTransition:
			fmt.Printf("  %s→ %s%s\n", dim, e.Edge, reset)
		}
	})

	fmt.Printf("\n%s%s=== Achilles — Origami Pipeline ===%s\n\n", bold, cyan, reset)
	fmt.Printf("  Repository: %s%s%s\n", bold, abs, reset)
	fmt.Printf("  Pipeline:   achilles (4 nodes, 6 edges)\n")
	fmt.Printf("  Walker:     %s (element=%s)\n\n",
		walker.Identity().PersonaName, walker.Identity().Element)

	def, err := resolvePipeline()
	if err != nil {
		return err
	}

	reg := fw.GraphRegistries{Nodes: NodeRegistry(abs)}
	runner, err := fw.NewRunnerWith(def, reg)
	if err != nil {
		return fmt.Errorf("build runner: %w", err)
	}

	runner.Graph.(*fw.DefaultGraph).SetObserver(fw.MultiObserver{observer, capture})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	if err := runner.Walk(ctx, walker, def.Start); err != nil {
		return fmt.Errorf("pipeline: %w", err)
	}

	if report, ok := capture.ArtifactAt("report"); ok {
		if text, ok := report.Raw().(string); ok {
			fmt.Print(text)
		}
	}

	return nil
}

func runRender(_ *cobra.Command, _ []string) error {
	def, err := resolvePipeline()
	if err != nil {
		return err
	}
	fmt.Println(fw.Render(def))
	return nil
}

func runValidate(_ *cobra.Command, _ []string) error {
	def, err := resolvePipeline()
	if err != nil {
		return err
	}
	if err := def.Validate(); err != nil {
		return fmt.Errorf("validate: %w", err)
	}
	reg := fw.GraphRegistries{Nodes: NodeRegistry(".")}
	if _, err := def.BuildGraph(reg); err != nil {
		return fmt.Errorf("build graph (dry run): %w", err)
	}
	fmt.Println("OK: pipeline is valid")
	return nil
}
