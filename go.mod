module github.com/dpopsuev/achilles

go 1.24.0

// TODO: Remove replace directive after publishing origami to GitHub
replace github.com/dpopsuev/origami => /home/dpopsuev/Workspace/origami

require (
	github.com/dpopsuev/origami v0.0.0-00010101000000-000000000000
	github.com/spf13/cobra v1.10.2
)

require (
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/spf13/pflag v1.0.9 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
