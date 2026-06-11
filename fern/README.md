# Fern SDK generator scaffold (proposal)

This directory holds a [Fern](https://buildwithfern.com) configuration that
generates a Go SDK from the Castle OpenAPI specification.

## Layout

```
fern/
├── fern.config.json        # Fern organization + CLI version
├── generators.yml          # generator groups (go-sdk)
├── openapi/
│   └── openapi.yml         # Castle OpenAPI specification
└── README.md               # this file
```

## Usage

Install the Fern CLI:

```bash
npm install -g fern-api
```

Validate the configuration and specification:

```bash
fern check
```

Generate the Go SDK locally:

```bash
fern generate --group go-sdk --local
```

## Output

The `go-sdk` group writes generated code to `../generated/go` (relative to
`fern/`), i.e. outside the `fern/` directory. That output is not committed: only
the `fern/` scaffold (YAML, JSON, Markdown) is tracked in this repository.
