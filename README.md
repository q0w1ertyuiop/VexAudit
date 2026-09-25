# VexAudit

VexAudit reconciles vulnerability findings with OpenVEX claims in the context of a CycloneDX dependency graph. It preserves uncertainty when a claim covers only one of several paths to a vulnerable component.

The `audit` package is a pure MoonBit core. It accepts an inventory, findings, and statements as values and returns one decision per finding. Each decision records the source statement IDs that contributed to it. `NoClaim`, `Incomplete`, and `Conflict` are distinct outcomes; the library never treats a missing claim as proof that a product is unaffected.

The first release uses exact PURL strings and explicit vulnerability IDs or aliases. It does not infer equivalence from PURL qualifiers, package names, or vulnerability descriptions.

## Development

```text
moon check --target wasm --deny-warn
moon test --target wasm --deny-warn
```

The `wire` package contains format readers under development. The command-line workflow and input examples will be documented with that entry point.

## License

MIT.
