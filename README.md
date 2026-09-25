# VexAudit

VexAudit reconciles vulnerability findings with OpenVEX claims in the context of a CycloneDX dependency graph. It preserves uncertainty when a claim covers only one of several paths to a vulnerable component.

The `audit` package is a pure MoonBit core. It accepts an inventory, findings, and statements as values and returns one decision per finding. Each decision records the source statement IDs that contributed to it. `NoClaim`, `Incomplete`, and `Conflict` are distinct outcomes; the library never treats a missing claim as proof that a product is unaffected.

The first release uses exact PURL strings and explicit vulnerability IDs or aliases. It does not infer equivalence from PURL qualifiers, package names, or vulnerability descriptions.

## Inputs

The `wire` package reads CycloneDX 1.6 JSON, standalone OpenVEX v0.2.0 JSON, and a small scanner-independent findings document. The SBOM must identify its root in `metadata.component`, give each component a `bom-ref` and PURL, and use `dependencies` to connect the root to affected components. OpenVEX subjects must have PURL identifiers. The reader validates the fields it uses; it is not a full CycloneDX or OpenVEX JSON Schema validator.

The findings document has this shape:

```json
{
  "findings": [
    {
      "id": "scanner-row-1",
      "vulnerability": "CVE-2026-1000",
      "component_purl": "pkg:generic/library@2"
    }
  ]
}
```

`read_cyclonedx`, `read_openvex`, and `read_findings` return errors for malformed or unsupported inputs. In particular, a VEX statement with a `not_affected` status needs a valid justification or an impact statement; an `affected` statement needs an action statement. No network lookup or alias inference occurs.

## Development

```text
moon check --target wasm --deny-warn
moon test --target wasm --deny-warn
```

The command-line workflow and input examples will be documented with that entry point.

## License

MIT.
