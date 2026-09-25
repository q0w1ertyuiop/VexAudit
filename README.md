# VexAudit

VexAudit reconciles vulnerability findings with OpenVEX claims in the context of a CycloneDX dependency graph. It preserves uncertainty when a claim covers only one of several paths to a vulnerable component.

## Try it

Install the current MoonBit toolchain and Node.js, then run from this repository:

```sh
moon run src/cli --target js samples/diamond/bom.cdx.json samples/diamond/findings.json samples/diamond/partial.openvex.json
```

The finding remains `Incomplete`: one OpenVEX statement covers the path through `left`, while the vulnerable library is also reachable through `right`. Run the same command with `samples/diamond/complete.openvex.json` to see `NotAffected` with both contributing statement IDs. These examples are synthetic and make no claim about a real vulnerability.

Use `samples/diamond/history.openvex.json` to see an `under_investigation` claim superseded by a later `fixed` claim. The active claim appears in `statement_ids`; the older claim remains visible in each path's `superseded_statement_ids`.

The `audit` package is a pure MoonBit core. It accepts an inventory, findings, and statements as values and returns one decision per finding. Each decision records the source statement IDs that contributed to it. Its `paths` array shows each dependency path as BOM references and PURLs, with the applicable statement IDs and statuses for that path. An empty `statement_ids` array on a path shows exactly where coverage is missing. `NoClaim`, `Incomplete`, and `Conflict` are distinct outcomes; the library never treats a missing claim as proof that a product is unaffected.

The main library flow is `@wire.read_cyclonedx`, `@wire.read_findings`, `@wire.read_openvex`, then `@audit.reconcile` and `@audit.report_json`. The command uses the same API and prints the JSON report. Invalid input or unreadable files exit with status 2. A valid report exits with status 0, including when its outcome is `Incomplete` or `Conflict`; callers can apply their own CI policy to the report.

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

The report describes claims and graph coverage; it does not authenticate the VEX author or independently verify the vulnerability analysis. A newer statement replaces an older one only when the document ID, author string, primary vulnerability ID, product PURL, and subcomponent set are identical. Equal timestamps, different documents or authors, and overlapping but different scopes remain visible as `Conflict` when statuses disagree. Timestamps must use RFC 3339; leap-second notation is not supported. Versionless PURL matching, qualifier subset matching, embedded VEX documents, non-PURL identifiers, and more than 1,024 dependency paths are outside this release's supported matching profile. If path traversal encounters a cycle or reaches the path limit, the outcome cannot be a complete favorable claim.

## Development

```text
moon check --target wasm --deny-warn
moon test --target wasm --deny-warn
moon test --target wasm-gc --deny-warn
moon test --target js --deny-warn
```

The `src/cli` package is a Node.js command; the library packages are tested on Wasm, Wasm-GC, and JavaScript.

## License

MIT.
