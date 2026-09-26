# VexAudit

VexAudit reconciles vulnerability findings with OpenVEX claims in the context of a CycloneDX dependency graph. It preserves uncertainty when a claim covers only one of several paths to a vulnerable component.

## Try it

Install the current MoonBit toolchain and Node.js, then run from this repository:

```sh
moon run src/cli --target js samples/diamond/bom.cdx.json samples/diamond/findings.json samples/diamond/partial.openvex.json
```

The finding remains `Incomplete`: one OpenVEX statement covers the path through `left`, while the vulnerable library is also reachable through `right`. Run the same command with `samples/diamond/complete.openvex.json` to see `NotAffected` with both contributing statement IDs. These examples are synthetic and make no claim about a real vulnerability.

Use `samples/diamond/history.openvex.json` to see an `under_investigation` claim superseded by a later `fixed` claim. The active claim appears in `statement_ids`; the older claim remains visible in each path's `superseded_statement_ids`.

Use `samples/diamond/unrelated-cycle.cdx.json` instead of the original SBOM to add a separate cyclic branch. With `complete.openvex.json`, the finding still receives `NotAffected`: that branch cannot reach the affected component. Traversal indexes dependency edges and follows only branches that can reach each target, preserving the original order of relevant path evidence.

For a [Trivy JSON report](https://trivy.dev/latest/docs/configuration/reporting/), pass `--trivy` before the three input files:

```sh
moon run src/cli --target js --trivy samples/diamond/bom.cdx.json samples/diamond/trivy.json samples/diamond/partial.openvex.json
```

This mode reads `Results[].Vulnerabilities[]` and joins each finding to the SBOM by `PkgIdentifier.PURL`. If that PURL is absent, it can use `PkgIdentifier.UID` to find a single PURL in the same result's `Packages[].Identifier`; [Trivy maintainers document this UID join](https://github.com/aquasecurity/trivy/discussions/10631). Conflicting package entries remain unresolved, and names alone never establish identity. Run Trivy with `--list-all-pkgs` when the package list is needed for this fallback. The output keeps the usual `decisions` array and adds `unresolved` for scanner rows without a vulnerability ID or reliable PURL. Each row names its position in the Trivy report and its `Target`. The sample shows both a UID join and an unresolved row. Review `unresolved` before treating the decisions as a complete audit. Trivy can omit `Results` or `Vulnerabilities` when there are no findings; the reader accepts those empty cases.

The `audit` package is a pure MoonBit core. It accepts an inventory, findings, and statements as values and returns one decision per finding. Each decision records the source statement IDs that contributed to it. Its `paths` array shows each dependency path as BOM references and PURLs, with the applicable statement IDs and statuses for that path. An empty `statement_ids` array on a path shows exactly where coverage is missing. `NoClaim`, `Incomplete`, and `Conflict` are distinct outcomes; the library never treats a missing claim as proof that a product is unaffected.

The main library flow is `@wire.read_cyclonedx`, `@wire.read_findings` or `@wire.read_trivy_json`, `@wire.read_openvex`, then `@audit.reconcile` and `@audit.report_json` or `@wire.trivy_report_json`. The command uses the same API and prints the JSON report. Invalid input or unreadable files exit with status 2. Without a gate, a valid report exits with status 0, including when its outcome is `Incomplete` or `Conflict` or it has unresolved Trivy rows.

For CI, add `--require-clear` before the input paths (it can be combined with `--trivy` in either order). This exits with status 0 only when every finding has a complete `NotAffected` or `Fixed` outcome and every Trivy row was resolved. It exits with status 1 for any other outcome or unresolved row, while still writing the full JSON report to stdout. An empty findings set passes. The reusable `@audit.all_findings_cleared` function applies the same outcome rule to a library report; callers using Trivy must also inspect `TrivyImport.unresolved`.

The first release uses exact PURL strings and explicit vulnerability IDs or aliases. It does not infer equivalence from PURL qualifiers, package names, or vulnerability descriptions.

## Inputs

The `wire` package reads CycloneDX 1.6 JSON, standalone OpenVEX v0.2.0 JSON, a small scanner-independent findings document, and Trivy JSON vulnerability reports. The SBOM must identify its root in `metadata.component`, give each component a `bom-ref` and PURL, and use `dependencies` to connect the root to affected components. OpenVEX subjects must have PURL identifiers. The reader validates the fields it uses; it is not a full CycloneDX, OpenVEX, or Trivy JSON Schema validator.

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

`read_cyclonedx`, `read_openvex`, and `read_findings` return errors for malformed or unsupported inputs. `read_trivy_json` returns valid rows together with unresolved rows that lack identifiers needed for reconciliation. It does not guess a PURL from a package name. In particular, a VEX statement with a `not_affected` status needs a valid justification or an impact statement; an `affected` statement needs an action statement. No network lookup or alias inference occurs.

The report describes claims and graph coverage; it does not authenticate the VEX author or independently verify the vulnerability analysis. A newer statement replaces an older one only when the document ID, author string, primary vulnerability ID, product PURL, and subcomponent set are identical. Equal timestamps, different documents or authors, and overlapping but different scopes remain visible as `Conflict` when statuses disagree. Timestamps must use RFC 3339; leap-second notation is not supported. Versionless PURL matching, qualifier subset matching, embedded VEX documents, non-PURL identifiers, and more than 1,024 dependency paths are outside this release's supported matching profile. If traversal encounters a cycle on a branch that can reach the target or exceeds the path limit, the outcome cannot be a complete favorable claim. Invalid dependency references or duplicate BOM references supplied directly to the core also prevent complete favorable claims.

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
