///|
test "parse three inputs and preserve the source statement in the decision" {
  let sbom =
    #|{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"component":{"bom-ref":"app","purl":"pkg:generic/app@1"}},"components":[{"bom-ref":"lib","purl":"pkg:generic/lib@2"}],"dependencies":[{"ref":"app","dependsOn":["lib"]},{"ref":"lib","dependsOn":[]}]}
  let findings =
    #|{"findings":[{"id":"scan-1","vulnerability":"GHSA-abcd-1234-wxyz","component_purl":"pkg:generic/lib@2"}]}
  let vex =
    #|{"@context":"https://openvex.dev/ns/v0.2.0","@id":"https://example.test/vex/1","author":"Example Team","timestamp":"2026-09-25T00:00:00Z","version":1,"statements":[{"@id":"https://example.test/vex/1#s1","vulnerability":{"name":"CVE-2026-1000","aliases":["GHSA-abcd-1234-wxyz"]},"products":[{"@id":"pkg:generic/app@1","subcomponents":[{"@id":"pkg:generic/lib@2"}]}],"status":"not_affected","justification":"vulnerable_code_not_present"}]}
  let inventory = match read_cyclonedx(sbom) {
    Ok(value) => value
    Err(message) => abort(message)
  }
  let finding_rows = match read_findings(findings) {
    Ok(value) => value
    Err(message) => abort(message)
  }
  let statements = match read_openvex(vex) {
    Ok(value) => value
    Err(message) => abort(message)
  }
  let report = @audit.reconcile(inventory, statements, finding_rows)
  assert_eq(report.decisions[0].outcome, @audit.NotAffected)
  assert_eq(report.decisions[0].statement_ids, ["https://example.test/vex/1#s1"])
  assert_eq(report.decisions[0].paths[0].purls, [
    "pkg:generic/app@1", "pkg:generic/lib@2",
  ])
  assert_eq(report.decisions[0].paths[0].statement_ids, [
    "https://example.test/vex/1#s1",
  ])
}

///|
test "invalid OpenVEX justifications are rejected before reconciliation" {
  let vex =
    #|{"@context":"https://openvex.dev/ns/v0.2.0","@id":"https://example.test/vex/2","author":"Example Team","timestamp":"2026-09-25T00:00:00Z","version":1,"statements":[{"vulnerability":{"name":"CVE-2026-1000"},"products":[{"@id":"pkg:generic/app@1"}],"status":"not_affected"}]}
  assert_eq(read_openvex(vex) is Err(_), true)
}

///|
test "conflicting subject identifiers cannot silently select one PURL" {
  let vex =
    #|{"@context":"https://openvex.dev/ns/v0.2.0","@id":"https://example.test/vex/3","author":"Example Team","timestamp":"2026-09-25T00:00:00Z","version":1,"statements":[{"vulnerability":{"name":"CVE-2026-1000"},"products":[{"@id":"pkg:generic/app@1","identifiers":{"purl":"pkg:generic/other@1"}}],"status":"fixed"}]}
  assert_eq(read_openvex(vex) is Err(_), true)
}

///|
test "unknown BOM references cannot fabricate graph coverage" {
  let sbom =
    #|{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"component":{"bom-ref":"app","purl":"pkg:generic/app@1"}},"components":[],"dependencies":[{"ref":"app","dependsOn":["missing"]}]}
  assert_eq(read_cyclonedx(sbom) is Err(_), true)
}

///|
test "statement time overrides document time" {
  let vex =
    #|{"@context":"https://openvex.dev/ns/v0.2.0","@id":"https://example.test/vex/4","author":"Example Team","timestamp":"2026-09-25T00:00:00Z","version":1,"statements":[{"timestamp":"2026-09-24T00:00:00Z","vulnerability":{"name":"CVE-2026-1000"},"products":[{"@id":"pkg:generic/app@1"}],"status":"fixed"}]}
  let statements = match read_openvex(vex) {
    Ok(value) => value
    Err(message) => abort(message)
  }
  assert_eq(statements[0].timestamp, "2026-09-24T00:00:00Z")
}
