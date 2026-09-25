///|
test "Trivy findings retain their source row and package URL" {
  let source =
    #|{"SchemaVersion":2,"Results":[{"Target":"image:latest","Vulnerabilities":[{"VulnerabilityID":"CVE-2026-1000","PkgIdentifier":{"PURL":"pkg:generic/shared@2.0.0"}}]},{"Target":"other","Vulnerabilities":[{"VulnerabilityID":"CVE-2026-2000","PkgIdentifier":{"PURL":"pkg:generic/other@1"}}]}]}
  let imported = match read_trivy_json(source) {
    Ok(value) => value
    Err(message) => abort(message)
  }
  assert_eq(imported.findings.length(), 2)
  assert_eq(imported.findings[0].id, "Results[0].Vulnerabilities[0]")
  assert_eq(imported.findings[0].component_purl, "pkg:generic/shared@2.0.0")
  assert_eq(imported.findings[1].vulnerability, "CVE-2026-2000")
  assert_eq(imported.unresolved.length(), 0)
}

///|
test "Trivy rows without a PURL or vulnerability ID remain visible" {
  let source =
    #|{"SchemaVersion":2,"Results":[{"Target":"example","Vulnerabilities":[{"VulnerabilityID":"CVE-2026-1000","PkgName":"shared"},{"PkgIdentifier":{"PURL":"pkg:generic/shared@2.0.0"}}]}]}
  let imported = match read_trivy_json(source) {
    Ok(value) => value
    Err(message) => abort(message)
  }
  assert_eq(imported.findings.length(), 0)
  assert_eq(imported.unresolved.length(), 2)
  assert_eq(imported.unresolved[0].row, "Results[0].Vulnerabilities[0]")
  assert_eq(imported.unresolved[0].target, "example")
  assert_eq(imported.unresolved[0].vulnerability, "CVE-2026-1000")
  assert_eq(imported.unresolved[1].reason, "VulnerabilityID is missing")
  let output = trivy_report_json({ decisions: [], }, imported)
  assert_eq(output.contains("\"unresolved\""), true)
  assert_eq(output.contains("Results[0].Vulnerabilities[0]"), true)
}

///|
test "Trivy can omit Results and Vulnerabilities when no findings exist" {
  let imported = match read_trivy_json("{\"SchemaVersion\":2}") {
    Ok(value) => value
    Err(message) => abort(message)
  }
  assert_eq(imported.findings.length(), 0)
  assert_eq(imported.unresolved.length(), 0)
  let empty_result = match
    read_trivy_json("{\"Results\":[{\"Target\":\"empty\"}]}") {
    Ok(value) => value
    Err(message) => abort(message)
  }
  assert_eq(empty_result.findings.length(), 0)
  assert_eq(read_trivy_json("{}") is Err(_), true)
  assert_eq(read_trivy_json("{\"SchemaVersion\":\"2\"}") is Err(_), true)
  assert_eq(read_trivy_json("{\"Results\":{}}") is Err(_), true)
}
