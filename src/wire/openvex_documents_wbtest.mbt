///|
test "separate OpenVEX documents combine path coverage in input order" {
  let left =
    #|{"@context":"https://openvex.dev/ns/v0.2.0","@id":"https://example.test/left","author":"Left Team","timestamp":"2026-09-25T00:00:00Z","version":1,"statements":[{"@id":"https://example.test/left#s1","vulnerability":{"name":"CVE-2026-1000"},"products":[{"@id":"pkg:generic/left@1","subcomponents":[{"@id":"pkg:generic/lib@2"}]}],"status":"not_affected","justification":"vulnerable_code_not_present"}]}
  let right =
    #|{"@context":"https://openvex.dev/ns/v0.2.0","@id":"https://example.test/right","author":"Right Team","timestamp":"2026-09-26T00:00:00Z","version":1,"statements":[{"@id":"https://example.test/right#s1","vulnerability":{"name":"CVE-2026-1000"},"products":[{"@id":"pkg:generic/right@1","subcomponents":[{"@id":"pkg:generic/lib@2"}]}],"status":"not_affected","justification":"vulnerable_code_not_present"}]}
  let statements = match read_openvex_documents([left, right]) {
    Ok(value) => value
    Err(message) => abort(message)
  }
  assert_eq(statements.length(), 2)
  assert_eq(statements[0].id, "https://example.test/left#s1")
  assert_eq(statements[1].id, "https://example.test/right#s1")
  let inventory : @audit.Inventory = {
    root_ref: "app",
    components: [
      { bom_ref: "app", purl: "pkg:generic/app@1", },
      { bom_ref: "left", purl: "pkg:generic/left@1", },
      { bom_ref: "right", purl: "pkg:generic/right@1", },
      { bom_ref: "lib", purl: "pkg:generic/lib@2", },
    ],
    edges: [
      { parent: "app", child: "left", },
      { parent: "app", child: "right", },
      { parent: "left", child: "lib", },
      { parent: "right", child: "lib", },
    ],
  }
  let finding : @audit.Finding = {
    id: "scan-1",
    vulnerability: "CVE-2026-1000",
    component_purl: "pkg:generic/lib@2",
  }
  let decision = @audit.reconcile_one(inventory, statements, finding)
  assert_eq(decision.outcome, @audit.NotAffected)
  assert_eq(decision.statement_ids, [
    "https://example.test/left#s1", "https://example.test/right#s1",
  ])
}

///|
test "duplicate IDs across documents cannot obscure attribution" {
  let document =
    #|{"@context":"https://openvex.dev/ns/v0.2.0","@id":"https://example.test/vex","author":"Example Team","timestamp":"2026-09-25T00:00:00Z","version":1,"statements":[{"vulnerability":{"name":"CVE-2026-1000"},"products":[{"@id":"pkg:generic/app@1"}],"status":"fixed"}]}
  let result = read_openvex_documents([document, document])
  match result {
    Err(message) => {
      assert_eq(message.contains("documents[0] and [1]"), true)
      assert_eq(message.contains("https://example.test/vex#statement-0"), true)
    }
    Ok(_) => abort("duplicate statement ID was accepted")
  }
  assert_eq(read_openvex_documents([document, "{}"]) is Err(_), true)
}

///|
test "an audit can start without OpenVEX documents" {
  let statements = match read_openvex_documents([]) {
    Ok(value) => value
    Err(message) => abort(message)
  }
  assert_eq(statements.length(), 0)
  let inventory : @audit.Inventory = {
    root_ref: "app",
    components: [
      { bom_ref: "app", purl: "pkg:generic/app@1", },
      { bom_ref: "lib", purl: "pkg:generic/lib@2", },
    ],
    edges: [{ parent: "app", child: "lib", }],
  }
  let finding : @audit.Finding = {
    id: "scan-1",
    vulnerability: "CVE-2026-1000",
    component_purl: "pkg:generic/lib@2",
  }
  let decision = @audit.reconcile_one(inventory, statements, finding)
  assert_eq(decision.outcome, @audit.NoClaim)
  assert_eq(decision.paths.length(), 1)
  assert_eq(decision.paths[0].statement_ids, [])
}
