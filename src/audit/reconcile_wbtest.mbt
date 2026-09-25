///|
fn diamond() -> Inventory {
  {
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
}

///|
fn claim(id : String, product : String, status : Status) -> Statement {
  {
    id,
    document_id: "https://example.test/vex/1",
    author: "Example Team",
    timestamp: "2026-09-25T00:00:00Z",
    vulnerability: "CVE-2026-1000",
    aliases: [],
    status,
    subjects: [
      { product_purl: product, subcomponent_purls: ["pkg:generic/lib@2"], },
    ],
  }
}

///|
fn vulnerable_lib() -> Finding {
  {
    id: "scan-1",
    vulnerability: "CVE-2026-1000",
    component_purl: "pkg:generic/lib@2",
  }
}

///|
test "one branch cannot clear a finding reachable through two branches" {
  let decision = reconcile_one(
    diamond(),
    [claim("left-claim", "pkg:generic/left@1", NotAffected)],
    vulnerable_lib(),
  )
  assert_eq(decision.outcome, Incomplete)
  assert_eq(decision.statement_ids, ["left-claim"])
  assert_eq(decision.paths.length(), 2)
  assert_eq(decision.paths[0].bom_refs, ["app", "left", "lib"])
  assert_eq(decision.paths[0].statement_ids, ["left-claim"])
  assert_eq(decision.paths[1].bom_refs, ["app", "right", "lib"])
  assert_eq(decision.paths[1].statement_ids, [])
}

///|
test "all dependency paths must carry the same claim" {
  let decision = reconcile_one(
    diamond(),
    [
      claim("left-claim", "pkg:generic/left@1", NotAffected),
      claim("right-claim", "pkg:generic/right@1", NotAffected),
    ],
    vulnerable_lib(),
  )
  assert_eq(decision.outcome, NotAffected)
  assert_eq(decision.statement_ids, ["left-claim", "right-claim"])
  assert_eq(decision.paths[0].statuses, [NotAffected])
  assert_eq(decision.paths[1].statuses, [NotAffected])
}

///|
test "disagreeing claims remain visible" {
  let decision = reconcile_one(
    diamond(),
    [
      claim("left-claim", "pkg:generic/left@1", NotAffected),
      claim("right-claim", "pkg:generic/right@1", Affected),
    ],
    vulnerable_lib(),
  )
  assert_eq(decision.outcome, Conflict)
  assert_eq(decision.paths[0].statuses, [NotAffected])
  assert_eq(decision.paths[1].statuses, [Affected])
}

///|
test "unmatched vulnerabilities and absent components are distinct" {
  let absent_claim = claim("other-vuln", "pkg:generic/app@1", Fixed)
  let no_claim = reconcile_one(diamond(), [absent_claim], {
    id: "scan-2",
    vulnerability: "GHSA-abcd-1234-wxyz",
    component_purl: "pkg:generic/lib@2",
  })
  assert_eq(no_claim.outcome, NoClaim)
  let missing = reconcile_one(diamond(), [], {
    id: "scan-3",
    vulnerability: "CVE-2026-1000",
    component_purl: "pkg:generic/absent@1",
  })
  assert_eq(missing.outcome, ComponentMissing)
  assert_eq(missing.paths.length(), 0)
}

///|
test "a disconnected duplicate PURL prevents a complete claim" {
  let inventory = diamond()
  inventory.components.push({ bom_ref: "other-lib", purl: "pkg:generic/lib@2", })
  let decision = reconcile_one(
    inventory,
    [claim("root-claim", "pkg:generic/app@1", NotAffected)],
    vulnerable_lib(),
  )
  assert_eq(decision.outcome, Incomplete)
  assert_eq(decision.paths.length(), 2)
}
