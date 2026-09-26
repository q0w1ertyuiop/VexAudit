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
fn dated_claim(
  id : String,
  author : String,
  timestamp : String,
  product : String,
  status : Status,
) -> Statement {
  {
    id,
    document_id: "https://example.test/vex/history",
    author,
    timestamp,
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

///|
test "a later same-author claim replaces the same scope across time zones" {
  let old = dated_claim(
    "old",
    "Example Team",
    "2026-09-25T00:00:00+02:00",
    "pkg:generic/app@1",
    Affected,
  )
  let current = dated_claim(
    "current",
    "Example Team",
    "2026-09-24T23:00:00Z",
    "pkg:generic/app@1",
    Fixed,
  )
  let decision = reconcile_one(diamond(), [old, current], vulnerable_lib())
  assert_eq(decision.outcome, Fixed)
  assert_eq(decision.statement_ids, ["current"])
  assert_eq(decision.paths[0].superseded_statement_ids, ["old"])
  assert_eq(decision.paths[1].superseded_statement_ids, ["old"])
}

///|
test "same instant and different authors do not silently resolve conflicts" {
  let old = dated_claim(
    "old",
    "Example Team",
    "2026-09-25T00:00:00+02:00",
    "pkg:generic/app@1",
    Affected,
  )
  let same_instant = dated_claim(
    "same-instant",
    "Example Team",
    "2026-09-24T22:00:00Z",
    "pkg:generic/app@1",
    Fixed,
  )
  assert_eq(
    reconcile_one(diamond(), [old, same_instant], vulnerable_lib()).outcome,
    Conflict,
  )
  let other_author = dated_claim(
    "other-author",
    "Another Team",
    "2026-09-26T00:00:00Z",
    "pkg:generic/app@1",
    Fixed,
  )
  assert_eq(
    reconcile_one(diamond(), [old, other_author], vulnerable_lib()).outcome,
    Conflict,
  )
}

///|
test "a narrower later claim cannot replace a broader scope" {
  let broad = dated_claim(
    "broad",
    "Example Team",
    "2026-09-24T00:00:00Z",
    "pkg:generic/app@1",
    Affected,
  )
  let narrow = dated_claim(
    "narrow",
    "Example Team",
    "2026-09-25T00:00:00Z",
    "pkg:generic/left@1",
    NotAffected,
  )
  let decision = reconcile_one(diamond(), [broad, narrow], vulnerable_lib())
  assert_eq(decision.outcome, Conflict)
  assert_eq(decision.paths[0].statement_ids, ["broad", "narrow"])
  assert_eq(decision.paths[1].statement_ids, ["broad"])
}

///|
test "a separate document cannot silently replace an earlier document" {
  let old = dated_claim(
    "old",
    "Example Team",
    "2026-09-24T00:00:00Z",
    "pkg:generic/app@1",
    Affected,
  )
  let newer : Statement = {
    id: "other-document",
    document_id: "https://example.test/vex/independent",
    author: "Example Team",
    timestamp: "2026-09-25T00:00:00Z",
    vulnerability: "CVE-2026-1000",
    aliases: [],
    status: Fixed,
    subjects: [
      {
        product_purl: "pkg:generic/app@1",
        subcomponent_purls: ["pkg:generic/lib@2"],
      },
    ],
  }
  assert_eq(
    reconcile_one(diamond(), [old, newer], vulnerable_lib()).outcome,
    Conflict,
  )
}

///|
test "release gate accepts complete favorable claims and rejects uncertain findings" {
  let inventory = diamond()
  let finding = vulnerable_lib()
  let clear = reconcile(
    inventory,
    [
      claim("left", "pkg:generic/left@1", NotAffected),
      claim("right", "pkg:generic/right@1", NotAffected),
    ],
    [finding],
  )
  assert_eq(all_findings_cleared(clear), true)
  assert_eq(
    all_findings_cleared(
      reconcile(inventory, [claim("fixed", "pkg:generic/app@1", Fixed)], [
        finding,
      ]),
    ),
    true,
  )
  assert_eq(
    all_findings_cleared(
      reconcile(
        inventory,
        [claim("partial", "pkg:generic/left@1", NotAffected)],
        [finding],
      ),
    ),
    false,
  )
  assert_eq(
    all_findings_cleared(
      reconcile(inventory, [claim("affected", "pkg:generic/app@1", Affected)], [
        finding,
      ]),
    ),
    false,
  )
  assert_eq(all_findings_cleared(reconcile(inventory, [], [finding])), false)
  assert_eq(all_findings_cleared(reconcile(inventory, [], [])), true)
}

///|
test "unrelated branching and cycles do not alter target path evidence" {
  let inventory = diamond()
  for layer in 0..<24 {
    for side in 0..<2 {
      let node = "unrelated-\{layer}-\{side}"
      inventory.components.push({
        bom_ref: node,
        purl: "pkg:generic/\{node}@1",
      })
      if layer == 0 {
        inventory.edges.push({ parent: "app", child: node, })
      } else {
        for previous_side in 0..<2 {
          inventory.edges.push({
            parent: "unrelated-\{layer - 1}-\{previous_side}",
            child: node,
          })
        }
      }
    }
  }
  inventory.edges.push({ parent: "unrelated-23-0", child: "unrelated-0-0", })
  let decision = reconcile_one(
    inventory,
    [claim("root", "pkg:generic/app@1", NotAffected)],
    vulnerable_lib(),
  )
  assert_eq(decision.outcome, NotAffected)
  assert_eq(decision.paths.length(), 2)
  assert_eq(decision.paths[0].bom_refs, ["app", "left", "lib"])
  assert_eq(decision.paths[1].bom_refs, ["app", "right", "lib"])
}

///|
test "cycles that can reach the target still prevent a complete claim" {
  let inventory = diamond()
  inventory.edges.push({ parent: "left", child: "right", })
  inventory.edges.push({ parent: "right", child: "left", })
  let decision = reconcile_one(
    inventory,
    [claim("root", "pkg:generic/app@1", NotAffected)],
    vulnerable_lib(),
  )
  assert_eq(decision.outcome, Incomplete)
  assert_eq(decision.paths.length(), 4)
}

///|
test "invalid references and duplicate BOM references cannot be pruned into success" {
  let invalid = diamond()
  invalid.edges.push({ parent: "app", child: "unknown", })
  assert_eq(
    reconcile_one(
      invalid,
      [claim("root", "pkg:generic/app@1", Fixed)],
      vulnerable_lib(),
    ).outcome,
    Incomplete,
  )
  let duplicate = diamond()
  duplicate.components.push({ bom_ref: "left", purl: "pkg:generic/another@1", })
  assert_eq(
    reconcile_one(
      duplicate,
      [claim("root", "pkg:generic/app@1", Fixed)],
      vulnerable_lib(),
    ).outcome,
    Incomplete,
  )
}

///|
test "path enumeration stops conservatively at the report limit" {
  let inventory : Inventory = {
    root_ref: "app",
    components: [
      { bom_ref: "app", purl: "pkg:generic/app@1", },
      { bom_ref: "lib", purl: "pkg:generic/lib@2", },
    ],
    edges: [],
  }
  for index in 0..<1024 {
    let node = "branch-\{index}"
    inventory.components.push({ bom_ref: node, purl: "pkg:generic/\{node}@1", })
    inventory.edges.push({ parent: "app", child: node, })
    inventory.edges.push({ parent: node, child: "lib", })
  }
  let statements = [claim("root", "pkg:generic/app@1", NotAffected)]
  let exact = reconcile_one(inventory, statements, vulnerable_lib())
  assert_eq(exact.outcome, NotAffected)
  assert_eq(exact.paths.length(), 1024)
  inventory.edges.push({ parent: "app", child: "lib", })
  let exceeded = reconcile_one(inventory, statements, vulnerable_lib())
  assert_eq(exceeded.outcome, Incomplete)
  assert_eq(exceeded.paths.length(), 1024)
}
