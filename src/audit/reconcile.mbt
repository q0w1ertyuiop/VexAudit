///|
fn component_purl(inventory : Inventory, bom_ref : String) -> String? {
  for component in inventory.components {
    if component.bom_ref == bom_ref {
      return Some(component.purl)
    }
  }
  None
}

///|
fn collect_paths(
  inventory : Inventory,
  current : String,
  target : String,
  path : Array[String],
  paths : Array[Array[String]],
  uncertain : Ref[Bool],
) -> Unit {
  if paths.length() >= 1024 || path.length() > inventory.components.length() {
    uncertain.val = true
    return
  }
  if path.contains(current) {
    uncertain.val = true
    return
  }
  if component_purl(inventory, current) is None {
    uncertain.val = true
    return
  }
  let next : Array[String] = []
  for item in path {
    next.push(item)
  }
  next.push(current)
  if current == target {
    paths.push(next)
    return
  }
  for edge in inventory.edges {
    if edge.parent == current {
      collect_paths(inventory, edge.child, target, next, paths, uncertain)
    }
  }
}

///|
fn statement_applies(
  inventory : Inventory,
  statement : Statement,
  finding : Finding,
  path : Array[String],
) -> Bool {
  if statement.vulnerability != finding.vulnerability &&
    !statement.aliases.contains(finding.vulnerability) {
    return false
  }
  for subject in statement.subjects {
    if !subject.subcomponent_purls.is_empty() &&
      !subject.subcomponent_purls.contains(finding.component_purl) {
      continue
    }
    for node in path {
      if component_purl(inventory, node) == Some(subject.product_purl) {
        return true
      }
    }
  }
  false
}

///|
fn outcome_of_status(status : Status) -> Outcome {
  match status {
    NotAffected => Outcome::NotAffected
    Affected => Outcome::Affected
    Fixed => Outcome::Fixed
    UnderInvestigation => Outcome::UnderInvestigation
  }
}

///| Evaluate a finding against all known paths from the inventory root.

///|
/// A favorable claim is never inferred from an absent or ambiguous path.
pub fn reconcile_one(
  inventory : Inventory,
  statements : Array[Statement],
  finding : Finding,
) -> Decision {
  let targets : Array[String] = []
  for component in inventory.components {
    if component.purl == finding.component_purl {
      targets.push(component.bom_ref)
    }
  }
  if targets.is_empty() {
    return {
      finding_id: finding.id,
      outcome: ComponentMissing,
      statement_ids: [],
      detail: "finding component is absent from the SBOM",
    }
  }
  let paths : Array[Array[String]] = []
  let uncertain = Ref(false)
  let mut missing_target_path = false
  for target in targets {
    let before = paths.length()
    collect_paths(inventory, inventory.root_ref, target, [], paths, uncertain)
    if paths.length() == before {
      missing_target_path = true
    }
  }
  if paths.is_empty() {
    return {
      finding_id: finding.id,
      outcome: if uncertain.val {
        Incomplete
      } else {
        Unreachable
      },
      statement_ids: [],
      detail: "the SBOM does not establish a dependency path to this component",
    }
  }
  let statuses : Array[Status] = []
  let statement_ids : Array[String] = []
  let mut uncovered = false
  for path in paths {
    let mut path_covered = false
    for statement in statements {
      if statement_applies(inventory, statement, finding, path) {
        path_covered = true
        if !statuses.contains(statement.status) {
          statuses.push(statement.status)
        }
        if !statement_ids.contains(statement.id) {
          statement_ids.push(statement.id)
        }
      }
    }
    if !path_covered {
      uncovered = true
    }
  }
  let (outcome, detail) = if statuses.length() > 1 {
    (Conflict, "applicable statements disagree on status")
  } else if statuses.is_empty() {
    (NoClaim, "no OpenVEX statement applies")
  } else if uncovered || uncertain.val || missing_target_path {
    (Incomplete, "the statement does not cover every known dependency path")
  } else {
    (outcome_of_status(statuses[0]), "all dependency paths have the same claim")
  }
  { finding_id: finding.id, outcome, statement_ids, detail, }
}

///|
pub fn reconcile(
  inventory : Inventory,
  statements : Array[Statement],
  findings : Array[Finding],
) -> Report {
  let decisions : Array[Decision] = []
  for finding in findings {
    decisions.push(reconcile_one(inventory, statements, finding))
  }
  { decisions, }
}
