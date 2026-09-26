///|
priv struct DependencyGraph {
  purls : Map[String, String]
  children : Map[String, Array[String]]
  parents : Map[String, Array[String]]
  valid : Bool
}

///|
fn dependency_graph(inventory : Inventory) -> DependencyGraph {
  let purls : Map[String, String] = Map([])
  let children : Map[String, Array[String]] = Map([])
  let parents : Map[String, Array[String]] = Map([])
  let mut valid = true
  for component in inventory.components {
    if purls.get(component.bom_ref) is Some(_) {
      valid = false
    } else {
      purls.set(component.bom_ref, component.purl)
    }
  }
  if purls.get(inventory.root_ref) is None {
    valid = false
  }
  for edge in inventory.edges {
    if purls.get(edge.parent) is None || purls.get(edge.child) is None {
      valid = false
    }
    match children.get(edge.parent) {
      Some(items) => items.push(edge.child)
      None => children.set(edge.parent, [edge.child])
    }
    match parents.get(edge.child) {
      Some(items) => items.push(edge.parent)
      None => parents.set(edge.child, [edge.parent])
    }
  }
  { purls, children, parents, valid, }
}

///|
fn target_ancestors(
  graph : DependencyGraph,
  target : String,
) -> Map[String, Bool] {
  let relevant : Map[String, Bool] = Map([(target, true)])
  let pending = [target]
  let mut index = 0
  while index < pending.length() {
    let current = pending[index]
    index = index + 1
    match graph.parents.get(current) {
      None => ()
      Some(items) =>
        for parent in items {
          if relevant.get(parent) is None {
            relevant.set(parent, true)
            pending.push(parent)
          }
        }
    }
  }
  relevant
}

///|
fn collect_paths(
  graph : DependencyGraph,
  node_count : Int,
  relevant : Map[String, Bool],
  current : String,
  target : String,
  path : Array[String],
  paths : Array[Array[String]],
  uncertain : Ref[Bool],
) -> Unit {
  if relevant.get(current) is None {
    return
  }
  if paths.length() >= 1024 || path.length() > node_count {
    uncertain.val = true
    return
  }
  if path.contains(current) {
    uncertain.val = true
    return
  }
  if graph.purls.get(current) is None {
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
  match graph.children.get(current) {
    None => ()
    Some(items) =>
      for child in items {
        collect_paths(
          graph, node_count, relevant, child, target, next, paths, uncertain,
        )
      }
  }
}

///|
priv struct Claim {
  statement_index : Int
  subject_index : Int
}

///|
fn subject_applies(
  graph : DependencyGraph,
  subject : Subject,
  finding : Finding,
  path : Array[String],
) -> Bool {
  if !subject.subcomponent_purls.is_empty() &&
    !subject.subcomponent_purls.contains(finding.component_purl) {
    return false
  }
  for node in path {
    if graph.purls.get(node) == Some(subject.product_purl) {
      return true
    }
  }
  false
}

///|
fn same_scope(left : Subject, right : Subject) -> Bool {
  if left.product_purl != right.product_purl ||
    left.subcomponent_purls.length() != right.subcomponent_purls.length() {
    return false
  }
  for purl in left.subcomponent_purls {
    let mut left_count = 0
    let mut right_count = 0
    for item in left.subcomponent_purls {
      if item == purl {
        left_count = left_count + 1
      }
    }
    for item in right.subcomponent_purls {
      if item == purl {
        right_count = right_count + 1
      }
    }
    if left_count != right_count {
      return false
    }
  }
  true
}

///|
fn superseded_by(
  older : Claim,
  newer : Claim,
  statements : Array[Statement],
) -> Bool {
  let old_statement = statements[older.statement_index]
  let new_statement = statements[newer.statement_index]
  if old_statement.author != new_statement.author ||
    old_statement.document_id != new_statement.document_id ||
    old_statement.vulnerability != new_statement.vulnerability ||
    !same_scope(
      old_statement.subjects[older.subject_index],
      new_statement.subjects[newer.subject_index],
    ) {
    return false
  }
  timestamp_order(old_statement.timestamp, new_statement.timestamp) == Some(-1)
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
      paths: [],
      detail: "finding component is absent from the SBOM",
    }
  }
  let graph = dependency_graph(inventory)
  let paths : Array[Array[String]] = []
  let uncertain = Ref(!graph.valid)
  let mut missing_target_path = false
  for target in targets {
    let before = paths.length()
    let relevant = target_ancestors(graph, target)
    collect_paths(
      graph,
      inventory.components.length(),
      relevant,
      inventory.root_ref,
      target,
      [],
      paths,
      uncertain,
    )
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
      paths: [],
      detail: "the SBOM does not establish a dependency path to this component",
    }
  }
  let statuses : Array[Status] = []
  let statement_ids : Array[String] = []
  let path_evidence : Array[PathEvidence] = []
  let mut uncovered = false
  for path in paths {
    let claims : Array[Claim] = []
    for statement_index, statement in statements {
      if statement.vulnerability != finding.vulnerability &&
        !statement.aliases.contains(finding.vulnerability) {
        continue
      }
      for subject_index, subject in statement.subjects {
        if subject_applies(graph, subject, finding, path) {
          claims.push({ statement_index, subject_index, })
        }
      }
    }
    let path_statement_ids : Array[String] = []
    let superseded_statement_ids : Array[String] = []
    let path_statuses : Array[Status] = []
    for claim in claims {
      let statement = statements[claim.statement_index]
      let mut superseded = false
      for candidate in claims {
        if superseded_by(claim, candidate, statements) {
          superseded = true
          break
        }
      }
      if superseded {
        if !superseded_statement_ids.contains(statement.id) {
          superseded_statement_ids.push(statement.id)
        }
      } else {
        if !statuses.contains(statement.status) {
          statuses.push(statement.status)
        }
        if !path_statuses.contains(statement.status) {
          path_statuses.push(statement.status)
        }
        if !statement_ids.contains(statement.id) {
          statement_ids.push(statement.id)
        }
        if !path_statement_ids.contains(statement.id) {
          path_statement_ids.push(statement.id)
        }
      }
    }
    if path_statement_ids.is_empty() {
      uncovered = true
    }
    let purls : Array[String] = []
    for node in path {
      match graph.purls.get(node) {
        Some(purl) => purls.push(purl)
        None => uncertain.val = true
      }
    }
    path_evidence.push({
      bom_refs: path,
      purls,
      statement_ids: path_statement_ids,
      superseded_statement_ids,
      statuses: path_statuses,
    })
  }
  let (outcome, detail) = if statuses.length() > 1 {
    (Conflict, "applicable statements disagree on status")
  } else if statuses.is_empty() {
    (NoClaim, "no OpenVEX statement applies")
  } else if uncovered {
    (Incomplete, "at least one dependency path has no applicable statement")
  } else if uncertain.val || missing_target_path {
    (Incomplete, "the dependency graph cannot establish complete coverage")
  } else {
    (outcome_of_status(statuses[0]), "all dependency paths have the same claim")
  }
  {
    finding_id: finding.id,
    outcome,
    statement_ids,
    paths: path_evidence,
    detail,
  }
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
