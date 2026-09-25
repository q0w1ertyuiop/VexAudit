///| A component's BOM reference and Package URL are kept separate because

///|
/// CycloneDX dependency edges use references, not PURLs.
pub(all) struct Component {
  bom_ref : String
  purl : String
} derive(Debug)

///|
pub extend Component with @debug.Debug::{to_repr}

///|
pub(all) struct Edge {
  parent : String
  child : String
} derive(Debug)

///|
pub extend Edge with @debug.Debug::{to_repr}

///|
pub(all) struct Inventory {
  root_ref : String
  components : Array[Component]
  edges : Array[Edge]
} derive(Debug)

///|
pub extend Inventory with @debug.Debug::{to_repr}

///| Findings identify the vulnerable component within an inventory. The

///|
/// product being audited is the inventory root.
pub(all) struct Finding {
  id : String
  vulnerability : String
  component_purl : String
} derive(Debug)

///|
pub extend Finding with @debug.Debug::{to_repr}

///|
pub(all) enum Status {
  NotAffected
  Affected
  Fixed
  UnderInvestigation
} derive(Eq, Debug, ToJson)

///|
pub extend Status with Eq::{equal, not_equal}

///|
pub extend Status with @debug.Debug::{to_repr}

///|
pub extend Status with ToJson::{to_json}

///|
pub(all) struct Subject {
  product_purl : String
  subcomponent_purls : Array[String]
} derive(Debug)

///|
pub extend Subject with @debug.Debug::{to_repr}

///|
pub(all) struct Statement {
  id : String
  document_id : String
  author : String
  timestamp : String
  vulnerability : String
  aliases : Array[String]
  status : Status
  subjects : Array[Subject]
} derive(Debug)

///|
pub extend Statement with @debug.Debug::{to_repr}

///| NoClaim means no applicable statement exists. Incomplete means a claim

///|
/// covers some, but not every, dependency path or the graph is uncertain.
pub(all) enum Outcome {
  NoClaim
  Incomplete
  Conflict
  NotAffected
  Affected
  Fixed
  UnderInvestigation
  ComponentMissing
  Unreachable
} derive(Eq, Debug, ToJson)

///|
pub extend Outcome with Eq::{equal, not_equal}

///|
pub extend Outcome with @debug.Debug::{to_repr}

///|
pub extend Outcome with ToJson::{to_json}

///|
pub(all) struct PathEvidence {
  bom_refs : Array[String]
  purls : Array[String]
  statement_ids : Array[String]
  statuses : Array[Status]
} derive(Debug, ToJson)

///|
pub extend PathEvidence with @debug.Debug::{to_repr}

///|
pub extend PathEvidence with ToJson::{to_json}

///|
pub(all) struct Decision {
  finding_id : String
  outcome : Outcome
  statement_ids : Array[String]
  paths : Array[PathEvidence]
  detail : String
} derive(Debug, ToJson)

///|
pub extend Decision with @debug.Debug::{to_repr}

///|
pub extend Decision with ToJson::{to_json}

///|
pub(all) struct Report {
  decisions : Array[Decision]
} derive(Debug, ToJson)

///|
pub extend Report with @debug.Debug::{to_repr}

///|
pub extend Report with ToJson::{to_json}
