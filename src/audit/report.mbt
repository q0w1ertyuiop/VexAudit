///| Serialize the machine-readable decision record. Array order follows the

///|
/// input findings and source statements; it is stable for equal inputs.
pub fn report_json(report : Report) -> String {
  @json.to_json(report).stringify(indent=2)
}

///|
/// A report is clear only when every finding has a complete `not_affected`
/// or `fixed` claim. An empty report is clear.
pub fn all_findings_cleared(report : Report) -> Bool {
  for decision in report.decisions {
    match decision.outcome {
      NotAffected | Fixed => ()
      _ => return false
    }
  }
  true
}
