///| Serialize the machine-readable decision record. Array order follows the

///|
/// input findings and source statements; it is stable for equal inputs.
pub fn report_json(report : Report) -> String {
  @json.to_json(report).stringify(indent=2)
}
