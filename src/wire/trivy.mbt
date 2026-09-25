///|
/// A Trivy row that cannot be joined to a CycloneDX component is retained in
/// the output so a scan is never mistaken for a fully reconciled report.
pub(all) struct TrivyUnresolved {
  row : String
  target : String
  vulnerability : String
  reason : String
} derive(Debug, ToJson)

///|
pub extend TrivyUnresolved with @debug.Debug::{to_repr}

///|
pub extend TrivyUnresolved with ToJson::{to_json}

///|
pub(all) struct TrivyImport {
  findings : Array[@audit.Finding]
  unresolved : Array[TrivyUnresolved]
} derive(Debug)

///|
pub extend TrivyImport with @debug.Debug::{to_repr}

///|
struct TrivyReport {
  decisions : Array[@audit.Decision]
  unresolved : Array[TrivyUnresolved]
} derive(ToJson)

///|
pub extend TrivyReport with ToJson::{to_json}

///|
pub fn trivy_report_json(
  report : @audit.Report,
  imported : TrivyImport,
) -> String {
  let output : TrivyReport = {
    decisions: report.decisions,
    unresolved: imported.unresolved,
  }
  output.to_json().stringify(indent=2)
}

///|
/// Read Trivy's JSON report without inventing package identities. Findings
/// with no usable Package URL are returned in `unresolved`.
pub fn read_trivy_json(source : StringView) -> Result[TrivyImport, String] {
  let document = match parse_json(source) {
    Ok(value) => value
    Err(message) => return Err(message)
  }
  let root = match object(document, "Trivy report") {
    Ok(value) => value
    Err(message) => return Err(message)
  }
  let results = match root.get("Results") {
    Some(value) =>
      match array(value, "Trivy report.Results") {
        Ok(value) => value
        Err(message) => return Err(message)
      }
    None => {
      match root.get("SchemaVersion") {
        Some(Number(2, ..)) => ()
        _ => return Err("Trivy report requires Results or SchemaVersion 2")
      }
      []
    }
  }
  let findings : Array[@audit.Finding] = []
  let unresolved : Array[TrivyUnresolved] = []
  for result_index, result in results {
    let result_path = "Results[\{result_index}]"
    let result_fields = match object(result, result_path) {
      Ok(value) => value
      Err(message) => return Err(message)
    }
    let target = match result_fields.get("Target") {
      Some(String(value)) => value
      _ => ""
    }
    let vulnerabilities = match result_fields.get("Vulnerabilities") {
      None | Some(Null) => []
      Some(value) =>
        match array(value, "\{result_path}.Vulnerabilities") {
          Ok(value) => value
          Err(message) => return Err(message)
        }
    }
    for vulnerability_index, vulnerability_json in vulnerabilities {
      let row = "\{result_path}.Vulnerabilities[\{vulnerability_index}]"
      let fields = match object(vulnerability_json, row) {
        Ok(value) => value
        Err(message) => return Err(message)
      }
      let vulnerability = match fields.get("VulnerabilityID") {
        Some(String(value)) => value
        _ => ""
      }
      if vulnerability.is_empty() {
        unresolved.push({
          row,
          target,
          vulnerability,
          reason: "VulnerabilityID is missing",
        })
        continue
      }
      let purl = match fields.get("PkgIdentifier") {
        Some(Object(identifier)) =>
          match identifier.get("PURL") {
            Some(String(value)) => value
            _ => ""
          }
        _ => ""
      }
      if !purl.has_prefix("pkg:") {
        unresolved.push({
          row,
          target,
          vulnerability,
          reason: "PkgIdentifier.PURL is missing or invalid",
        })
        continue
      }
      findings.push({ id: row, vulnerability, component_purl: purl, })
    }
  }
  Ok({ findings, unresolved, })
}
