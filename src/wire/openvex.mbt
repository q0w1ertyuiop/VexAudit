///|
fn optional_string(
  fields : Map[String, Json],
  key : String,
  path : String,
) -> Result[String?, String] {
  match fields.get(key) {
    None => Ok(None)
    Some(value) =>
      match string(value, "\{path}.\{key}") {
        Ok(text) => Ok(Some(text))
        Err(message) => Err(message)
      }
  }
}

///|
fn optional_strings(
  fields : Map[String, Json],
  key : String,
  path : String,
) -> Result[Array[String], String] {
  let values = match fields.get(key) {
    None => return Ok([])
    Some(value) =>
      match array(value, "\{path}.\{key}") {
        Ok(items) => items
        Err(message) => return Err(message)
      }
  }
  let result : Array[String] = []
  for index, value in values {
    match string(value, "\{path}.\{key}[\{index}]") {
      Ok(text) => result.push(text)
      Err(message) => return Err(message)
    }
  }
  Ok(result)
}

///|
fn purl_identifier(
  fields : Map[String, Json],
  path : String,
) -> Result[String, String] {
  let identifier = match optional_string(fields, "@id", path) {
    Ok(value) => value
    Err(message) => return Err(message)
  }
  let named_purl = match fields.get("identifiers") {
    None => None
    Some(value) => {
      let identifiers = match object(value, "\{path}.identifiers") {
        Ok(value) => value
        Err(message) => return Err(message)
      }
      match optional_string(identifiers, "purl", "\{path}.identifiers") {
        Ok(value) => value
        Err(message) => return Err(message)
      }
    }
  }
  match named_purl {
    Some(purl) if purl.has_prefix("pkg:") => {
      if identifier is Some(iri) && iri.has_prefix("pkg:") && iri != purl {
        return Err("\{path} has conflicting Package URL identifiers")
      }
      Ok(purl)
    }
    Some(_) => Err("\{path}.identifiers.purl must be a Package URL")
    None =>
      match identifier {
        Some(purl) if purl.has_prefix("pkg:") => Ok(purl)
        _ => Err("\{path} needs a Package URL identifier")
      }
  }
}

///|
fn parse_subject(value : Json, path : String) -> Result[@audit.Subject, String] {
  let fields = match object(value, path) {
    Ok(value) => value
    Err(message) => return Err(message)
  }
  let product_purl = match purl_identifier(fields, path) {
    Ok(value) => value
    Err(message) => return Err(message)
  }
  let subcomponent_purls : Array[String] = []
  match fields.get("subcomponents") {
    None => ()
    Some(value) => {
      let items = match array(value, "\{path}.subcomponents") {
        Ok(value) => value
        Err(message) => return Err(message)
      }
      for index, item in items {
        let subpath = "\{path}.subcomponents[\{index}]"
        let entry = match object(item, subpath) {
          Ok(value) => value
          Err(message) => return Err(message)
        }
        let purl = match purl_identifier(entry, subpath) {
          Ok(value) => value
          Err(message) => return Err(message)
        }
        subcomponent_purls.push(purl)
      }
    }
  }
  Ok({ product_purl, subcomponent_purls, })
}

///|
fn parse_status(value : String) -> Result[@audit.Status, String] {
  match value {
    "not_affected" => Ok(@audit.NotAffected)
    "affected" => Ok(@audit.Affected)
    "fixed" => Ok(@audit.Fixed)
    "under_investigation" => Ok(@audit.UnderInvestigation)
    _ => Err("unknown OpenVEX status: \{value}")
  }
}

///|
fn valid_justification(value : String) -> Bool {
  match value {
    "component_not_present"
    | "vulnerable_code_not_present"
    | "vulnerable_code_not_in_execute_path"
    | "vulnerable_code_cannot_be_controlled_by_adversary"
    | "inline_mitigations_already_exist" => true
    _ => false
  }
}

///|
fn parse_statement(
  value : Json,
  index : Int,
  document_id : String,
  author : String,
  document_timestamp : String,
) -> Result[@audit.Statement, String] {
  let path = "OpenVEX.statements[\{index}]"
  let fields = match object(value, path) {
    Ok(value) => value
    Err(message) => return Err(message)
  }
  let id = match optional_string(fields, "@id", path) {
    Ok(Some(value)) => value
    Ok(None) => "\{document_id}#statement-\{index}"
    Err(message) => return Err(message)
  }
  let timestamp = match optional_string(fields, "timestamp", path) {
    Ok(Some(value)) => value
    Ok(None) => document_timestamp
    Err(message) => return Err(message)
  }
  let vulnerability_data = match object_field(fields, "vulnerability", path) {
    Ok(value) => value
    Err(message) => return Err(message)
  }
  let vulnerability = match
    string_field(vulnerability_data, "name", "\{path}.vulnerability") {
    Ok(value) => value
    Err(message) => return Err(message)
  }
  let aliases = match
    optional_strings(vulnerability_data, "aliases", "\{path}.vulnerability") {
    Ok(value) => value
    Err(message) => return Err(message)
  }
  let status = match string_field(fields, "status", path) {
    Ok(value) =>
      match parse_status(value) {
        Ok(status) => status
        Err(message) => return Err(message)
      }
    Err(message) => return Err(message)
  }
  match status {
    @audit.NotAffected => {
      let justification = match optional_string(fields, "justification", path) {
        Ok(value) => value
        Err(message) => return Err(message)
      }
      let impact = match optional_string(fields, "impact_statement", path) {
        Ok(value) => value
        Err(message) => return Err(message)
      }
      if justification is None && impact is None {
        return Err("\{path} needs justification or impact_statement")
      }
      if justification is Some(value) && !valid_justification(value) {
        return Err("\{path}.justification is not an OpenVEX label")
      }
    }
    @audit.Affected =>
      match string_field(fields, "action_statement", path) {
        Ok(_) => ()
        Err(message) => return Err(message)
      }
    _ => ()
  }
  let product_data = match array_field(fields, "products", path) {
    Ok(value) => value
    Err(message) => return Err(message)
  }
  if product_data.is_empty() {
    return Err("\{path}.products must not be empty in a standalone document")
  }
  let subjects : Array[@audit.Subject] = []
  for product_index, item in product_data {
    let subject = match
      parse_subject(item, "\{path}.products[\{product_index}]") {
      Ok(value) => value
      Err(message) => return Err(message)
    }
    subjects.push(subject)
  }
  Ok({
    id,
    document_id,
    author,
    timestamp,
    vulnerability,
    aliases,
    status,
    subjects,
  })
}

///| Accept standalone OpenVEX v0.2.0 documents with PURL subjects. This is

///|
/// a deliberately narrower profile than the full JSON-LD specification.
pub fn read_openvex(
  source : StringView,
) -> Result[Array[@audit.Statement], String] {
  let document = match parse_json(source) {
    Ok(value) => value
    Err(message) => return Err(message)
  }
  let root = match object(document, "OpenVEX") {
    Ok(value) => value
    Err(message) => return Err(message)
  }
  if string_field(root, "@context", "OpenVEX") !=
    Ok("https://openvex.dev/ns/v0.2.0") {
    return Err("OpenVEX context must be v0.2.0")
  }
  let document_id = match string_field(root, "@id", "OpenVEX") {
    Ok(value) => value
    Err(message) => return Err(message)
  }
  let author = match string_field(root, "author", "OpenVEX") {
    Ok(value) => value
    Err(message) => return Err(message)
  }
  let timestamp = match string_field(root, "timestamp", "OpenVEX") {
    Ok(value) => value
    Err(message) => return Err(message)
  }
  match field(root, "version", "OpenVEX") {
    Ok(Number(value, ..)) if value >= 1.0 && value.trunc() == value => ()
    _ => return Err("OpenVEX.version must be a positive integer")
  }
  let items = match array_field(root, "statements", "OpenVEX") {
    Ok(value) => value
    Err(message) => return Err(message)
  }
  let statements : Array[@audit.Statement] = []
  for index, item in items {
    let statement = match
      parse_statement(item, index, document_id, author, timestamp) {
      Ok(value) => value
      Err(message) => return Err(message)
    }
    for previous in statements {
      if previous.id == statement.id {
        return Err("duplicate OpenVEX statement ID: \{statement.id}")
      }
    }
    statements.push(statement)
  }
  Ok(statements)
}
