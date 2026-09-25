///|
fn object(value : Json, path : String) -> Result[Map[String, Json], String] {
  match value {
    Object(fields) => Ok(fields)
    _ => Err("\{path} must be an object")
  }
}

///|
fn array(value : Json, path : String) -> Result[Array[Json], String] {
  match value {
    Array(items) => Ok(items)
    _ => Err("\{path} must be an array")
  }
}

///|
fn field(
  fields : Map[String, Json],
  key : String,
  path : String,
) -> Result[Json, String] {
  match fields.get(key) {
    Some(value) => Ok(value)
    None => Err("\{path}.\{key} is required")
  }
}

///|
fn string(value : Json, path : String) -> Result[String, String] {
  match value {
    String(text) if !text.is_empty() => Ok(text)
    _ => Err("\{path} must be a nonempty string")
  }
}

///|
fn string_field(
  fields : Map[String, Json],
  key : String,
  path : String,
) -> Result[String, String] {
  match field(fields, key, path) {
    Ok(value) => string(value, "\{path}.\{key}")
    Err(message) => Err(message)
  }
}

///|
fn object_field(
  fields : Map[String, Json],
  key : String,
  path : String,
) -> Result[Map[String, Json], String] {
  match field(fields, key, path) {
    Ok(value) => object(value, "\{path}.\{key}")
    Err(message) => Err(message)
  }
}

///|
fn array_field(
  fields : Map[String, Json],
  key : String,
  path : String,
) -> Result[Array[Json], String] {
  match field(fields, key, path) {
    Ok(value) => array(value, "\{path}.\{key}")
    Err(message) => Err(message)
  }
}

///|
fn parse_json(source : StringView) -> Result[Json, String] {
  let parsed : Json? = Some(@json.parse(source)) catch { _ => None }
  match parsed {
    Some(value) => Ok(value)
    None => Err("invalid JSON")
  }
}

///|
fn parse_component(
  value : Json,
  path : String,
) -> Result[@audit.Component, String] {
  let fields = match object(value, path) {
    Ok(fields) => fields
    Err(message) => return Err(message)
  }
  let bom_ref = match string_field(fields, "bom-ref", path) {
    Ok(value) => value
    Err(message) => return Err(message)
  }
  let purl = match string_field(fields, "purl", path) {
    Ok(value) => value
    Err(message) => return Err(message)
  }
  if !purl.has_prefix("pkg:") {
    return Err("\{path}.purl must be a Package URL")
  }
  Ok({ bom_ref, purl, })
}

///| Read a CycloneDX 1.6 JSON inventory, including dependency edges. Every

///|
/// referenced component must have a PURL; unsupported identifiers fail closed.
pub fn read_cyclonedx(source : StringView) -> Result[@audit.Inventory, String] {
  let document = match parse_json(source) {
    Ok(value) => value
    Err(message) => return Err(message)
  }
  let root = match object(document, "SBOM") {
    Ok(value) => value
    Err(message) => return Err(message)
  }
  if string_field(root, "bomFormat", "SBOM") != Ok("CycloneDX") ||
    string_field(root, "specVersion", "SBOM") != Ok("1.6") {
    return Err("SBOM must be CycloneDX JSON version 1.6")
  }
  let metadata = match object_field(root, "metadata", "SBOM") {
    Ok(value) => value
    Err(message) => return Err(message)
  }
  let root_json = match field(metadata, "component", "SBOM.metadata") {
    Ok(value) => value
    Err(message) => return Err(message)
  }
  let root_component = match
    parse_component(root_json, "SBOM.metadata.component") {
    Ok(value) => value
    Err(message) => return Err(message)
  }
  let root_ref = root_component.bom_ref
  let components : Array[@audit.Component] = [root_component]
  let items = match array_field(root, "components", "SBOM") {
    Ok(value) => value
    Err(message) => return Err(message)
  }
  for index, item in items {
    let component = match parse_component(item, "SBOM.components[\{index}]") {
      Ok(value) => value
      Err(message) => return Err(message)
    }
    for previous in components {
      if previous.bom_ref == component.bom_ref {
        return Err("duplicate BOM reference: \{component.bom_ref}")
      }
    }
    components.push(component)
  }
  let edges : Array[@audit.Edge] = []
  let dependencies = match root.get("dependencies") {
    None => []
    Some(value) =>
      match array(value, "SBOM.dependencies") {
        Ok(items) => items
        Err(message) => return Err(message)
      }
  }
  for index, item in dependencies {
    let path = "SBOM.dependencies[\{index}]"
    let row = match object(item, path) {
      Ok(value) => value
      Err(message) => return Err(message)
    }
    let parent = match string_field(row, "ref", path) {
      Ok(value) => value
      Err(message) => return Err(message)
    }
    if !has_ref(components, parent) {
      return Err("dependency refers to unknown component: \{parent}")
    }
    let children = match array_field(row, "dependsOn", path) {
      Ok(value) => value
      Err(message) => return Err(message)
    }
    for child_index, child_json in children {
      let child = match
        string(child_json, "\{path}.dependsOn[\{child_index}]") {
        Ok(value) => value
        Err(message) => return Err(message)
      }
      if !has_ref(components, child) {
        return Err("dependency refers to unknown component: \{child}")
      }
      edges.push({ parent, child, })
    }
  }
  Ok({ root_ref, components, edges, })
}

///|
fn has_ref(components : Array[@audit.Component], bom_ref : String) -> Bool {
  for component in components {
    if component.bom_ref == bom_ref {
      return true
    }
  }
  false
}

///|
/// The finding format is intentionally small and scanner-independent.
pub fn read_findings(
  source : StringView,
) -> Result[Array[@audit.Finding], String] {
  let document = match parse_json(source) {
    Ok(value) => value
    Err(message) => return Err(message)
  }
  let root = match object(document, "findings document") {
    Ok(value) => value
    Err(message) => return Err(message)
  }
  let rows = match array_field(root, "findings", "findings document") {
    Ok(value) => value
    Err(message) => return Err(message)
  }
  let findings : Array[@audit.Finding] = []
  for index, row in rows {
    let path = "findings[\{index}]"
    let fields = match object(row, path) {
      Ok(value) => value
      Err(message) => return Err(message)
    }
    let id = match string_field(fields, "id", path) {
      Ok(value) => value
      Err(message) => return Err(message)
    }
    for previous in findings {
      if previous.id == id {
        return Err("duplicate finding ID: \{id}")
      }
    }
    let vulnerability = match string_field(fields, "vulnerability", path) {
      Ok(value) => value
      Err(message) => return Err(message)
    }
    let component_purl = match string_field(fields, "component_purl", path) {
      Ok(value) => value
      Err(message) => return Err(message)
    }
    if !component_purl.has_prefix("pkg:") {
      return Err("\{path}.component_purl must be a Package URL")
    }
    findings.push({ id, vulnerability, component_purl, })
  }
  Ok(findings)
}
