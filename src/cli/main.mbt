///|
extern "js" fn read_text(path : String) -> String =
  #| function(path) {
  #|   try { return require("node:fs").readFileSync(path, "utf8"); }
  #|   catch (_) { return ""; }
  #| }

///|
extern "js" fn write_output(text : String) -> Unit =
  #| function(text) { process.stdout.write(text); }

///|
extern "js" fn write_error(text : String) -> Unit =
  #| function(text) { process.stderr.write(text); }

///|
extern "js" fn set_exit_code(code : Int) -> Unit =
  #| function(code) { process.exitCode = code; }

///|
fn main {
  let args = @env.args()
  let trivy_mode = args.length() == 6 && args[2] == "--trivy"
  if args.length() != 5 && !trivy_mode {
    write_error(
      "usage: vexaudit [--trivy] <sbom.cdx.json> <findings.json|trivy.json> <openvex.json>\n",
    )
    set_exit_code(2)
    return
  }
  let offset = if trivy_mode { 1 } else { 0 }
  let sbom = read_text(args[2 + offset])
  let findings = read_text(args[3 + offset])
  let vex = read_text(args[4 + offset])
  if sbom.is_empty() || findings.is_empty() || vex.is_empty() {
    write_error("vexaudit: unable to read an input file or input is empty\n")
    set_exit_code(2)
    return
  }
  let inventory = match @wire.read_cyclonedx(sbom) {
    Ok(value) => value
    Err(message) => {
      write_error("vexaudit: \{message}\n")
      set_exit_code(2)
      return
    }
  }
  let mut imported : @wire.TrivyImport? = None
  let finding_rows = if trivy_mode {
    match @wire.read_trivy_json(findings) {
      Ok(value) => {
        imported = Some(value)
        value.findings
      }
      Err(message) => {
        write_error("vexaudit: \{message}\n")
        set_exit_code(2)
        return
      }
    }
  } else {
    match @wire.read_findings(findings) {
      Ok(value) => value
      Err(message) => {
        write_error("vexaudit: \{message}\n")
        set_exit_code(2)
        return
      }
    }
  }
  let statements = match @wire.read_openvex(vex) {
    Ok(value) => value
    Err(message) => {
      write_error("vexaudit: \{message}\n")
      set_exit_code(2)
      return
    }
  }
  let report = @audit.reconcile(inventory, statements, finding_rows)
  match imported {
    Some(value) => write_output(@wire.trivy_report_json(report, value))
    None => write_output(@audit.report_json(report))
  }
  write_output("\n")
}
