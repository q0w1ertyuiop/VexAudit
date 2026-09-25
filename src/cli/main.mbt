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
  let mut trivy_mode = false
  let mut require_clear = false
  let mut input_start = 2
  while input_start < args.length() && args[input_start].has_prefix("--") {
    match args[input_start] {
      "--trivy" if !trivy_mode => trivy_mode = true
      "--require-clear" if !require_clear => require_clear = true
      _ => {
        write_error(
          "vexaudit: unknown or duplicate option: \{args[input_start]}\n",
        )
        set_exit_code(2)
        return
      }
    }
    input_start = input_start + 1
  }
  if args.length() != input_start + 3 {
    write_error(
      "usage: vexaudit [--trivy] [--require-clear] <sbom.cdx.json> <findings.json|trivy.json> <openvex.json>\n",
    )
    set_exit_code(2)
    return
  }
  let sbom = read_text(args[input_start])
  let findings = read_text(args[input_start + 1])
  let vex = read_text(args[input_start + 2])
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
  let mut has_unresolved = false
  match imported {
    Some(value) => {
      has_unresolved = !value.unresolved.is_empty()
      write_output(@wire.trivy_report_json(report, value))
    }
    None => write_output(@audit.report_json(report))
  }
  write_output("\n")
  if require_clear && (!@audit.all_findings_cleared(report) || has_unresolved) {
    set_exit_code(1)
  }
}
