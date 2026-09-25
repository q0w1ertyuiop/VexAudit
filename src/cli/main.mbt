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
  if args.length() != 5 {
    write_error(
      "usage: vexaudit <sbom.cdx.json> <findings.json> <openvex.json>\n",
    )
    set_exit_code(2)
    return
  }
  let sbom = read_text(args[2])
  let findings = read_text(args[3])
  let vex = read_text(args[4])
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
  let finding_rows = match @wire.read_findings(findings) {
    Ok(value) => value
    Err(message) => {
      write_error("vexaudit: \{message}\n")
      set_exit_code(2)
      return
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
  write_output(
    @audit.report_json(@audit.reconcile(inventory, statements, finding_rows)),
  )
  write_output("\n")
}
