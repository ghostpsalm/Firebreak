fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let manifest = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity version="0.1.0.0" name="firebreak" type="win32"/>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="requireAdministrator" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application>
      <!-- Windows 10 / 11 -->
      <supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/>
    </application>
  </compatibility>
</assembly>
"#;
        let mut res = winresource::WindowsResource::new();
        res.set_manifest(manifest);
        res.set("ProductName", "firebreak");
        res.set("FileDescription", "Windows Firewall rule-usage auditor");
        res.set_icon("assets/icons/firebreak.ico"); // taskbar / Explorer icon
        if let Err(e) = res.compile() {
            println!("cargo:warning=resource embedding failed: {e}");
        }
    }
}
