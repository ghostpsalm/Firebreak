output "public_ip" {
  description = "Point your A record here; certbot picks it up within ten minutes."
  value       = oci_core_instance.this.public_ip
}

output "endpoint" {
  description = "Set this as ENDPOINT in src/telemetry.rs, then cut a build."
  value       = "https://${var.domain_name}/v1/ping"
}

output "ssh" {
  description = "How to get onto the box."
  value       = "ssh ubuntu@${oci_core_instance.this.public_ip}"
}

// Deliberately a script you read before running: it copies a private key
// into a third party, and the host key it pins is the thing that stops a
// deploy going to someone else's machine.
output "ci_setup" {
  description = "Commands to point GitHub Actions at this host. Run after DNS and TLS are up."
  value = var.deploy_public_key == "" ? (
    "deploy_public_key is empty, so no CI account exists on this host.\nGenerate a key, set the variable and re-apply to enable deployment:\n  ssh-keygen -t ed25519 -f ci_deploy_key -N \"\" -C \"firebreak CI deploy\"\n"
  ) : <<-EOT

    Set these three repository secrets, then every push to main that passes
    the gate deploys the collector.

      gh secret set OCI_HOST     --body '${oci_core_instance.this.public_ip}'
      gh secret set OCI_DEPLOY_KEY < ci_deploy_key

      # Pin the host key, so a deploy cannot be steered to another machine.
      # Read it once, from a network you trust:
      ssh-keyscan -t ed25519 ${oci_core_instance.this.public_ip} > known_hosts
      gh secret set OCI_HOST_KEY < known_hosts

    Then check the key really is limited to the one command — it should
    print the deploy script's output and refuse to give you a shell:

      ssh -i ci_deploy_key deploy@${oci_core_instance.this.public_ip} whoami
  EOT
}

output "next_steps" {
  description = "What to do once apply finishes."
  value       = <<-EOT

    1. DNS      A record: ${var.domain_name} -> ${oci_core_instance.this.public_ip}
                A timer retries every 10 minutes, so this can be done after apply.

    2. Verify   curl https://${var.domain_name}/healthz          (expect: ok)
                ssh ubuntu@${oci_core_instance.this.public_ip} \
                  'sudo journalctl -u firebreak-receiver -f'

    3. Client   set ENDPOINT in src/telemetry.rs to
                  https://${var.domain_name}/v1/ping
                and cut a release. Until then no build sends anything, and
                no consent prompt is shown.

    4. Look     ssh ubuntu@${oci_core_instance.this.public_ip} \
                  'sudo firebreak-telemetry-summary'

    5. Back up  scp ubuntu@${oci_core_instance.this.public_ip}:/var/lib/firebreak-receiver/telemetry.db .
                (needs sudo on the box; see server/README.md)
  EOT
}
