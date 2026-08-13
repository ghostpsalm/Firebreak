// Firebreak's telemetry collector on an Oracle Always Free host.
//
// One small VM running nginx (TLS via certbot, and the place to add more
// services later) in front of firebreak-receiver on loopback, with SQLite on
// the boot volume.
//
// The shape of it is chosen for a service that must not need operating:
// no load balancer, no managed database, no container registry, nothing with
// a bill attached. Every resource here is inside the Always Free allowance.

data "oci_identity_availability_domains" "ads" {
  compartment_id = var.tenancy_ocid
}

locals {
  ad = data.oci_identity_availability_domains.ads.availability_domains[
    var.availability_domain_index
  ].name

  // Flexible shapes need an explicit CPU/memory allocation; fixed ones
  // reject the block outright, so it is emitted conditionally below.
  is_flex = can(regex("Flex", var.instance_shape))
}

// Canonical's Ubuntu 22.04, newest build, matching the shape's architecture.
// Pinned by name pattern rather than a hard OCID so this stays deployable in
// any region, where image OCIDs differ.
data "oci_core_images" "ubuntu" {
  compartment_id           = var.compartment_ocid
  operating_system         = "Canonical Ubuntu"
  operating_system_version = "22.04"
  shape                    = var.instance_shape
  sort_by                  = "TIMECREATED"
  sort_order               = "DESC"
}

// ---- network ----

resource "oci_core_vcn" "this" {
  compartment_id = var.compartment_ocid
  display_name   = var.name
  cidr_blocks    = ["10.0.0.0/16"]
  dns_label      = "collector"
}

resource "oci_core_internet_gateway" "this" {
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.this.id
  display_name   = "${var.name}-igw"
  enabled        = true
}

resource "oci_core_route_table" "this" {
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.this.id
  display_name   = "${var.name}-rt"

  route_rules {
    destination       = "0.0.0.0/0"
    network_entity_id = oci_core_internet_gateway.this.id
  }
}

// Three ports in, everything out. The receiver itself is not reachable from
// off-box at all — it binds loopback, so the only way to it is through nginx.
resource "oci_core_security_list" "this" {
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.this.id
  display_name   = "${var.name}-sl"

  egress_security_rules {
    destination = "0.0.0.0/0"
    protocol    = "all"
  }

  ingress_security_rules {
    protocol    = "6" // TCP
    source      = var.ssh_allowed_cidr
    description = "SSH"
    tcp_options {
      min = 22
      max = 22
    }
  }

  // Needed even though nothing is served on it: Let's Encrypt's HTTP-01
  // challenge and the redirect to HTTPS both use it.
  ingress_security_rules {
    protocol    = "6"
    source      = "0.0.0.0/0"
    description = "HTTP (ACME challenge and redirect)"
    tcp_options {
      min = 80
      max = 80
    }
  }

  ingress_security_rules {
    protocol    = "6"
    source      = "0.0.0.0/0"
    description = "HTTPS"
    tcp_options {
      min = 443
      max = 443
    }
  }
}

resource "oci_core_subnet" "this" {
  compartment_id    = var.compartment_ocid
  vcn_id            = oci_core_vcn.this.id
  cidr_block        = "10.0.1.0/24"
  display_name      = "${var.name}-subnet"
  route_table_id    = oci_core_route_table.this.id
  security_list_ids = [oci_core_security_list.this.id]
  dns_label         = "collector"
}

// ---- host ----

resource "oci_core_instance" "this" {
  compartment_id      = var.compartment_ocid
  availability_domain = local.ad
  display_name        = var.name
  shape               = var.instance_shape

  dynamic "shape_config" {
    for_each = local.is_flex ? [1] : []
    content {
      ocpus         = var.shape_ocpus
      memory_in_gbs = var.shape_memory_gb
    }
  }

  source_details {
    source_type             = "image"
    source_id               = data.oci_core_images.ubuntu.images[0].id
    boot_volume_size_in_gbs = var.boot_volume_gb
  }

  create_vnic_details {
    subnet_id        = oci_core_subnet.this.id
    assign_public_ip = true
    hostname_label   = "collector"
  }

  metadata = {
    ssh_authorized_keys = var.ssh_public_key
    user_data = base64encode(templatefile("${path.module}/cloud-init.yaml.tftpl", {
      domain_name       = var.domain_name
      acme_email        = var.acme_email
      retention_days    = var.retention_days
      rate_per_hour     = var.rate_per_hour
      deno_version      = var.deno_version
      deploy_public_key = trimspace(var.deploy_public_key)
    }))
  }

  // The image is looked up by "newest matching" and moves when Canonical
  // publishes a build. Without this, an unrelated `apply` months later would
  // propose destroying a working collector to rebuild it on a newer image.
  lifecycle {
    ignore_changes = [source_details[0].source_id]
  }
}

// ---- the receiver itself ----
//
// Three TypeScript files copied into place. There is no build, no compiler
// and no artifact registry: Deno runs the source, so deploying a change is
// a file copy and a restart.

locals {
  // Only the modules the service actually runs. The *_test.ts files stay on
  // this machine — the box has no business holding a test suite, and they
  // are the only things here with a third-party import.
  receiver_files = ["main.ts", "ping.ts", "db.ts"]
}

resource "null_resource" "receiver" {
  triggers = {
    instance = oci_core_instance.this.id
    // Any change to the service's own source redeploys it, without touching
    // the host underneath.
    source = sha256(join("", [
      for f in local.receiver_files :
      filesha256("${path.module}/../receiver/${f}")
    ]))
  }

  connection {
    type        = "ssh"
    host        = oci_core_instance.this.public_ip
    user        = "ubuntu"
    private_key = file(var.ssh_private_key_path)
    timeout     = "10m"
  }

  // cloud-init is still installing Deno and nginx when SSH first answers.
  provisioner "remote-exec" {
    inline = [
      "cloud-init status --wait || true",
      "mkdir -p /home/ubuntu/receiver",
    ]
  }

  // Named files rather than the directory, so nothing local — a stray
  // build directory, an editor's scratch file — is ever swept up the wire.
  // Listed one by one because `dynamic` does not apply to provisioners;
  // local.receiver_files is still the single source of truth for the
  // redeploy trigger above and the install step below.
  provisioner "file" {
    source      = "${path.module}/../receiver/main.ts"
    destination = "/home/ubuntu/receiver/main.ts"
  }

  provisioner "file" {
    source      = "${path.module}/../receiver/ping.ts"
    destination = "/home/ubuntu/receiver/ping.ts"
  }

  provisioner "file" {
    source      = "${path.module}/../receiver/db.ts"
    destination = "/home/ubuntu/receiver/db.ts"
  }

  provisioner "remote-exec" {
    inline = [
      "set -euo pipefail",
      // Ownership matches what cloud-init set up, so a later CI deploy —
      // which runs as `deploy` and does not use sudo for the copy — can
      // still write here.
      "sudo install -d -m 0755 -o deploy -g deploy /opt/firebreak-receiver",
      "sudo install -m 0644 -o deploy -g deploy /home/ubuntu/receiver/*.ts /opt/firebreak-receiver/",
      "sudo systemctl restart firebreak-receiver",
      "sudo systemctl is-active --quiet firebreak-receiver",
      // Prove it end to end rather than trusting that the unit started: a
      // service that is 'active' but not answering is the failure this
      // whole stack exists to avoid discovering months later.
      "for i in $(seq 1 15); do curl -fsS http://127.0.0.1:8787/healthz && break || sleep 2; done",
      // And prove the proxy in front of it is wired up too.
      "curl -fsS http://127.0.0.1/healthz",
    ]
  }
}
