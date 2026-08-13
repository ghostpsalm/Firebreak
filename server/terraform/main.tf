// Firebreak's telemetry collector on an Oracle Always Free host.
//
// One small VM running Caddy (TLS, and the place to add more services later)
// in front of firebreak-receiver on loopback, with SQLite on the boot volume.
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
// off-box at all — it binds loopback, so the only way to it is through Caddy.
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
  // challenge and Caddy's redirect to HTTPS both use it.
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
      domain_name    = var.domain_name
      acme_email     = var.acme_email
      retention_days = var.retention_days
      rate_per_hour  = var.rate_per_hour
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
// Shipped as source and built on the box rather than as a binary, so this
// stack needs no cross-compiler, no musl toolchain and no registry to push
// to. The trade is a first apply that takes several minutes on the small
// AMD shape; that is a one-off, and `terraform taint` re-runs just this.

resource "null_resource" "receiver" {
  triggers = {
    instance = oci_core_instance.this.id
    // Any change to the service's own source redeploys it, without touching
    // the host underneath.
    //
    // Scoped to src/ and the manifests rather than the whole directory: a
    // bare "**/*.rs" also matches generated code under target/, which would
    // make this hash change every time anyone built the receiver locally.
    source = sha256(join("", concat(
      [for f in fileset("${path.module}/../receiver", "src/**/*.rs") :
      filesha256("${path.module}/../receiver/${f}")],
      [filesha256("${path.module}/../receiver/Cargo.toml")],
      [filesha256("${path.module}/../receiver/Cargo.lock")],
    )))
  }

  connection {
    type        = "ssh"
    host        = oci_core_instance.this.public_ip
    user        = "ubuntu"
    private_key = file(var.ssh_private_key_path)
    timeout     = "10m"
  }

  // cloud-init is still installing rust and Caddy when SSH first answers.
  provisioner "remote-exec" {
    inline = [
      "cloud-init status --wait || true",
      "mkdir -p /home/ubuntu/receiver/src",
    ]
  }

  // Named files rather than the directory: copying ../receiver wholesale
  // would drag every local build artifact under target/ up the wire.
  provisioner "file" {
    source      = "${path.module}/../receiver/Cargo.toml"
    destination = "/home/ubuntu/receiver/Cargo.toml"
  }

  // Shipped so the box builds the same dependency versions that were tested
  // here, rather than whatever is newest on the day it is deployed.
  provisioner "file" {
    source      = "${path.module}/../receiver/Cargo.lock"
    destination = "/home/ubuntu/receiver/Cargo.lock"
  }

  provisioner "file" {
    source      = "${path.module}/../receiver/src/"
    destination = "/home/ubuntu/receiver/src"
  }

  provisioner "remote-exec" {
    inline = [
      "set -euo pipefail",
      "cd /home/ubuntu/receiver",
      "$HOME/.cargo/bin/cargo build --release",
      "sudo install -m 0755 target/release/firebreak-receiver /usr/local/bin/firebreak-receiver",
      "sudo systemctl restart firebreak-receiver",
      "sudo systemctl is-active --quiet firebreak-receiver",
      // Prove it end to end rather than trusting that the unit started:
      // a service that is 'active' but not answering is the failure this
      // whole stack exists to avoid discovering months later.
      "for i in $(seq 1 10); do curl -fsS http://127.0.0.1:8787/healthz && break || sleep 2; done",
    ]
  }
}
