# Firebreak: what this repository needs on a Shipyard fleet VM, as a NixOS module.
# Fleet Command (github.com/ghostpsalm/fleet-command) imports this file into
# every host that carries Firebreak; change it here and Fleet Command picks it up
# on its next input update and deploy. Use only fleet options and nixpkgs:
#   fleet.toolchains.rust.enable / .mingw.enable / .denoLatest.enable,
#   fleet.rust.targets, fleet.pkgConfigLibs, fleet.pythonPackages,
#   fleet.postgres.enable / .package / .setupSQL, fleet.factory.envPassthrough,
#   fleet.factory.gateEnv.<repo> (non-secret gate variables), environment.*
# Never credentials (this lands in the Nix store), never sudo grants.
#
#   Gate: stable Rust with rustfmt, clippy and the x86_64-pc-windows-gnu target
#   (Windows code is linted, never run), mingw-w64 cc for the bundled SQLite and
#   windres, a native cc, and Deno 2 for server/receiver. scripts/gate.sh fails
#   if any of them is missing. Running the app itself needs root and a real
#   firewall, so it is not done on a fleet VM.
{ pkgs, ... }:
{
  fleet.toolchains.rust.enable = true;
  fleet.toolchains.mingw.enable = true;
  fleet.rust.targets = [ "x86_64-pc-windows-gnu" ];
  environment.systemPackages = [ pkgs.deno ];
}
