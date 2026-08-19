# anonix task runner.
# Ad-hoc: nix run nixpkgs#just -- <target>   Shell: nix shell nixpkgs#just

host := "anon"

# List available targets.
default:
    @just --list

# Run the whole CI pipeline locally (same order as the GitHub workflow):
# lint, every flake check, the CI/demo ISO, SBOM + CVE audit. Needs /dev/kvm
# for the VM checks; on a machine without it use `just ci-tcg`.
ci: lint test iso-ci audit

# Same pipeline for a machine without /dev/kvm (VM tests via TCG emulation).
ci-tcg: lint test-tcg iso-ci audit

# Evaluate the flake and all NixOS assertions. Requires the VPN endpoint
# filled in (modules/vpn.nix) or the placeholder assertion fails by design.
check:
    nix flake check --show-trace

# Build the full system closure (won't activate anything).
build:
    nixos-rebuild build --flake .#{{host}} --show-trace

# Build a QEMU VM image from the vmVariant (applies the test overrides).
build-vm:
    nixos-rebuild build-vm --flake .#{{host}} --show-trace

# Build the offline live-USB installer ISO -> result/iso/anon-installer.iso.
# Requires real VPN values and the encrypted key (anon closure is baked in).
iso:
    nix build .#installer-iso --show-trace
    @echo "ISO: $(readlink -f result)/iso/anon-installer.iso"

# Build the CI/demo installer ISO (dummy VPN values baked in; a system
# installed from it stays offline by design). No secrets needed.
iso-ci:
    nix build .#installer-iso-ci --show-trace
    @echo "ISO: $(readlink -f result)/iso/anon-installer-ci.iso"

# Build and boot the VM in QEMU (serial console; Ctrl-a x to quit).
# The tunnel stays down (no VPN key), so the guest is offline by design.
vm: build-vm
    ./result/bin/run-{{host}}-vm -nographic

# Apply to this machine only. The anon system uses doas, not sudo.
switch:
    doas nixos-rebuild switch --flake .#{{host}}

# Build every flake check (auto-discovered; new checks need no list edits here).
# KVM-backed VM checks need /dev/kvm; eval-only checks do not.
test:
    nix build -L --show-trace $(nix eval --raw --apply 'cs: builtins.concatStringsSep " " (map (n: ".#checks.x86_64-linux." + n) (builtins.attrNames cs))' .#checks.x86_64-linux)

# Run all checks WITHOUT /dev/kvm: eval-only checks build normally; VM tests
# run their drivers (not KVM-gated) under QEMU TCG software emulation, which
# is slow (~1-7 min per test). Per-test logs land in a temp dir.
test-tcg:
    #!/usr/bin/env bash
    set -euo pipefail
    unset XDG_RUNTIME_DIR QEMU_OPTS
    logdir=$(mktemp -d -t anonix-tests.XXXXXX)
    fail=0
    for t in $(nix eval --raw .#checks.x86_64-linux --apply 'cs: builtins.concatStringsSep " " (builtins.attrNames cs)'); do
      # VM tests expose a .driver attribute; eval-only checks do not. Any
      # other eval outcome is an infrastructure error, not a missing driver.
      hd=$(nix eval --raw ".#checks.x86_64-linux.$t" \
             --apply 'c: if c ? driver then "vm" else "eval-only"' \
             2>"$logdir/$t.eval.log") || hd=error
      case "$hd" in
        vm)
          drv=$(nix build ".#checks.x86_64-linux.$t.driver" --no-link \
                  --print-out-paths 2>"$logdir/$t.log") \
            || { echo "FAIL(driver-build) $t  log: $logdir/$t.log"; fail=1; continue; }
          rundir=$(mktemp -d "$logdir/run-$t.XXXXXX")
          start=$(date +%s)
          if (cd "$rundir" && "$drv/bin/nixos-test-driver" >"$logdir/$t.log" 2>&1); then
            echo "PASS $t ($(( $(date +%s) - start ))s)"
          else
            echo "FAIL $t ($(( $(date +%s) - start ))s)  log: $logdir/$t.log"; fail=1
          fi
          ;;
        eval-only)
          if nix build ".#checks.x86_64-linux.$t" --no-link >"$logdir/$t.log" 2>&1; then
            echo "PASS(build) $t"
          else
            echo "FAIL(build) $t  log: $logdir/$t.log"; fail=1
          fi
          ;;
        *)
          echo "FAIL(eval) $t  log: $logdir/$t.eval.log"; fail=1
          ;;
      esac
    done
    exit "$fail"

# Run just the gateway security / hardening / escalation VM test.
test-sec:
    nix build .#checks.x86_64-linux.gateway-security -L --show-trace

# Run just the no-clearnet-leak VM test (tunnel up, capture the WAN wire).
test-leak:
    nix build .#checks.x86_64-linux.no-clearnet-leak -L --show-trace

# Run just the duress-passphrase test (crypto-erase /persist + reprovision).
test-duress:
    nix build .#checks.x86_64-linux.duress-wipes-persist -L --show-trace

# Workstation return-traffic regression: eval-level ruleset check (no KVM) plus
# the end-to-end VM proof (needs KVM).
test-ws-return:
    nix build .#checks.x86_64-linux.workstation-return-ruleset .#checks.x86_64-linux.workstation-return -L --show-trace

# Fail-closed under component failure (needs KVM): kill Tor, kill the VPN, or
# kill the whole gateway (workstation isolation).
test-killswitch:
    nix build .#checks.x86_64-linux.killswitch-egress .#checks.x86_64-linux.killswitch-gateway-down -L --show-trace

# Lint the Nix sources (same tools and pins as CI; see statix.toml).
lint:
    nix run --inputs-from . --flake-registry "" nixpkgs#statix -- check .
    nix run --inputs-from . --flake-registry "" nixpkgs#deadnix -- --fail -L .

# Generate SBOMs (SPDX + CycloneDX + csv) of the full system closure, using
# the CI variant so no secrets are needed. Same tools and pins as CI.
sbom:
    nix build .#anon-ci-system -o result-system
    nix run --inputs-from . --flake-registry "" nixpkgs#sbomnix -- "$(readlink -f result-system)" --cdx sbom.cdx.json --spdx sbom.spdx.json --csv sbom.csv

# CVE-audit the system closure: grype scan of the CycloneDX SBOM. Fails on
# any Critical finding (same gate as CI). Triage false positives / accepted
# risks in .grype.yaml — never by loosening the gate.
audit: sbom
    nix run --inputs-from . --flake-registry "" nixpkgs#grype -- sbom:./sbom.cdx.json --fail-on critical

# Format the Nix files.
fmt:
    nix fmt

# Format Markdown with prettier.
fmt-md:
    nix run nixpkgs#nodePackages.prettier -- --write "**/*.md"

# Activate the repo's git hooks (pre-commit formats staged Markdown).
install-hooks:
    git config core.hooksPath .githooks
    @echo "core.hooksPath -> .githooks (pre-commit will prettier-format staged .md)"

# Remove build artifacts.
clean:
    rm -f result result-vm result-system sbom.cdx.json sbom.spdx.json sbom.csv
