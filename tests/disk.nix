##############################################################################
# Eval-level guards for the runtime-selectable install target (--disk), which
# works by building the disko script against a sentinel device path and
# rewriting it at install time. Two things must hold, neither visible from a
# booted VM:
#
#   1. The system closure must not depend on the target device, or the baked
#      closure would disagree with the disk it was installed to.
#   2. The sentinel must appear in the generated script. If disko stops
#      inlining the device, the rewrite silently no-ops. install-anon aborts on
#      a surviving sentinel, but that should fail at build time, not in front
#      of someone holding a USB stick.
#
# Requires no QEMU and no VPN values.
#
# Build: `nix build .#checks.x86_64-linux.disk-target-is-runtime-selectable -L`.
##############################################################################
{ system, nixpkgs, anon, targetSentinel }:

let
  pkgs = nixpkgs.legacyPackages.${system};
  lib = nixpkgs.lib;

  # The same override mkInstaller applies, plus dummy VPN values so this check
  # evaluates without secrets (the placeholder assertion would otherwise trip).
  withDevice = dev: anon.extendModules {
    modules = [{
      disko.devices.disk.main.device = lib.mkForce dev;
      anon.vpn.endpointIp = lib.mkForce "192.0.2.1";
      anon.vpn.serverPublicKey = lib.mkForce "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    }];
  };

  sentinelCfg = withDevice targetSentinel;
  # Two arbitrary, structurally different device names. If the closure is
  # device-independent, all three of these produce the same derivation.
  nvmeCfg = withDevice "/dev/nvme0n1";
  sataCfg = withDevice "/dev/sda";

  diskoScript = sentinelCfg.config.system.build.diskoScript;

  checks = [
    { name = "system closure is identical for /dev/nvme0n1 and /dev/sda";
      ok = nvmeCfg.config.system.build.toplevel.drvPath
        == sataCfg.config.system.build.toplevel.drvPath; }
    { name = "system closure is identical for the sentinel and a real device";
      ok = sentinelCfg.config.system.build.toplevel.drvPath
        == nvmeCfg.config.system.build.toplevel.drvPath; }
    { name = "no filesystem is mounted by device name (labels only)";
      ok = lib.all (fs: fs.device == null || !lib.hasPrefix "/dev/nvme" fs.device)
        (lib.attrValues nvmeCfg.config.fileSystems); }
    { name = "LUKS containers are opened by partlabel, not device name";
      ok = lib.all (d: lib.hasPrefix "/dev/disk/by-" d.device)
        (lib.attrValues nvmeCfg.config.boot.initrd.luks.devices); }
  ];

  failed = lib.filter (x: !x.ok) checks;
  report = lib.concatMapStringsSep "\n"
    (x: "  ${if x.ok then "PASS" else "FAIL"}  ${x.name}") checks;
in
pkgs.runCommand "disk-target-is-runtime-selectable"
  {
    inherit report diskoScript targetSentinel;
    passed = toString (builtins.length checks - builtins.length failed);
    total = toString (builtins.length checks);
  } ''
  printf 'install target invariants (%s/%s eval checks passed):\n%s\n' \
    "$passed" "$total" "$report"
  ${lib.optionalString (failed != [ ]) ''
    printf '\nINSTALL TARGET INVARIANTS FAILED (see FAIL lines above).\n' >&2
    exit 1
  ''}

  # The generated script must contain the sentinel, or install-anon's rewrite
  # would have nothing to replace.
  n=$(grep -c -- "$targetSentinel" "$diskoScript" || true)
  if [ "$n" -eq 0 ]; then
    printf '  FAIL  disko inlines the device path as the sentinel\n' >&2
    printf '\nThe sentinel %s does not appear in the generated disko script.\n' \
      "$targetSentinel" >&2
    printf 'disko changed how it emits the device; --disk would not work.\n' >&2
    exit 1
  fi
  printf '  PASS  disko inlines the device path as the sentinel (%s occurrences)\n' "$n"

  # Rewriting every occurrence must leave no trace of the sentinel behind --
  # this is exactly what install-anon does before partitioning.
  sed "s|$targetSentinel|/dev/sdz|g" "$diskoScript" > rewritten
  if grep -q -- "$targetSentinel" rewritten; then
    printf '  FAIL  a global rewrite replaces every occurrence\n' >&2
    exit 1
  fi
  printf '  PASS  a global rewrite replaces every occurrence\n'

  touch "$out"
''
