##############################################################################
# Fast, eval-level security invariants for the real `anon` configuration.
#
# Requires no QEMU and no VPN values. Inspects the evaluated config and
# fails the build if any security-critical option drifts. Covers properties a
# booted VM cannot observe, notably the locked root account (the nixosTest
# framework force-unlocks root for console access).
#
# Build: `nix build .#checks.x86_64-linux.anon-security-invariants -L`.
##############################################################################
{ system, nixpkgs, config }:

let
  pkgs = nixpkgs.legacyPackages.${system};
  lib = nixpkgs.lib;
  c = config;

  checks = [
    { name = "root account is locked (no usable password)";
      ok = c.users.users.root.hashedPassword == "!"; }
    { name = "sudo is disabled";
      ok = c.security.sudo.enable == false; }
    { name = "doas is enabled";
      ok = c.security.doas.enable == true; }
    { name = "users are immutable";
      ok = c.users.mutableUsers == false; }
    { name = "the admin user is in wheel";
      ok = lib.elem "wheel" c.users.users.anon.extraGroups; }
    { name = "doas rules are wheel-only, no keepEnv, no passwordless";
      ok = c.security.doas.extraRules != [ ] && lib.all
        (r: (r.groups or [ ]) == [ "wheel" ]
          && (r.noPass or false) == false
          && (r.keepEnv or false) == false)
        c.security.doas.extraRules; }
    { name = "IPv6 disabled system-wide";
      ok = c.boot.kernel.sysctl."net.ipv6.conf.all.disable_ipv6" == 1; }
    { name = "kernel pointer/ptrace/bpf hardening";
      ok = c.boot.kernel.sysctl."kernel.kptr_restrict" == 2
        && c.boot.kernel.sysctl."kernel.yama.ptrace_scope" == 2
        && c.boot.kernel.sysctl."kernel.unprivileged_bpf_disabled" == 1; }
    { name = "stock firewall off, nftables killswitch on";
      ok = c.networking.firewall.enable == false && c.networking.nftables.enable == true; }
    { name = "sealed appliance: no public substituters";
      ok = c.nix.settings.substituters == [ ]; }
    { name = "sealed appliance: box cannot mutate itself (no nix on the box)";
      ok = c.nix.enable == false; }
    { name = "interactive logins are capability-bounded out of CAP_NET_ADMIN";
      ok = let s = c.systemd.services."getty@".serviceConfig.CapabilityBoundingSet or "";
           in lib.hasPrefix "~" s
             && lib.hasInfix "CAP_NET_ADMIN" s
             && lib.hasInfix "CAP_SYS_MODULE" s; }
    { name = "workstation VM runs unprivileged (a hypervisor escape is NOT gateway root)";
      ok = !c.anon.workstation.enable
        || (let u = (c.systemd.services."microvm@" or { serviceConfig = { }; })
                      .serviceConfig.User or null;
            in u != null && u != "root" && u != "0"); }
    { name = "no unproxied NTP";
      ok = c.services.timesyncd.enable == false; }
    { name = "volatile journald (no on-disk logs)";
      ok = c.services.journald.storage == "volatile"; }
    { name = "SMT/hyper-threading disabled by default (side-channel)";
      ok = c.anon.sideChannel.disableSMT == true; }
    { name = "online Nix fetch is opt-in (off by default)";
      ok = c.anon.updates.allowOnlineFetch == false; }
  ];

  failed = lib.filter (x: !x.ok) checks;
  report = lib.concatMapStringsSep "\n"
    (x: "  ${if x.ok then "PASS" else "FAIL"}  ${x.name}") checks;
in
pkgs.runCommand "anon-security-invariants"
  {
    inherit report;
    passed = toString (builtins.length checks - builtins.length failed);
    total = toString (builtins.length checks);
  } ''
  printf 'anon security invariants (%s/%s passed):\n%s\n' "$passed" "$total" "$report"
  touch "$out"
  ${lib.optionalString (failed != [ ]) ''
    printf '\nSECURITY INVARIANTS FAILED (see FAIL lines above).\n' >&2
    exit 1
  ''}
''
