##############################################################################
# Whonix/Kicksecure-style side-channel hardening.
#
# The Tor gateway + killswitch protect the network path. This module addresses
# the additional side-channel classes that Whonix/Kicksecure cover:
#
#   * Microarchitectural: disable SMT/Hyper-Threading and force all
#     speculative-execution mitigations (SMT enables L1TF/MDS/TAA family leaks).
#   * Timing: disable TCP timestamps, randomize the clock at boot, no clearnet NTP.
#   * DMA: enable the IOMMU, block early-boot PCI DMA, blacklist FireWire/
#     Thunderbolt and rare-protocol modules used for DMA and driver attacks.
#   * Memory disclosure: zero-on-alloc/free, kernel lockdown, optional hardened_malloc.
#   * Traffic analysis: connection/circuit padding, seccomp sandbox, stream
#     isolation per destination (configured in tor-gateway.nix).
#
# Whonix's sdwdate is Debian-specific and not in nixpkgs. NTP is disabled and
# boot-clock randomization approximates its intent; keep the RTC roughly correct.
##############################################################################
{ config, lib, pkgs, ... }:

let
  cfg = config.anon.sideChannel;

  # Randomize the clock by a small +/- offset at every boot so the machine's
  # wall clock is not perfectly correlated with real time. TCP timestamps are
  # disabled separately, so sub-second precision is not needed here.
  bootClockRandomize = pkgs.writeShellScript "boot-clock-randomize" ''
    set -eu
    range=${toString cfg.bootClockRandomizationRange}
    rand=$(${pkgs.coreutils}/bin/od -An -N4 -tu4 /dev/urandom | ${pkgs.coreutils}/bin/tr -d ' ')
    offset=$(( rand % (2 * range + 1) - range ))
    now=$(${pkgs.coreutils}/bin/date +%s)
    ${pkgs.coreutils}/bin/date -s "@$(( now + offset ))" >/dev/null
    echo "[boot-clock-randomization] applied ''${offset}s offset"
  '';
in {
  options.anon.sideChannel = {
    disableSMT = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''
        Disable SMT/Hyper-Threading and force full CPU mitigations. SMT is the
        precondition for cross-thread microarchitectural leaks. Costs some
        performance; set false only if you accept the risk.
      '';
    };
    hardenedMalloc = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Use GrapheneOS hardened_malloc as the system-wide allocator (Kicksecure
        default). Strong heap-exploit mitigation, but as a system-wide
        ld.so.preload it can break fragile programs and has stalled early boot
        in minimal environments. Test your workload before relying on it.
      '';
    };
    bootClockRandomizationRange = lib.mkOption {
      type = lib.types.ints.positive;
      default = 15;
      description = "Max magnitude, in seconds, of the random boot clock offset.";
    };
  };

  config = {
    ########################################################################
    # Kernel hardening.
    # nixpkgs removed linuxPackages_hardened; Whonix/Kicksecure also do not
    # ship a hardened-patchset kernel and instead harden the stock kernel via
    # boot parameters, sysctls, and lockdown, which is what this module does.
    # To pin your own hardened kernel, set boot.kernelPackages in the host.
    # Hardened allocator (Kicksecure default, opt-in; see hardenedMalloc option).
    ########################################################################
    environment.memoryAllocator.provider =
      lib.mkIf cfg.hardenedMalloc "graphene-hardened";

    ########################################################################
    # Kernel command line.
    ########################################################################
    boot.kernelParams = [
      # Memory disclosure: zero pages on allocation and free.
      "init_on_alloc=1"
      "init_on_free=1"
      # Shrink kernel attack/observation surface.
      "vsyscall=none"
      "debugfs=off"
      "oops=panic"
      "lockdown=confidentiality"
      # Don't trust the CPU's RNG as the sole entropy source.
      "random.trust_cpu=off"
      # DMA protection: IOMMU on and strict, block early PCI DMA before the
      # kernel takes over (Thunderbolt/PCILeech-style attacks).
      "efi=disable_early_pci_dma"
      "intel_iommu=on"
      "amd_iommu=on"
      "iommu=force"
      "iommu.strict=1"
      "iommu.passthrough=0"
    ] ++ lib.optionals cfg.disableSMT [
      # Kill SMT and pin the full speculative-execution mitigation set.
      "nosmt"
      "mds=full,nosmt"
      "l1tf=full,force"
      "tsx=off"
      "tsx_async_abort=full,nosmt"
      "mmio_stale_data=full,nosmt"
      "retbleed=auto,nosmt"
      "gather_data_sampling=force"
      "reg_file_data_sampling=on"
      "kvm.nx_huge_pages=force"
    ];

    ########################################################################
    # Sysctls (keys not already set in hardening.nix).
    ########################################################################
    boot.kernel.sysctl = {
      # Remote uptime / clock-skew fingerprinting via TCP timestamps.
      "net.ipv4.tcp_timestamps" = 0;
      # Microarchitectural measurement tooling for unprivileged users.
      "kernel.perf_event_paranoid" = 3;
      # Attack surface / recovery-path side channels.
      "kernel.kexec_load_disabled" = 1;
      "kernel.sysrq" = 0;
      "dev.tty.ldisc_autoload" = 0;
      "vm.unprivileged_userfaultfd" = 0;
    };

    ########################################################################
    # Module blacklist: DMA (FireWire/Thunderbolt), rare network protocols,
    # and uncommon filesystems.
    ########################################################################
    boot.blacklistedKernelModules = [
      # DMA / driver attack surface
      "firewire-core" "firewire-ohci" "firewire-sbp2" "thunderbolt"
      # Rare / legacy network protocols
      "dccp" "sctp" "rds" "tipc" "n-hdlc" "ax25" "netrom" "x25" "rose"
      "decnet" "econet" "af_802154" "ipx" "appletalk" "psnap" "p8023"
      "p8022" "can" "atm"
      # Uncommon filesystems
      "cramfs" "freevxfs" "jffs2" "hfs" "hfsplus" "udf" "gfs2"
      # Known-buggy / unused
      "vivid" "bluetooth" "btusb"
    ];

    ########################################################################
    # Boot clock randomization (Whonix-style).
    ########################################################################
    systemd.services.boot-clock-randomization = {
      description = "Randomize system clock to hinder time-based correlation (Whonix-style)";
      wantedBy = [ "network-pre.target" ];
      before = [
        "network-pre.target"
        "wg-quick-wg-tunnel.service"
        "tor.service"
      ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStart = bootClockRandomize;
      };
    };
  };
}
