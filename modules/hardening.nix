##############################################################################
# Anonymity- and privacy-oriented system hardening. Removes smaller ways a
# machine gives itself away or leaks data at rest. Does not replace the Tor
# gateway or the killswitch.
##############################################################################
{ config, lib, pkgs, ... }:

{
  ##########################################################################
  # Randomize the MAC address of every NIC on each connection. A udev .link
  # file ensures this applies regardless of which DHCP client is used
  # (systemd-udevd processes .link files even without networkd enabled).
  ##########################################################################
  environment.etc."systemd/network/99-mac-random.link".text = ''
    [Match]
    OriginalName=*

    [Link]
    MACAddressPolicy=random
  '';

  ##########################################################################
  # No NTP. Tor tolerates modest skew and derives time from the consensus;
  # a plain NTP client talks cleartext and reveals your real time source.
  # (For robust anonymous time, investigate Whonix's sdwdate.)
  ##########################################################################
  services.timesyncd.enable = false;

  ##########################################################################
  # Kernel / network hardening.
  ##########################################################################
  boot.kernelParams = [
    "slab_nomerge"
    "page_alloc.shuffle=1"
    "randomize_kstack_offset=on"
  ];

  boot.kernel.sysctl = {
    # No source routing, no redirects, reverse-path filtering on.
    "net.ipv4.conf.all.accept_redirects" = 0;
    "net.ipv4.conf.all.send_redirects" = 0;
    "net.ipv4.conf.all.accept_source_route" = 0;
    "net.ipv4.conf.all.rp_filter" = 1;
    "net.ipv4.conf.default.rp_filter" = 1;

    # General hardening.
    "kernel.kptr_restrict" = 2;
    "kernel.dmesg_restrict" = 1;
    "kernel.unprivileged_bpf_disabled" = 1;
    "net.core.bpf_jit_harden" = 2;
    "kernel.yama.ptrace_scope" = 2;

    # Core dumps can contain secrets; discard them instead.
    "kernel.core_pattern" = "|/bin/false";
  };

  systemd.coredump.enable = false;

  ##########################################################################
  # Volatile logs: journal in RAM only, nothing forensic survives a reboot.
  # /var/log is excluded from the impermanence keep-list. Combined with the
  # tmpfs root this makes the box near-amnesic (Whonix-style).
  ##########################################################################
  services.journald.storage = "volatile";
  services.journald.extraConfig = "SystemMaxUse=50M";

  ##########################################################################
  # Mandatory access control: contain a compromised app (browser, tooling).
  ##########################################################################
  security.apparmor.enable = true;

  ##########################################################################
  # Kernel image protection: no kexec, no hibernation, no runtime kernel
  # replacement. (Overlaps some side-channel sysctls; this meta-option is
  # the clean, comprehensive switch.)
  ##########################################################################
  security.protectKernelImage = true;
  # security.lockKernelModules = true;  # OPT-IN, RISKY: blocks loading any
  #   module after boot. Can break the microVM host (kvm/vhost/tun), the GUI
  #   (drm/virtio-gpu), and NIC/wg drivers unless every needed module is
  #   loaded at boot. Enable only after confirming the machine still works.

  ##########################################################################
  # Capability bounding on interactive logins (defense in depth).
  #
  # Strips capabilities needed to tear down the killswitch or subvert the
  # kernel from every process tree starting an interactive session (console
  # getty, serial console, SSH, the GUI greeter). The bounding set can only
  # shrink across fork/exec, so a login shell and everything it runs,
  # including setuid-root `doas`, can never regain these caps. Hence
  # `doas nft flush`, `doas wg-quick down`, `doas insmod` all fail with
  # EPERM even as uid 0.
  #
  # Limit: this is depth, not a boundary. A root shell can still reach the
  # full set through systemd:
  #   doas systemd-run -qt -p 'AmbientCapabilities=CAP_NET_ADMIN' \
  #     -p 'CapabilityBoundingSet=CAP_NET_ADMIN' nft list ruleset
  # because logind/PID 1 keep full caps by design. That is deliberate: it
  # forces network/kernel reconfiguration off the ad-hoc root shell and onto
  # a conspicuous, journal-logged, PID1-mediated path. Only a separate
  # physical gateway removes that option entirely (docs/workstation.md assurance ladder,
  # rung 3). With the amnesic root, any such tamper is gone on next reboot.
  #
  # Note: shell diagnostics that read/modify netfilter or the tunnel
  # (`nft list ruleset`, `wg-quick down ...`) need CAP_NET_ADMIN too. Run
  # them via the `systemd-run` form above when you intend them.
  ##########################################################################
  systemd.services =
    let
      drop.serviceConfig.CapabilityBoundingSet =
        "~CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BROADCAST CAP_SYS_MODULE";
    in
    lib.mkMerge [
      {
        "getty@" = drop;
        "serial-getty@" = drop;
      }
      (lib.mkIf config.services.openssh.enable { sshd = drop; })
      (lib.mkIf config.services.greetd.enable { greetd = drop; })
    ];

  ##########################################################################
  # USBGuard: block hot-plugged USB devices (BadUSB / rogue HID / storage)
  # while the machine is unlocked. Devices present at boot are allowed (so
  # your keyboard is not locked out); anything inserted afterwards is blocked
  # until authorized: `usbguard list-devices`, `usbguard allow-device <id>`.
  ##########################################################################
  services.usbguard = {
    enable = true;
    implicitPolicyTarget = "block";
    presentDevicePolicy = "allow";
    presentControllerPolicy = "allow";
  };

  ##########################################################################
  # Trim attack surface and fingerprint: no bluetooth, printing, avahi, etc.
  ##########################################################################
  hardware.bluetooth.enable = lib.mkDefault false;
  services.printing.enable = lib.mkDefault false;
  services.avahi.enable = lib.mkDefault false;
  networking.firewall.logRefusedConnections = false;

  # Drop the NixOS manual from the closure: smaller image, less on-disk
  # metadata about the configuration.
  documentation.nixos.enable = lib.mkDefault false;

  ##########################################################################
  # Nix: keep the build sandbox on. The box carries no public substituters
  # and takes pre-built closures out of band, so a rebuild does not phone
  # cache.nixos.org and emit a NixOS-usage fingerprint.
  # That policy lives in modules/updates.nix (anon.updates); see docs/updating.md.
  ##########################################################################
  nix.settings = {
    sandbox = true;
    experimental-features = [ "nix-command" "flakes" ];
    # Reduce metadata written about who built what.
    allowed-users = [ "@wheel" ];
  };

  # A generic, boring hostname is set in hosts/anon/default.nix.
}
