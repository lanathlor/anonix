{ config, lib, pkgs, pkgs-unstable, ... }:

{
  imports = [
    ./hardware-configuration.nix
    ../../modules/disk.nix
    ../../modules/impermanence.nix
    ../../modules/persist-provision.nix
    ../../modules/duress.nix
    ../../modules/secrets.nix
    ../../modules/vpn.nix
    ../../modules/tor-gateway.nix
    ../../modules/hardening.nix
    ../../modules/updates.nix
    ../../modules/admin.nix
    ../../modules/side-channel.nix
    ../../modules/secure-boot.nix
    ../../modules/microvm-host.nix
    ../../modules/workstation-viewer.nix
  ];

  ##########################################################################
  # Boot loader
  ##########################################################################
  boot.loader.systemd-boot.enable = true;
  boot.loader.efi.canTouchEfiVariables = true;
  # Do not advertise the distro in the boot menu / motd more than necessary.
  boot.loader.timeout = 1;

  ##########################################################################
  # Identity: keep it generic and non-fingerprintable.
  ##########################################################################
  networking.hostName = "anon";
  time.timeZone = "UTC"; # Never leak a local timezone.
  i18n.defaultLocale = "en_US.UTF-8";

  # A few workstation tools carry unfree licenses: VeraCrypt (deniable hidden
  # volumes), wpscan (non-commercial), waybackurls. Allow exactly those. The
  # microVM reuses the host's nixpkgs instance, so the allowance must live here
  # (the guest uses an externally-created pkgs, not its own nixpkgs.config).
  nixpkgs.config.allowUnfreePredicate = pkg:
    lib.elem (lib.getName pkg) [ "veracrypt" "wpscan" "waybackurls" ];

  # Kicksecure-style hardened heap allocator (GrapheneOS hardened_malloc) on the
  # gateway. The gateway is minimal (Tor/wg/nft), so compatibility risk is low.
  # If a service misbehaves or early boot stalls, flip this off.
  # Not set on the workstation guest, where KDE is more likely to trip a strict
  # allocator; enable there only after testing.
  anon.sideChannel.hardenedMalloc = true;

  # Duress passphrase: a second boot passphrase that crypto-erases /persist and
  # boots a clean decoy (plausible deniability under coercion). See duress.nix.
  # Incompatible with TPM2 auto-unlock (requires a typed passphrase at boot),
  # so enabling this forces anon.secureBoot.tpm2Unlock off. Enrol with
  # install-anon. Set false to keep TPM2 auto-unlock instead.
  anon.duress.enable = true;

  # Users, doas, and locked-root policy live in modules/admin.nix (shared with
  # tests/security.nix so the escalation posture is asserted).

  ##########################################################################
  # Minimal, privacy-respecting base system.
  ##########################################################################
  environment.systemPackages = with pkgs; [
    tor
    torsocks
    wireguard-tools
    git
    # From unstable: stable's vim lags with a large backlog of open CVEs.
    pkgs-unstable.vim
  ];

  # Tor Browser is the correct way to browse anonymously even behind a
  # transparent proxy (it also defeats browser fingerprinting). Uncomment:
  # environment.systemPackages = [ pkgs.tor-browser-bundle-bin ];

  # Absolutely no remote entry points.
  services.openssh.enable = lib.mkDefault false;

  system.stateVersion = "26.05";

  ##########################################################################
  # QEMU test build overrides (used by `just vm` / `nixos-rebuild build-vm`).
  #
  # No real VPN key in the VM, so the tunnel stays down and the killswitch
  # keeps the guest offline. The VM boots to a login prompt for inspection.
  ##########################################################################
  virtualisation.vmVariant = {
    virtualisation = {
      memorySize = 2048;
      cores = 2;
      graphics = false; # serial console
      diskSize = 4096;
    };
    # Satisfy the killswitch assertion. 10.0.2.2 is the QEMU user-net gateway;
    # the tunnel still won't come up (no private key).
    anon.vpn.endpointIp = lib.mkForce "10.0.2.2";
    # Satisfy the serverPublicKey placeholder assertion (modules/vpn.nix).
    # Dummy but syntactically valid; never used on the wire.
    anon.vpn.serverPublicKey =
      lib.mkForce "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    # On hardware the password is a hash file on /persist. The VM backs /persist
    # with tmpfs so that file never exists; fall back to a known password (anon / nixos).
    users.users.anon.hashedPasswordFile = lib.mkForce null;
    users.users.anon.password = lib.mkForce "nixos";

    # hardened_malloc has been observed to stall early boot in a minimal VM. Off
    # here; stays on for the real gateway build.
    anon.sideChannel.hardenedMalloc = lib.mkForce false;

    # Secure Boot is a firmware feature; build-vm boots via -kernel and bypasses
    # the bootloader, so auto-enroll units would error. Validated by the real
    # toplevel build and on hardware.
    anon.secureBoot.enable = lib.mkForce false;

    # The duress feature acts on LUKS /persist in the initrd; the VM backs
    # /persist with tmpfs so cryptsetup opens would fail. Covered by the
    # toplevel build and tests/duress.nix.
    anon.duress.enable = lib.mkForce false;

    # The workstation microVM needs nested virtualization that build-vm does not
    # provide. The microVM split is validated by the toplevel build.
    anon.workstation.enable = lib.mkForce false;
    # Back /persist with tmpfs so no extra disk image is needed. Impermanence
    # still binds from it.
    fileSystems."/persist" = lib.mkVMOverride {
      device = "tmpfs";
      fsType = "tmpfs";
      neededForBoot = true;
      options = [ "mode=0755" ];
    };
  };
}
