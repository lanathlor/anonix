##############################################################################
# QEMU VM test for the non-destructive update (update-anon).
#
# Exercises the exact mechanism update-anon relies on: disko's mount-only script
# re-opening the existing encrypted volumes, and nixos-install writing a new
# system over an already-populated /nix + /persist. Asserts that /persist
# survives, the system profile advances, and the old generation is retained.
#
# Uses the real modules/disk.nix layout. Two test-only accommodations (neither
# changes the update mechanism):
#   * LUKS volumes are unlocked from a keyFile instead of an interactive passphrase.
#   * v1/v2 are minimal systems installed with --no-bootloader. This test does
#     not cover the lanzaboote/Secure-Boot re-sign path (see docs/updating.md).
#
# Run: `nix build .#checks.x86_64-linux.update-keeps-persist -L` (or `just test`).
##############################################################################
{ system, nixpkgs, disko }:

let
  pkgs = nixpkgs.legacyPackages.${system};
  lib = nixpkgs.lib;

  # Production disko layout pointed at the test disk, unlocked by keyFile.
  # Only `device` and `passwordFile` differ from modules/disk.nix.
  testDisk = {
    imports = [ ../modules/disk.nix ];
    disko.devices.disk.main.device = lib.mkForce "/dev/vdb";
    disko.devices.disk.main.content.partitions.nix.content.passwordFile = "/tmp/disk.key";
    disko.devices.disk.main.content.partitions.persist.content.passwordFile = "/tmp/disk.key";
  };

  # Minimal installable system with a version marker. v1/v2 differ only in that
  # marker; closures are almost entirely shared.
  mkSystem = marker: (nixpkgs.lib.nixosSystem {
    inherit system;
    modules = [
      disko.nixosModules.disko
      testDisk
      {
        nixpkgs.hostPlatform = system;
        documentation.enable = false;
        # A bootloader must be configured for the toplevel to evaluate, but we
        # never install it (--no-bootloader). systemd-boot evaluates without a grub device.
        boot.loader.systemd-boot.enable = true;
        boot.loader.efi.canTouchEfiVariables = false;
        environment.etc."update-test-generation".text = marker;
        users.users.root.hashedPassword = "!";
        system.stateVersion = "26.05";
      }
    ];
  }).config.system.build.toplevel;

  v1 = mkSystem "v1";
  v2 = mkSystem "v2";

  # disko's generated scripts: `disko` (format+mount, used by install-anon) and
  # `disko-mount` (mount-only, used by update-anon).
  diskoConf = (nixpkgs.lib.nixosSystem {
    inherit system;
    modules = [ disko.nixosModules.disko testDisk { nixpkgs.hostPlatform = system; } ];
  }).config;
  diskoScript = diskoConf.system.build.diskoScript;
  mountScript = diskoConf.system.build.mountScript;
in
pkgs.testers.runNixOSTest {
  name = "update-keeps-persist";

  nodes.machine = { pkgs, ... }: {
    # /dev/vdb: big enough for the real layout (nix=64G) on a sparse image.
    virtualisation.emptyDiskImages = [ 70000 ];
    virtualisation.memorySize = 4096;
    virtualisation.cores = 2;
    virtualisation.diskSize = 8192;
    environment.systemPackages = with pkgs; [ cryptsetup util-linux nixos-install-tools ];
    # Pre-populate both closures so nixos-install copies rather than fetches.
    system.extraDependencies = [ v1 v2 ];
  };

  testScript = ''
    machine.wait_for_unit("multi-user.target")
    machine.succeed("printf test-passphrase > /tmp/disk.key")

    with subtest("fresh install of v1 (format + install), like install-anon"):
        machine.succeed("${diskoScript}")
        machine.succeed("test -b /dev/mapper/nix && test -b /dev/mapper/persist")
        machine.succeed(
            "nixos-install --system ${v1} --root /mnt "
            "--no-root-passwd --no-bootloader --no-channel-copy >&2"
        )
        assert "${v1}" in machine.succeed("readlink -f /mnt/nix/var/nix/profiles/system")

    with subtest("mark /persist, then REBOOT (a genuine fresh boot, like a new USB)"):
        machine.succeed("echo keepme > /mnt/persist/marker")
        machine.succeed("umount -R /mnt")
        machine.succeed("sync")
        # Full power-cycle: QEMU relaunches with the same disk images, so /dev/vdb
        # persists while all LUKS/dm state is cleared. This is the exact starting
        # point of update-anon on a freshly booted USB.
        machine.shutdown()
        machine.start()
        machine.wait_for_unit("multi-user.target")
        # tmpfs /tmp is cleared by the reboot; recreate the unlock key.
        machine.succeed("printf test-passphrase > /tmp/disk.key")
        # Nothing is open or mounted yet.
        machine.fail("test -e /dev/mapper/nix")

    with subtest("update: non-destructive unlock + mount of the EXISTING disk"):
        # Mirror update-anon: disko's mountScript omits the LUKS open for one
        # container, so open both explicitly first, then let mountScript mount.
        machine.succeed("cryptsetup open /dev/disk/by-partlabel/disk-main-nix nix --key-file /tmp/disk.key")
        machine.succeed("cryptsetup open /dev/disk/by-partlabel/disk-main-persist persist --key-file /tmp/disk.key")
        machine.succeed("${mountScript}")
        # /persist survived the reboot + remount unchanged.
        assert machine.succeed("cat /mnt/persist/marker").strip() == "keepme"

    with subtest("install v2 OVER the existing store/persist (no format)"):
        machine.succeed(
            "nixos-install --system ${v2} --root /mnt "
            "--no-root-passwd --no-bootloader --no-channel-copy >&2"
        )
        # /persist STILL intact after the update.
        assert machine.succeed("cat /mnt/persist/marker").strip() == "keepme"

    with subtest("profile advanced to v2, and v1 is retained (rollback)"):
        assert "${v2}" in machine.succeed("readlink -f /mnt/nix/var/nix/profiles/system")
        machine.succeed("test -e /mnt/nix/var/nix/profiles/system-1-link")
        machine.succeed("test -e /mnt/nix/var/nix/profiles/system-2-link")
        machine.succeed("test -e ${v1}")
  '';
}
