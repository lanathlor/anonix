##############################################################################
# QEMU VM test for the duress passphrase (modules/duress.nix +
# modules/persist-provision.nix).
#
# Drives the real modules/duress-unlock-core.sh and persist-provision script
# against a scratch LUKS volume on /dev/vdb (keyfile unlock, same approach as
# tests/update.nix). What it proves:
#   * Real key: /persist opens, data intact, LUKS header unchanged.
#   * Duress key: crypto-erase. The LUKS header UUID is rotated, the old real
#     key can no longer open the volume (master key gone), the canary is gone,
#     and the decoy login hash is seeded from the typed passphrase.
#   * Provisioning repopulates a working /persist (skeleton + fresh age id).
#   * No persistent forensic trace of the duress branch.
#
# Does not reboot through the real initrd. Initrd wiring is covered by the
# toplevel build and manual hardware checks. This test covers the mechanism.
#
# Run: `nix build .#checks.x86_64-linux.duress-wipes-persist -L` (or `just test-duress`).
##############################################################################
{ system, nixpkgs }:

let
  pkgs = nixpkgs.legacyPackages.${system};
  lib = nixpkgs.lib;

  # sha-512 crypt of "changeme"; only used as the provisioning fallback here.
  decoyHash = "$6$4jNpQuPiFL1C8ZUL$uRY1DG3W13oxGjvZKQGN4NWG0XvEOaU4rLSoIfI248Oifm.5muI.QfLH8xHTeLT11mnLRlFPpXlomsbV9kPr.1";

  # The exact production provisioning script.
  provisionScript = import ../modules/persist-provision-script.nix {
    inherit pkgs lib;
    inherit decoyHash;
  };

  # Wrap the production core (duress-unlock-core.sh) so the test drives the same
  # code the initrd runs. Tools come from PATH; the core contains no store paths.
  duressUnlock = pkgs.writeShellScriptBin "duress-unlock" ''
    export PATH=${
      lib.makeBinPath [
        pkgs.cryptsetup
        pkgs.e2fsprogs.bin
        pkgs.mkpasswd
        pkgs.util-linux
        pkgs.coreutils
      ]
    }:$PATH
    ${builtins.readFile ../modules/duress-unlock-core.sh}
    duress_unlock_persist "$1" "$2" "$3"
  '';
in
pkgs.testers.runNixOSTest {
  name = "duress-wipes-persist";

  nodes.machine = { pkgs, ... }: {
    imports = [
      ../modules/persist-provision.nix
      ../modules/admin.nix
    ];
    # /dev/vdb: the scratch persist volume.
    virtualisation.emptyDiskImages = [ 512 ];
    virtualisation.memorySize = 4096;
    virtualisation.cores = 2;
    environment.systemPackages = with pkgs; [
      cryptsetup
      e2fsprogs
      mkpasswd
      util-linux
      age
      duressUnlock
    ];
  };

  testScript = ''
    machine.wait_for_unit("multi-user.target")

    with subtest("set up a persist LUKS with real (slot 0) + duress (slot 7) keys"):
        machine.succeed("printf '%s' real-pass   > /tmp/real.key")
        machine.succeed("printf '%s' duress-pass > /tmp/duress.key")
        machine.succeed(
            "cryptsetup luksFormat --type luks2 --label persistcrypt -q "
            "--key-file /tmp/real.key /dev/vdb"
        )
        machine.succeed(
            "cryptsetup luksAddKey --key-slot 7 -q "
            "--key-file /tmp/real.key /dev/vdb /tmp/duress.key"
        )
        dump = machine.succeed("cryptsetup luksDump /dev/vdb")
        assert "0: luks2" in dump, dump
        assert "7: luks2" in dump, dump
        uuid_before = machine.succeed("cryptsetup luksUUID /dev/vdb").strip()

        # Seed a canary onto the encrypted /persist.
        machine.succeed("cryptsetup open --key-file /tmp/real.key /dev/vdb probe")
        machine.succeed("mkfs.ext4 -q -L persist /dev/mapper/probe")
        machine.succeed("mkdir -p /mnt && mount /dev/mapper/probe /mnt")
        machine.succeed("mkdir -p /mnt/secrets && echo TOP-SECRET-CANARY > /mnt/secrets/canary")
        machine.succeed("umount /mnt && cryptsetup close probe")

    with subtest("REAL passphrase: opens normally, data intact, no wipe"):
        machine.succeed("printf '%s' real-pass | ${duressUnlock}/bin/duress-unlock /dev/vdb persist 7")
        machine.succeed("test -b /dev/mapper/persist")
        machine.succeed("mount /dev/mapper/persist /mnt")
        assert machine.succeed("cat /mnt/secrets/canary").strip() == "TOP-SECRET-CANARY"
        machine.succeed("umount /mnt && cryptsetup close persist")
        assert machine.succeed("cryptsetup luksUUID /dev/vdb").strip() == uuid_before, \
            "REAL branch must not touch the LUKS header"

    with subtest("DURESS passphrase: crypto-erase + reformat, canary gone"):
        machine.succeed("printf '%s' duress-pass | ${duressUnlock}/bin/duress-unlock /dev/vdb persist 7")
        uuid_after = machine.succeed("cryptsetup luksUUID /dev/vdb").strip()
        assert uuid_after != uuid_before, "LUKS header not rotated -> no crypto-erase"
        # Old real key can no longer open the volume (master key gone).
        machine.fail("cryptsetup open --test-passphrase --key-file /tmp/real.key /dev/vdb")
        machine.succeed("test -b /dev/mapper/persist")
        machine.succeed("mount /dev/mapper/persist /mnt")
        machine.fail("test -e /mnt/secrets/canary")
        assert machine.succeed("blkid -s LABEL -o value /dev/mapper/persist").strip() == "persist"
        # Decoy login seeded from the typed duress passphrase.
        machine.succeed("test -s /mnt/secrets/anon.passwd")
        seeded = machine.succeed("cat /mnt/secrets/anon.passwd").strip()
        assert seeded.startswith("$6$"), "expected a sha-512 login hash, got: " + seeded
        machine.succeed("umount /mnt")

    with subtest("provisioning repopulates a working decoy on the wiped /persist"):
        machine.succeed("mkdir -p /persist && mount /dev/mapper/persist /persist")
        machine.succeed("${provisionScript}")
        machine.succeed("test -d /persist/secrets")
        assert machine.succeed("stat -c %a /persist/secrets").strip() == "700"
        machine.succeed("test -s /persist/secrets/anon.passwd")   # seeded hash preserved
        machine.succeed("test -s /persist/secrets/age-identity")  # fresh identity generated
        machine.succeed("test -d /persist/ws-secrets")
        machine.succeed("test -d /persist/microvms/workstation")
        machine.succeed("umount /persist")

    with subtest("no persistent forensic trace of the duress branch"):
        machine.succeed("mount /dev/mapper/persist /mnt")
        machine.fail("grep -rIl duress /mnt")
        machine.fail("test -e /mnt/secrets/.duress")
        machine.succeed("umount /mnt && cryptsetup close persist")
  '';
}
