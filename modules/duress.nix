##############################################################################
# Duress passphrase.
#
# Enrols a second LUKS passphrase (a separate keyslot on both encrypted
# volumes). At boot you type one passphrase:
#   * the real one    -> normal boot, all data intact.
#   * the duress one  -> /persist is crypto-erased (its LUKS master key is
#                        destroyed and the volume reformatted, instantly and
#                        irreversibly) and the machine boots into a working
#                        but empty system. To an observer, the boot looks and
#                        behaves exactly like a normal unlock.
# The decoy's login password is the duress passphrase itself (seeded by the
# initrd). A fresh /persist is repopulated by modules/persist-provision.nix.
#
# HOW IT WORKS: a scripted-initrd hook (boot.initrd.preLVMCommands) prompts
# once, captures the passphrase, and checks whether it matches the duress
# keyslot (`--test-passphrase --key-slot N`). It then opens /persist normally
# or erases and reformats it. /nix is never wiped; the duress key is enrolled
# there only so /nix still opens.
#
# TRADE-OFFS (read before enabling):
#   * Requires a typed passphrase. Incompatible with TPM2 auto-unlock (a
#     machine that auto-unlocks never sees the passphrase). Enabling duress
#     forces anon.secureBoot.tpm2Unlock off and uses the scripted initrd.
#   * Not deniable against offline disk imaging: `cryptsetup luksDump` shows
#     two populated keyslots. An adversary with the powered-off disk can infer
#     a secondary key exists (it looks like a backup key; no labels leak
#     "duress"). It IS deniable to someone watching you boot. True
#     header-level hiding needs a VeraCrypt-style hidden volume (out of scope).
#   * Irreversible: typing the duress passphrase permanently destroys the data.
#
# Enrol the duress keyslot at install time with `install-anon` (see flake.nix).
##############################################################################
{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.anon.duress;

  # Encrypted partitions addressed by their stable disko partlabels.
  persistDev = "/dev/disk/by-partlabel/disk-main-persist";
  nixDev = "/dev/disk/by-partlabel/disk-main-nix";

  # Shared decision+erase logic in one POSIX file so the initrd and the VM
  # test run byte-identical code. Defines duress_unlock_persist().
  coreScript = builtins.readFile ./duress-unlock-core.sh;
in
{
  options.anon.duress = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Enable the boot-time duress passphrase. Typing the duress passphrase
        at the LUKS prompt crypto-erases /persist and boots a clean decoy.
        Forces anon.secureBoot.tpm2Unlock off and selects the scripted initrd.
      '';
    };

    keySlot = lib.mkOption {
      type = lib.types.ints.between 2 31;
      default = 7;
      description = ''
        LUKS2 keyslot holding the duress passphrase on both volumes.
        Single source of truth: install-anon enrols exactly this slot.
        Slots 0 (real passphrase) and 1 (TPM2 enrolment, if used) are avoided.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    # Duress needs the passphrase typed, so TPM2 auto-unlock must be off and
    # the scripted initrd (which runs preLVMCommands) must be active.
    anon.secureBoot.tpm2Unlock = lib.mkForce false;
    boot.initrd.systemd.enable = lib.mkForce false;
    warnings = [
      (
        "anon.duress.enable: TPM2 auto-unlock is disabled. Duress needs a typed "
        + "passphrase, so the disk always prompts at boot."
      )
    ];

    # Stage extra tools needed by the duress branch into the initrd.
    # cryptsetup is already present (disko declares boot.initrd.luks.devices).
    # mke2fs (as mkfs.ext4, whose ext4 defaults depend on argv[0]) needs its
    # config file; mkpasswd seeds the decoy login hash.
    boot.initrd.extraUtilsCommands = ''
      copy_bin_and_libs ${pkgs.e2fsprogs.bin}/bin/mke2fs
      ln -sf mke2fs $out/bin/mkfs.ext4
      mkdir -p $out/etc
      cp -f ${pkgs.e2fsprogs.out}/etc/mke2fs.conf $out/etc/mke2fs.conf
      copy_bin_and_libs ${pkgs.mkpasswd}/bin/mkpasswd
    '';
    boot.initrd.extraUtilsCommandsTest = ''
      $out/bin/mkfs.ext4 -V
      echo probe | $out/bin/mkpasswd -m sha-512 -s >/dev/null
    '';

    # Duress-aware unlock, run BEFORE the scripted initrd opens the LUKS
    # devices. We open both mappers here; NixOS's own LUKS step then finds
    # /dev/mapper/{nix,persist} already present and skips its prompt (the
    # "opened externally" path in nixos/.../luksroot.nix do_open_passphrase).
    boot.initrd.preLVMCommands = ''
      ${coreScript}

      # Only if nothing is open yet (re-entrancy / resume safety).
      if [ ! -e /dev/mapper/persist ] || [ ! -e /dev/mapper/nix ]; then
        # The encrypted partitions should already be present (udev settled
        # before preLVMCommands), but wait briefly just in case.
        _n=0
        while [ ! -e ${persistDev} ] || [ ! -e ${nixDev} ]; do
          _n=$((_n + 1)); [ "$_n" -ge 30 ] && break; sleep 1
        done

        # Prompt once; the same passphrase opens both volumes. Re-prompt on a
        # wrong password exactly as the stock LUKS prompt would (no message
        # that could distinguish the duress path).
        while :; do
          printf 'Enter passphrase for disk: ' > /dev/console
          IFS= read -rs _try < /dev/console || _try=
          printf '\n' > /dev/console
          if printf '%s' "$_try" | cryptsetup open --test-passphrase \
               --key-file - ${persistDev} >/dev/null 2>&1; then
            break
          fi
          printf 'No key available with this passphrase.\n' > /dev/console
        done

        # /persist: duress-aware (may crypto-erase). /nix: plain open, never
        # wiped (the duress key is enrolled there only so it still opens).
        printf '%s' "$_try" | duress_unlock_persist ${persistDev} persist ${toString cfg.keySlot}
        printf '%s' "$_try" | cryptsetup open --key-file - ${nixDev} nix >/dev/null 2>&1 || :

        _try=
        unset _try 2>/dev/null || :
      fi
    '';
  };
}
