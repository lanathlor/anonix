##############################################################################
# Managed UEFI Secure Boot via lanzaboote.
#
# lanzaboote replaces systemd-boot with a signed boot stub and signs the
# kernel and initrd with your Machine Owner Keys. This closes the evil-maid
# gap left by an unencrypted ESP (the kernel and initrd live in the Nix store).
#
# Key management is automatic:
#   * autoGenerateKeys: keys are created on first boot (allowUnsigned lets the
#     first switch install to the ESP before the keys exist).
#   * autoEnrollKeys: keys are enrolled into the firmware automatically
#     (Microsoft keys included by default so option ROMs do not brick), then
#     all artifacts are re-signed.
#
# The private signing keys live on /persist to survive the tmpfs wipe.
# lanzaboote keys the "already generated?" check on ${pkiBundle}/keys.
#
# One manual prerequisite: put the firmware into Secure Boot "Setup Mode"
# (clear the platform keys in your UEFI setup) before the enrollment boot.
##############################################################################
{ config, lib, pkgs, ... }:

let
  cfg = config.anon.secureBoot;
in {
  options.anon.secureBoot = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Manage UEFI Secure Boot with lanzaboote (replaces systemd-boot).";
    };

    pkiBundle = lib.mkOption {
      type = lib.types.str;
      # On /persist so the private signing keys survive the impermanence wipe.
      # On real hardware /persist should be LUKS-encrypted (see README).
      default = "/persist/secureboot";
      description = "Directory holding the Secure Boot PKI (db/KEK/PK).";
    };

    includeMicrosoftKeys = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''
        Also enroll Microsoft's keys. Many devices' firmware and GPU/NIC option
        ROMs are Microsoft-signed and will brick without them. Set false only
        after verifying your hardware needs no MS keys (and also set
        boot.lanzaboote.autoEnrollKeys.allowBrickingMyMachine).
      '';
    };

    autoReboot = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Reboot automatically once keys are staged so the firmware enrolls them
        on the next boot (only useful when the firmware is already in Setup
        Mode). Default off: you reboot when ready.
      '';
    };

    tpm2Unlock = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''
        Measured Boot: unlock LUKS volumes from the TPM2, sealed to PCR 7
        (Secure Boot policy) and PCR 11 (kernel + initrd + cmdline measured by
        the lanzaboote stub). Enroll on the running machine:
          doas systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs=7+11 \
            /dev/disk/by-label/nixcrypt
          doas systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs=7+11 \
            /dev/disk/by-label/persistcrypt
        Without a TPM or without enrollment it falls back to the passphrase
        prompt, so it is safe to leave on. PCR 11 is required in addition to
        PCR 7: PCR 7 alone is satisfied by any Microsoft-signed loader when MS
        keys are enrolled. PCR 11 changes on every kernel/initrd update; re-run
        the enroll commands after updates (it reverts to the passphrase until
        you do, which is safe). Mutually exclusive with anon.duress.enable:
        duress requires a typed passphrase, so enabling duress forces this off.
      '';
    };

    tpm2Pcrs = lib.mkOption {
      type = lib.types.str;
      default = "7+11";
      description = ''
        TPM2 PCRs for LUKS auto-unlock (crypttab tpm2-pcrs=). PCR 7 is the
        Secure Boot policy; PCR 11 is the kernel + initrd + cmdline measurement.
        Enroll with the same set (see tpm2Unlock) and re-enroll after updates.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    # lanzaboote replaces systemd-boot.
    boot.loader.systemd-boot.enable = lib.mkForce false;
    boot.loader.efi.canTouchEfiVariables = true;

    boot.lanzaboote = {
      enable = true;
      pkiBundle = cfg.pkiBundle;

      # Create keys on first boot (allowUnsigned lets the first switch succeed).
      autoGenerateKeys.enable = true;

      # Enroll into firmware automatically, then re-sign.
      autoEnrollKeys.enable = true;
      autoEnrollKeys.autoReboot = cfg.autoReboot;
      autoEnrollKeys.includeMicrosoftKeys = cfg.includeMicrosoftKeys;
    };

    # TPM2 LUKS unlock via systemd initrd (honours the tpm2-device crypttab option).
    # Device names come from modules/disk.nix. Falls back to passphrase if not
    # enrolled. Not active in the QEMU test VM (secureBoot forced off, no LUKS).
    boot.initrd.systemd.enable = lib.mkIf cfg.tpm2Unlock true;
    boot.initrd.luks.devices = lib.mkIf cfg.tpm2Unlock {
      nix.crypttabExtraOpts = [ "tpm2-device=auto" "tpm2-pcrs=${cfg.tpm2Pcrs}" ];
      persist.crypttabExtraOpts = [ "tpm2-device=auto" "tpm2-pcrs=${cfg.tpm2Pcrs}" ];
    };

    # Ensure PKI bundle dir exists on /persist before sbctl writes keys into it.
    systemd.tmpfiles.rules = [ "d ${cfg.pkiBundle} 0700 root root - -" ];

    # `sbctl` for manual inspection: `sbctl status`, `sbctl verify`, etc.
    environment.systemPackages = [ pkgs.sbctl ];
  };
}
