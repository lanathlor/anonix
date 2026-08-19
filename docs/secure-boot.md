# Secure Boot (managed, lanzaboote)

`modules/secure-boot.nix` signs kernel and initrd with your own Machine Owner
Keys, so the firmware only runs a boot chain you signed. This protects
against boot-chain tampering (an "evil maid" attack) that the unsigned
on-disk kernel would otherwise allow. It is managed: no manual `sbctl`
juggling.

- Keys are auto-generated on first boot at `/persist/secureboot`
  (LUKS-encrypted at rest, survives the wipe).
- Keys are auto-enrolled into the firmware (Microsoft keys included by
  default so option ROMs don't brick), then all artifacts re-signed.
- `autoGenerateKeys` implies `allowUnsigned`, so the first switch succeeds
  before keys exist.

## Bootstrap (one-time)

1. Install/switch normally; keys are generated on first boot.
2. Reboot into UEFI setup and clear the Platform Key / enable Setup Mode
   ("Erase all Secure Boot keys", "Custom mode"; wording varies). This is the
   one manual step.
3. Boot back in; `systemd-boot` enrolls the staged keys. Then enable Secure
   Boot in the firmware.
4. Verify:
   ```sh
   sbctl status          # Secure Boot: enabled, setup mode: disabled
   sbctl verify          # all boot files signed
   bootctl status        # "Secure Boot: enabled (user)"
   ```

Toggles (in `hosts/anon/default.nix`):

```nix
anon.secureBoot.enable = true;                # default
anon.secureBoot.includeMicrosoftKeys = true;  # default; safer (fewer bricks)
anon.secureBoot.autoReboot = false;           # reboot yourself after key staging
```

For keys-only (no Microsoft keys, stronger but riskier): set
`includeMicrosoftKeys = false` and
`boot.lanzaboote.autoEnrollKeys.allowBrickingMyMachine = true`, only after
confirming your hardware needs no MS-signed option ROMs.

## Measured Boot (TPM2 LUKS unlock)

`anon.secureBoot.tpm2Unlock` (default on) uses a systemd initrd so the LUKS
volumes auto-unlock from the TPM2, sealed to PCR 7 + PCR 11. The disk
decrypts only while the exact signed boot chain is intact; tamper with it and
it falls back to asking for the passphrase. PCR 11 matters: PCR 7 only
reflects which keys are enrolled, so with Microsoft keys present any
MS-signed loader satisfies it, while PCR 11 pins the actual kernel + initrd +
cmdline. Enroll once on the running machine (until then it just prompts for
the passphrase):

```sh
doas systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs=7+11 /dev/disk/by-label/nixcrypt
doas systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs=7+11 /dev/disk/by-label/persistcrypt
```

Without a TPM it falls back to the passphrase. PCR 11 changes on every
kernel/initrd update, so re-run the enroll commands after such an update (or
adopt a signed PCR policy). `anon.secureBoot.tpm2Unlock = false` gives a
passphrase-only initrd; `anon.secureBoot.tpm2Pcrs` changes the bound set.
