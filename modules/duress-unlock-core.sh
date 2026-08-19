# shellcheck shell=sh
##############################################################################
# Shared duress-unlock core (POSIX sh). Single source of truth for the
# boot-time branch that either opens /persist normally or, when the duress
# passphrase was typed, crypto-erases it and boots a clean decoy.
#
# Used in two places, so it must stay portable:
#   * modules/duress.nix  -> inlined verbatim into boot.initrd.preLVMCommands
#                            (runs under the scripted initrd's busybox ash;
#                            tools come from boot.initrd.extraUtilsCommands).
#   * tests/duress.nix    -> wrapped into a `duress-unlock` package so the VM
#                            test exercises this code (tools come from PATH).
#
# Constraints: no absolute store paths, no `local`, no bashisms. Every binary
# (cryptsetup, mke2fs/mkfs.ext4, mkpasswd, mount, umount) is resolved from
# PATH. The passphrase is read from stdin (no trailing newline required) so it
# never lands in argv or the process list. Nothing is written that records
# which branch ran. The only persistent effect of the duress branch is a
# freshly-formatted /persist, which is the deniable outcome.
##############################################################################

# printf '%s' "$passphrase" | duress_unlock_persist <device> <mapper> <duress-slot>
#
# On return, /dev/mapper/<mapper> is open for the normal boot to mount,
# whether the typed passphrase was the real one or the duress one.
duress_unlock_persist() {
  _dev=$1
  _mapper=$2
  _slot=$3
  _pass=$(cat)

  if printf '%s' "$_pass" | cryptsetup open --test-passphrase \
       --key-slot "$_slot" --key-file - "$_dev" >/dev/null 2>&1; then
    # ---- DURESS branch --------------------------------------------------
    # Destroy the LUKS master key (all keyslots). The old ciphertext is
    # instantly and irreversibly unrecoverable even though the passphrase is
    # now known. Then lay down a fresh LUKS2 (same header label) unlocked by
    # the typed passphrase, and an empty ext4 (same fs label).
    cryptsetup luksErase -q "$_dev" >/dev/null 2>&1 || :
    printf '%s' "$_pass" | cryptsetup luksFormat --type luks2 \
      --label persistcrypt -q --key-file - "$_dev" >/dev/null 2>&1
    printf '%s' "$_pass" | cryptsetup open --key-file - "$_dev" "$_mapper" \
      >/dev/null 2>&1
    # Lazy init keeps this near-instant and independent of volume size, so
    # the duress boot is not observably slower than a normal one.
    mkfs.ext4 -F -L persist -E lazy_itable_init=1,lazy_journal_init=1 \
      "/dev/mapper/$_mapper" >/dev/null 2>&1

    # Seed the login hash from the typed passphrase so the decoy logs in
    # with the password just entered. Everything else (age identity, dir
    # skeleton) is filled in by the persistProvision activation script once
    # /persist is mounted.
    _mnt="/duress-seed.$$"
    mkdir -p "$_mnt"
    if mount -t ext4 "/dev/mapper/$_mapper" "$_mnt" >/dev/null 2>&1; then
      _hash=$(printf '%s' "$_pass" | mkpasswd -m sha-512 -s 2>/dev/null || :)
      if [ -n "$_hash" ]; then
        mkdir -p "$_mnt/secrets" "$_mnt/ws-secrets"
        chmod 0700 "$_mnt/secrets"
        chmod 0755 "$_mnt/ws-secrets"
        printf '%s\n' "$_hash" > "$_mnt/secrets/anon.passwd"
        chmod 0400 "$_mnt/secrets/anon.passwd"
        printf '%s\n' "$_hash" > "$_mnt/ws-secrets/user.passwd"
        chmod 0644 "$_mnt/ws-secrets/user.passwd"
      fi
      _hash=
      sync
      umount "$_mnt" >/dev/null 2>&1 || :
    fi
    rmdir "$_mnt" 2>/dev/null || :
  else
    # ---- normal branch: open with the real passphrase -------------------
    printf '%s' "$_pass" | cryptsetup open --key-file - "$_dev" "$_mapper" \
      >/dev/null 2>&1
  fi

  # Scrub the plaintext from the shell.
  _pass=
  unset _pass 2>/dev/null || :
  return 0
}
