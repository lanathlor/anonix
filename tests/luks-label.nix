##############################################################################
# Regression guard for the existing-install probe (luks_label in flake.nix),
# which install-anon and update-anon use to spot an anon install by its
# 'persistcrypt' LUKS2 label.
#
# The probe was once `cryptsetup luksDumpLabel`, which is not a cryptsetup
# action; the call site swallowed the error, so it returned the empty string
# on every device and neither script ever found an install.
#
# cryptsetup works on a plain file, so this needs no VM, loop device or root.
#
# Build: `nix build .#checks.x86_64-linux.luks-label-probe -L`.
##############################################################################
{ system, nixpkgs, luksLabel }:

let
  pkgs = nixpkgs.legacyPackages.${system};
in
pkgs.runCommand "luks-label-probe"
  {
    nativeBuildInputs = with pkgs; [ cryptsetup gnused coreutils ];
    inherit luksLabel;
  } ''
  set -euo pipefail
  ${luksLabel}

  # Fast KDF: this is a throwaway header, not a security boundary.
  fmt() {
    truncate -s 32M "$1"
    printf 'x' | cryptsetup -q luksFormat "$1" --key-file - \
      --pbkdf pbkdf2 --pbkdf-force-iterations 1000 "''${@:2}"
  }

  fmt labelled.img --label persistcrypt
  fmt unlabelled.img
  truncate -s 1M notluks.img

  fail=0
  check() { # check <what> <expected> <actual>
    if [ "$2" = "$3" ]; then
      printf '  PASS  %s\n' "$1"
    else
      printf '  FAIL  %s (expected [%s], got [%s])\n' "$1" "$2" "$3" >&2
      fail=1
    fi
  }

  check "reads the LUKS2 label of a labelled container" \
        persistcrypt "$(luks_label labelled.img)"
  check "empty for a LUKS container with no label" \
        "" "$(luks_label unlabelled.img)"
  check "empty for a non-LUKS device" \
        "" "$(luks_label notluks.img)"

  # Its absence is what makes the hand-rolled parse necessary. If cryptsetup
  # ever grows the action, this fires and luks_label can be simplified.
  if cryptsetup luksDumpLabel labelled.img >/dev/null 2>&1; then
    printf '  FAIL  cryptsetup still has no luksDumpLabel action\n' >&2
    printf '\ncryptsetup grew a luksDumpLabel action; luks_label can be simplified.\n' >&2
    fail=1
  else
    printf '  PASS  cryptsetup still has no luksDumpLabel action (parse needed)\n'
  fi

  # A non-LUKS device is the common case and must not abort a `set -e` caller.
  ( set -e; luks_label notluks.img >/dev/null; ) \
    && printf '  PASS  non-LUKS device does not trip set -e in the caller\n' \
    || { printf '  FAIL  non-LUKS device aborts under set -e\n' >&2; fail=1; }

  [ "$fail" -eq 0 ] || { printf '\nLUKS LABEL PROBE FAILED.\n' >&2; exit 1; }
  touch "$out"
''
