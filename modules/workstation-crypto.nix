##############################################################################
# Crypto wallets for the workstation microVM.
#
# Installed only in the isolated, fully-torified workstation guest. All TCP is
# transparently forced through the gateway's Tor, including .onion (resolved
# automatically via AutomapHostsOnResolve). Critical: do not let the wallet
# app launch its own Tor (that is Tor-over-Tor). Set each app's proxy to
# "None"; the gateway handles it. See docs/workstation.md for the exact in-app toggles.
#
# Requires the KDE desktop (anon.workstation.desktop.enable, on by default).
#
#   * Feather: lightweight, Tor-native Monero wallet with built-in onion nodes.
#   * Sparrow: privacy-focused Bitcoin wallet; connect to your own node or an
#     onion Electrum server.
#
# Key persistence: the workstation is amnesic (root on tmpfs, wiped every
# boot); only /home survives. Both wallets store key files under $HOME by
# default (/home/user), which is the persistent encrypted volume on the host's
# LUKS /persist. Keys survive reboots; the tmpfs wipe never touches them.
#   Default locations:
#     Feather:  ~/Monero/wallets  (config in ~/.config/feather)
#     Sparrow:  ~/.sparrow/wallets
# These directories are pre-created with 0700 perms to pin keys to /home and
# to correct Feather's default mkpath (which would leave the dir at 0755).
# Always set a strong wallet password; that is what protects keys if the /home
# image is read.
#
# Warning: a wallet saved outside /home (/tmp, /root, etc.) is destroyed on
# the next reboot. Back up your seed phrase offline regardless.
#
# Bisq 2 is not included: it must run its own Tor co-located with itself
# (hardcodes the control channel to 127.0.0.1) and cannot use the gateway's
# Tor, so it would only work as Tor-over-Tor.
#
# To build without the wallets: anon.workstation.crypto.enable = false;
##############################################################################
{ config, lib, pkgs, ... }:

let
  cfg = config.anon.workstation.crypto;
in {
  options.anon.workstation.crypto.enable =
    lib.mkEnableOption "Monero (Feather) + Bitcoin (Sparrow) wallets in the workstation microVM" // {
      default = true;
    };

  config = lib.mkIf cfg.enable {
    environment.systemPackages = [ pkgs.feather pkgs.sparrow ];

    # Pre-create wallet key directories on the persistent /home volume with
    # 0700 perms. Creating them before first run guarantees keys land on the
    # persistent volume, never on the tmpfs root. Owner user:users matches
    # modules/workstation.nix. The home is created by activation before
    # systemd-tmpfiles runs, so these only add leaf dirs under an existing home.
    systemd.tmpfiles.rules = [
      "d /home/user/Monero 0700 user users - -"
      "d /home/user/Monero/wallets 0700 user users - -"
      "d /home/user/.sparrow 0700 user users - -"
      "d /home/user/.sparrow/wallets 0700 user users - -"
    ];
  };
}
