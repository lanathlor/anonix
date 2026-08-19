{
  description =
    "anonix — maximal-anonymity NixOS: mandatory transparent Tor gateway routed over a WireGuard VPN tunnel (any provider), with root-on-tmpfs impermanence. Killswitch by construction: if either Tor or the VPN is down, no packet leaves the machine.";

  inputs = {
    # Pin a stable channel. Re-audit the firewall after upgrades.
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";

    # Secondary pin used only to pull individual "worst offender" packages
    # (via pkgs-unstable.<name>) that the stable channel ships with a large
    # backlog of open CVEs — e.g. vim. The base system stays on stable; this
    # is not a channel switch. Keep the set of packages taken from here small
    # and reviewed (see hosts/anon and the installer in this flake).
    nixpkgs-unstable.url = "github:NixOS/nixpkgs/nixos-unstable";

    # Erase-your-darlings style impermanence.
    impermanence.url = "github:nix-community/impermanence";

    # age-encrypted secrets, committed to git in encrypted form.
    agenix.url = "github:ryantm/agenix";
    agenix.inputs.nixpkgs.follows = "nixpkgs";

    # Secure Boot: sign the boot chain with our own keys (lanzaboote).
    # Pinned: managed autoGenerate/autoEnroll keys landed in 1.0.
    lanzaboote.url = "github:nix-community/lanzaboote/v1.1.0";
    lanzaboote.inputs.nixpkgs.follows = "nixpkgs";

    # microVMs for the Whonix-style Gateway/Workstation isolation split.
    microvm.url = "github:microvm-nix/microvm.nix";
    microvm.inputs.nixpkgs.follows = "nixpkgs";

    # Declarative disk partitioning + the offline installer's format step.
    disko.url = "github:nix-community/disko";
    disko.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = { self, nixpkgs, nixpkgs-unstable, impermanence, agenix, lanzaboote, microvm, disko, ... }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};

      # Cherry-picked packages from nixos-unstable while the base system stays
      # on the stable pin. Referenced as pkgs-unstable.<name> and passed to
      # modules via specialArgs. Only for leaf packages the config installs
      # directly; transitive libraries would need an overlay instead.
      pkgs-unstable = import nixpkgs-unstable {
        inherit system;
        config.allowUnfree = true;
      };

      anon = self.nixosConfigurations.anon;

      # CI/demo variant of the anon system: dummy VPN values in place of the
      # real endpoint and peer key, so the closure (and the installer ISO that
      # bakes it) builds without any secrets. The tunnel can never come up
      # (dummy peer, no private key), so the killswitch keeps such a system
      # offline: fine for pipelines and demos, useless for deployment. Real
      # installs build .#installer-iso with the real values filled in.
      anonCi = anon.extendModules {
        modules = [{
          anon.vpn.endpointIp = nixpkgs.lib.mkForce "192.0.2.1"; # TEST-NET-1
          anon.vpn.serverPublicKey =
            nixpkgs.lib.mkForce "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        }];
      };

      # Offline installer ISO for a given evaluated anon system (the real one,
      # or anonCi above). Bakes the exact system closure and the disko format
      # script into the ISO so the install runs with no network and no flake
      # evaluation on the target. Writes secrets onto the encrypted /persist.
      # Target disk is whatever modules/disk.nix points at.
      mkInstaller = { anon, isoBaseName }:
        let
          # Install target disk from modules/disk.nix; scripts use it to detect
          # an existing install and find the LUKS volumes.
          targetDevice = anon.config.disko.devices.disk.main.device;

          installAnon = pkgs.writeShellApplication {
            name = "install-anon";
            runtimeInputs = with pkgs; [ coreutils util-linux cryptsetup nixos-install-tools mkpasswd ];
            text = ''
              if [ "$#" -lt 1 ]; then
                cat >&2 <<'EOF'
              usage: install-anon <age-identity-file> [lan-bypass-ip ...]

                Wipes the disk configured in modules/disk.nix and installs the anon
                system offline from this USB, then writes the age identity onto the
                encrypted /persist so it boots working. You are prompted to set
                the gateway and workstation login passwords; no pre-made hash file.
                Put the age identity on the USB (or another drive) beforehand.

                Any extra args are LAN-bypass IPs (hosts the workstation may reach
                directly, bypassing Tor, e.g. a local LLM). They are written to
                /persist/lan-bypass; leave none for a fully-torified box. You can
                also edit that file later on the running system (no rebuild). E.g.:
                  install-anon age-identity 10.0.0.2
              EOF
                exit 1
              fi
              identity="$1"; shift 1
              test -f "$identity" || { echo "no age identity file: $identity" >&2; exit 1; }

              # Prompt (twice, confirmed) for a login password and print its sha-512
              # hash on stdout. Prompts go to stderr so $(...) captures only the hash.
              prompt_pw() {
                local label="$1" p1 p2
                while :; do
                  printf 'Set password for %s: ' "$label" >&2
                  read -rs p1; printf '\n' >&2
                  printf 'Confirm password for %s: ' "$label" >&2
                  read -rs p2; printf '\n' >&2
                  if [ -z "$p1" ]; then printf 'Empty password; try again.\n' >&2; continue; fi
                  if [ "$p1" != "$p2" ]; then printf 'Passwords do not match; try again.\n' >&2; continue; fi
                  break
                done
                printf '%s' "$p1" | mkpasswd -m sha-512 -s
              }

              # Warn if the target already holds an anon install: this command wipes
              # it. update-anon keeps /persist instead.
              if [ -b "${targetDevice}" ]; then
                while IFS= read -r part; do
                  if [ "$(cryptsetup luksDumpLabel "$part" 2>/dev/null || true)" = persistcrypt ]; then
                    echo "WARNING: $part looks like an existing anon /persist (encrypted)." >&2
                    echo "install-anon will destroy it: secrets, Secure Boot keys and the" >&2
                    echo "workstation /home included. To keep /persist and just apply this" >&2
                    echo "USB's system, abort now and run:  update-anon" >&2
                    break
                  fi
                done < <(lsblk -rno PATH "${targetDevice}" 2>/dev/null)
              fi

              echo "This erases the target disk (see modules/disk.nix) and installs anon."
              printf 'Type ERASE to continue: '; read -r ans
              [ "$ans" = ERASE ] || { echo "aborted."; exit 1; }

              # Set passwords before the destructive wipe so we never erase and then
              # fail on an empty password. Hashed here so no plaintext reaches the system.
              gw_hash=$(prompt_pw "the gateway login (user 'anon')")
              ws_hash=$(prompt_pw "the workstation login (user 'user')")

              # 1. Wipe, partition, LUKS (prompts for passphrase), format, mount at /mnt.
              ${anon.config.system.build.diskoScript}
              ${nixpkgs.lib.optionalString anon.config.anon.duress.enable ''
              # 1b. Enrol the duress passphrase into LUKS keyslot ${toString anon.config.anon.duress.keySlot}
              #     on both volumes. Typing it at boot crypto-erases /persist and boots
              #     a clean decoy (see modules/duress.nix). cryptsetup prompts per
              #     volume: enter your real passphrase to authorise, then the duress
              #     passphrase twice. Pick something distinct; it is never stored.
              echo
              echo ">>> Set the duress passphrase (slot ${toString anon.config.anon.duress.keySlot} on both volumes)."
              echo ">>> For each volume: enter your real passphrase to authorise, then"
              echo ">>> the duress passphrase twice. It wipes /persist when typed at boot."
              for _dev in /dev/disk/by-partlabel/disk-main-nix /dev/disk/by-partlabel/disk-main-persist; do
                cryptsetup luksAddKey --key-slot ${toString anon.config.anon.duress.keySlot} "$_dev"
              done
              ''}
              # 2. Install the baked closure. No eval, no network.
              nixos-install --system ${anon.config.system.build.toplevel} \
                --root /mnt --no-root-passwd --no-channel-copy

              # 3. Drop the secrets onto the (mounted) encrypted /persist.
              install -d -m 0700 /mnt/persist/secrets \
                                 /mnt/persist/secureboot \
                                 /mnt/persist/microvms/workstation
              install -m 0400 "$identity" /mnt/persist/secrets/age-identity
              # Gateway login hash (root-only).
              printf '%s\n' "$gw_hash" > /mnt/persist/secrets/anon.passwd
              chmod 0400 /mnt/persist/secrets/anon.passwd
              # Workstation login hash. 0644 because the guest reads it over a 9p
              # share (QEMU may run as the unprivileged microvm user). Lives only on
              # encrypted /persist; never enters the Nix store. See workstation.nix.
              install -d -m 0755 /mnt/persist/ws-secrets
              printf '%s\n' "$ws_hash" > /mnt/persist/ws-secrets/user.passwd
              chmod 0644 /mnt/persist/ws-secrets/user.passwd

              # 4. Optional LAN-bypass list from remaining args.
              if [ "$#" -gt 0 ]; then
                printf '%s\n' "$@" > /mnt/persist/lan-bypass
                chmod 0644 /mnt/persist/lan-bypass
                echo "LAN bypass (direct, non-Tor) configured for: $*"
              fi
              sync
              echo "Done. Remove the USB and reboot."
              echo "First boot: enter the LUKS passphrase; then set UEFI Setup Mode"
              echo "to let Secure Boot enroll the auto-generated keys (see README)."
            '';
          };

          # Non-destructive update. Applies this USB's baked closure to an
          # existing anon install, keeping /persist. Unlocks and mounts the
          # existing encrypted volumes, installs the new system over /nix, and
          # re-signs the bootloader using the Secure Boot keys already on
          # /persist. Rebuild a newer ISO, dd it, boot the target, and run this.
          updateAnon = pkgs.writeShellApplication {
            name = "update-anon";
            runtimeInputs = with pkgs; [ coreutils util-linux cryptsetup nixos-install-tools ];
            text = ''
              # usage: update-anon [lan-bypass-ip ...]
              #   With no args the existing /persist/lan-bypass is left unchanged;
              #   any args REPLACE it (same meaning as for install-anon).
              device=${targetDevice}

              # Detect an existing anon install by its LUKS2 /persist header label.
              found=""
              if [ -b "$device" ]; then
                while IFS= read -r part; do
                  if [ "$(cryptsetup luksDumpLabel "$part" 2>/dev/null || true)" = persistcrypt ]; then
                    found="$part"; break
                  fi
                done < <(lsblk -rno PATH "$device" 2>/dev/null)
              fi
              if [ -z "$found" ]; then
                echo "No existing anon install (a 'persistcrypt' LUKS volume) found on $device." >&2
                echo "Nothing to update. For a fresh install use: install-anon <age-identity>" >&2
                exit 1
              fi

              echo "Existing anon install detected on $device ($found)."
              echo "This applies this USB's system to it and keeps /persist untouched"
              echo "(secrets, Secure Boot keys, Tor guards, workstation /home, lan-bypass)."
              echo "No disk is wiped. You will be asked for the existing LUKS passphrase."
              printf 'Proceed with the update? [y/N]: '; read -r ans
              case "$ans" in y|Y|yes|YES) ;; *) echo "aborted."; exit 1;; esac

              # 1. Unlock and mount the existing encrypted volumes at /mnt (no format).
              #    disko's mountScript emits the LUKS open for only one of the two
              #    containers (caught by tests/update.nix), so open both explicitly
              #    first. mountScript re-checks cryptsetup status before opening, so
              #    this stays correct even if disko is fixed later.
              cryptsetup open /dev/disk/by-partlabel/disk-main-nix nix
              cryptsetup open /dev/disk/by-partlabel/disk-main-persist persist
              ${anon.config.system.build.mountScript}

              # 2. Install the baked closure over the existing store. /nix already
              #    holds most paths; this adds the new generation, points the profile
              #    at it, and reinstalls the signed bootloader. /persist is read for
              #    the Secure Boot keys but never rewritten. No eval, no network.
              nixos-install --system ${anon.config.system.build.toplevel} \
                --root /mnt --no-root-passwd --no-channel-copy

              # 3. Optional: replace the LAN-bypass list. With no args it is unchanged.
              if [ "$#" -gt 0 ]; then
                printf '%s\n' "$@" > /mnt/persist/lan-bypass
                chmod 0644 /mnt/persist/lan-bypass
                echo "LAN bypass (direct, non-Tor) updated to: $*"
              fi
              sync
              echo "Update applied. Remove the USB and reboot into the new generation."
              echo "(Roll back later by picking an older generation in the boot menu.)"
            '';
          };
        in
        nixpkgs.lib.nixosSystem {
          inherit system;
          modules = [
            ({ modulesPath, lib, pkgs, ... }: {
              imports = [ (modulesPath + "/installer/cd-dvd/installation-cd-minimal.nix") ];
              environment.systemPackages = [ installAnon updateAnon pkgs.mkpasswd pkgs.age pkgs-unstable.vim ];
              systemd.tmpfiles.rules = [ "C /root/README.md 0644 root root - ${installReadme}" ];
              services.getty.helpLine = lib.mkForce ''

                >>> Offline installer. Run:  cat README.md
              '';
              # The ISO builder derives the output file name from
              # image.baseName ("<baseName>.iso"); image.fileName is NOT
              # consulted (nixpkgs iso-image.nix hardcodes the former).
              image.baseName = lib.mkForce isoBaseName;
              networking.hostName = "anon-installer";
              # Silence the forceImportRoot warning (ZFS pulled in by the base profile).
              boot.zfs.forceImportRoot = false;
              # No network used; flakes enabled for convenience in a shell.
              nix.settings.experimental-features = [ "nix-command" "flakes" ];
              services.getty.autologinUser = lib.mkForce "root";
            })
          ];
        };

      # Cheat sheet placed at /root/README.md on the live ISO.
      installReadme = pkgs.writeText "README.md" ''
        ================================================================
         anonix OFFLINE INSTALLER  (anon: Tor-over-VPN + isolated WS)
        ================================================================
        This USB installs the whole system onto this machine. Everything is baked
        in; no network is used. It wipes the disk configured at build time.

        ---- 1. Check the target disk --------------------------------------------
          lsblk
        The installer erases the disk set in modules/disk.nix. Be sure it's right.

        ---- 2. Get your two secrets onto this box -------------------------------
        (a) age identity: the private key matching the public key you built this
            ISO with. Copy your `age-identity` file here, e.g. from a USB stick:
              mkdir -p /mnt/usb && mount /dev/sdX1 /mnt/usb
              cp /mnt/usb/age-identity /root/age-identity
            Without it the box boots but cannot decrypt the VPN key and stays offline.
            (It must be the same identity used at build time; a fresh one won't
             match the baked, encrypted VPN key.)

        (b) nothing to prepare for passwords: the installer prompts you in
            step 3 to set the gateway and workstation login passwords (it hashes
            them for you and writes them onto the encrypted /persist).

        ---- 3. Install ----------------------------------------------------------
          install-anon /root/age-identity
        Reach a LAN host directly (bypassing Tor), e.g. a local LLM: add its IP:
          install-anon /root/age-identity 10.0.0.2
        You type ERASE to confirm, set the gateway and workstation login
        passwords when prompted, then choose a LUKS passphrase (remember it).

        ---- 4. Reboot -----------------------------------------------------------
          - Remove the USB and power on. Enter the LUKS passphrase at boot.
          - Secure Boot: reboot into UEFI setup, enable "Setup Mode" (clear keys),
            boot back in (keys auto-enroll), then turn Secure Boot on.

        ---- Duress passphrase (if enabled) --------------------------------------
        During install you also set a second, duress passphrase. At the boot
        prompt it behaves like a normal unlock, except it first crypto-erases
        /persist (instantly and irreversibly) and boots a clean, working but
        empty decoy that logs in with that very passphrase. Give it under
        coercion.
          - Typing it destroys all real data, irreversibly. Don't confuse it
            with your real passphrase.
          - It is incompatible with TPM2 auto-unlock, so the disk always prompts
            at boot (required for duress to work).
          - It only wipes when typed at boot. Typing it into install-anon or
            update-anon on the USB does not wipe (trusted context).
          - The header shows two keyslots, so an adversary imaging the powered-off
            disk can infer a second key exists (looks like a backup key). It is
            deniable to someone watching you boot, not to offline forensics.

        ---- UPDATE an existing box (keep /persist) ------------------------------
        Booted a newer installer USB on a machine that already runs anon? Apply
        this USB's system without wiping: secrets, Secure Boot keys, Tor guards
        and the workstation /home are preserved:
          update-anon                 # detect the install, keep the LAN-bypass list
          update-anon 10.0.0.2        # ... and replace the LAN-bypass list
        It asks for the existing LUKS passphrase, installs offline, and never
        formats. Roll back via an older generation in the boot menu.

        ---- Verify (on the installed system, after first boot) ------------------
          curl https://check.torproject.org/api/ip                  # IsTor: true
          doas wg-quick down wg-tunnel && curl -m5 https://example.com   # must fail

        Tools here: install-anon, update-anon, mkpasswd, age, lsblk, cryptsetup, vim.
        Change the LAN bypass later on the box: edit /persist/lan-bypass.
        ================================================================
      '';
    in {
      nixosConfigurations.anon = nixpkgs.lib.nixosSystem {
        inherit system;
        specialArgs = { inherit pkgs-unstable; };
        modules = [
          impermanence.nixosModules.impermanence
          agenix.nixosModules.default
          lanzaboote.nixosModules.lanzaboote
          microvm.nixosModules.host
          disko.nixosModules.disko
          ./hosts/anon
        ];
      };

      # Live-USB installer image. Build with `nix build .#installer-iso` (or `just iso`).
      # Building it forces the anon closure to build, so fill in the real VPN
      # values and encrypt the key first (the placeholder assertion must pass).
      nixosConfigurations.installer = mkInstaller {
        inherit anon;
        isoBaseName = "anon-installer";
      };

      # Same installer, baking the anonCi dummy-VPN variant, so CI can build and
      # publish an ISO without any secrets. Demo/pipeline artifact only: a
      # system installed from it stays offline (killswitch, no VPN key) until
      # updated from an ISO built with real values.
      nixosConfigurations.installer-ci = mkInstaller {
        anon = anonCi;
        isoBaseName = "anon-installer-ci";
      };

      packages.${system} = {
        # `nix build` builds the system closure. Prefer `just vm` for a bootable
        # QEMU image (applies vmVariant overrides in hosts/anon/default.nix).
        default = anon.config.system.build.toplevel;

        # The offline live-USB installer ISO.
        installer-iso = self.nixosConfigurations.installer.config.system.build.isoImage;

        # The CI/demo ISO (dummy VPN values; see nixosConfigurations.installer-ci).
        installer-iso-ci = self.nixosConfigurations.installer-ci.config.system.build.isoImage;

        # The CI/demo system closure itself (same dummy VPN values). CI builds
        # this for the SBOM + CVE audit; also handy for a full-closure build
        # without secrets.
        anon-ci-system = anonCi.config.system.build.toplevel;

        # `nix run .#agenix -- -e vpn-wg.key.age` (run from the secrets/ dir).
        agenix = agenix.packages.${system}.default;
      };

      # QEMU VM tests (or `just test`). Do not need the VPN values filled in.
      checks.${system} = {
        update-keeps-persist =
          import ./tests/update.nix { inherit system nixpkgs disko; };
        duress-wipes-persist =
          import ./tests/duress.nix { inherit system nixpkgs; };
        gateway-security =
          import ./tests/security.nix { inherit system nixpkgs; };
        anon-security-invariants =
          import ./tests/invariants.nix { inherit system nixpkgs; config = anon.config; };
        no-clearnet-leak =
          import ./tests/no-leak.nix { inherit system nixpkgs; };
        # Regression guards for the workstation return-traffic drop: eval-level
        # ruleset check (no KVM) and end-to-end VM proof (needs KVM).
        workstation-return-ruleset =
          import ./tests/workstation-return-ruleset.nix { inherit system nixpkgs; };
        workstation-return =
          import ./tests/workstation-return.nix { inherit system nixpkgs; };
        # Fail-closed under component failure: kill Tor / kill the VPN (one VM);
        # kill the whole gateway (workstation isolation, separate topology).
        killswitch-egress =
          import ./tests/killswitch-egress.nix { inherit system nixpkgs; };
        killswitch-gateway-down =
          import ./tests/killswitch-gateway-down.nix { inherit system nixpkgs; };
      };

      # Dev shell (`nix develop`). A devShell cannot provide KVM; /dev/kvm is a
      # host kernel feature. The QEMU VM checks need the build host to expose
      # /dev/kvm to the Nix sandbox. The eval-only checks
      # (anon-security-invariants, workstation-return-ruleset) need no KVM.
      devShells.${system}.default = pkgs.mkShellNoCC {
        packages = [
          pkgs.just
          pkgs.qemu_kvm          # run the built VM / VM tests locally
          pkgs.age
          agenix.packages.${system}.default
          pkgs.cryptsetup
          pkgs.mkpasswd
          pkgs.nixfmt-rfc-style
        ];
        shellHook = ''
          if [ -e /dev/kvm ] && [ -w /dev/kvm ]; then
            echo "anonix devShell. KVM: available. QEMU VM checks can boot."
          else
            echo "anonix devShell. KVM: /dev/kvm NOT available/writable here."
            echo "  A devShell cannot provide KVM; it is a HOST feature. To run the"
            echo "  QEMU VM checks (just test / .#checks.*), enable it on THIS machine:"
            echo "    - NixOS: usually automatic on bare metal; ensure the kvm module"
            echo "      loads (boot.kernelModules = [ \"kvm-intel\" ] or \"kvm-amd\"),"
            echo "      your user is in the 'kvm' group, and (in a guest) nested virt"
            echo "      is on. nix.settings.system-features must include \"kvm\"."
            echo "    - Eval-only checks still work: .#checks.*.anon-security-invariants"
            echo "      and .#checks.*.workstation-return-ruleset (no KVM needed)."
          fi
        '';
      };

      formatter.${system} = nixpkgs.legacyPackages.${system}.nixfmt-rfc-style;
    };
}
