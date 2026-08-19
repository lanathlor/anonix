##############################################################################
# Dev + offensive-security toolkit for the workstation microVM.
#
# Authorized-pentest/CTF/research tooling, installed only in the isolated
# workstation. Tools live in the read-only shared store; projects and loot live
# in the persistent /home.
#
# Tor constraints (these affect tool selection):
#   * Only TCP connect() traverses Tor. No raw sockets: no SYN/UDP/ACK scans,
#     no ICMP. Use `nmap -sT -Pn -n`; expect it slow and possibly blocked by
#     the target (shared Tor exit).
#   * UDP is dropped at the gateway (except DNS via Tor's DNSPort). Tools that
#     emit their own UDP (masscan, raw DNS brute) will fail silently. Left out.
#   * No inbound from the clearnet: catching a reverse shell from an arbitrary
#     host is not possible. Use a Tor onion service as the listener, or a bind
#     shell on a Tor-reachable target.
#   * Everything exits from a Tor exit IP. Only test targets you are authorized
#     to test; the exit is shared.
#
# This closure is large (metasploit, seclists). To build a lean image:
#   anon.workstation.toolkit.enable = false;
##############################################################################
{ config, lib, pkgs, ... }:

let
  cfg = config.anon.workstation.toolkit;

  # Python with the security libraries that are painful to obtain via pip.
  pythonEnv = pkgs.python3.withPackages (ps: with ps; [
    pip virtualenv requests
    pwntools   # CTF / exploit-development framework
    impacket   # SMB / MSRPC / Active Directory network protocols
    scapy      # packet crafting/parsing (crafting needs raw sockets ⇒ parse-only over Tor)
  ]);
in {
  options.anon.workstation.toolkit.enable =
    lib.mkEnableOption "the dev + recon/exploit toolkit in the workstation microVM" // {
      default = true;
    };

  config = lib.mkIf cfg.enable {
    environment.systemPackages = with pkgs; [
      # ---- language toolchains + build ----
      # pipx 1.8.0's test suite is incompatible with the newer `packaging`
      # library at this nixpkgs pin (spec rendering: "name@ url" vs
      # "name @ url"), so Hydra never cached it and a from-source build dies
      # in the check phase. The tool itself works; skip its tests until the
      # pin moves past the upstream fix.
      pythonEnv uv (pipx.overridePythonAttrs (_: { doCheck = false; }))
      nodejs_22 pnpm yarn
      go gopls
      gcc gnumake pkg-config binutils nasm

      # ---- AI coding agents ----
      opencode        # needs an LLM API endpoint reached over Tor (provider may block Tor exits)
      aider-chat      # coding agent; point at a local (e.g. Ollama) endpoint to avoid the Tor-exit block

      # ---- route arbitrary tools through Tor's SOCKS ----
      proxychains-ng

      # ---- recon: DNS / subdomains / web ----
      nmap whois dnsutils
      amass subfinder dnsx
      httpx nuclei
      ffuf gobuster feroxbuster dirb wfuzz
      nikto whatweb wafw00f wpscan
      katana gau waybackurls
      theharvester recon-ng
      seclists        # wordlists (LARGE: the biggest single contributor to image size)

      # ---- exploitation ----
      metasploit sqlmap thc-hydra netexec
      john            # john the ripper (CPU cracker)
      exploitdb       # `searchsploit`
      # hashcat REMOVED 2026-08-17: v7.1.2 has three unfixed Critical buffer
      # overflows (CVE-2026-42482/42483/42484) triggered by crafted rule and
      # PKZIP-hash files — exactly the untrusted input a cracker is pointed at.
      # No patched release exists upstream. Restore this line once nixpkgs
      # ships a fixed hashcat. john covers CPU cracking meanwhile.

      # ---- reversing / analysis / net utils ----
      gdb radare2 binwalk ltrace strace
      socat netcat-gnu tcpdump termshark
      httpie jq
    ];
  };
}
