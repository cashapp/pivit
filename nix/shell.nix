{ pkgs ? import <nixpkgs> {} }:
with pkgs;
let
  # A cgo dependency (go-piv) needs either pcsclite (Linux) or PCSC (macOS)
  pcsc = lib.optional stdenv.isLinux (lib.getDev pcsclite)
         ++ lib.optional stdenv.isDarwin (darwin.apple_sdk.frameworks.PCSC);
in mkShell {
  buildInputs = [
    file
    gnumake
    go
    pcsc
  ] ++ lib.optional stdenv.isLinux pkg-config;
}
