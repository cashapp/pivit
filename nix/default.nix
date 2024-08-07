{ pkgs ? import <nixpkgs> {} }:
with pkgs;
let
  # A cgo dependency (go-piv) needs either pcsclite (Linux) or PCSC (macOS)
  pcsc = lib.optional stdenv.isLinux (lib.getDev pcsclite)
         ++ lib.optional stdenv.isDarwin (darwin.apple_sdk.frameworks.PCSC);
in buildGoModule rec {
  pname = "pivit";
  version = "0.6.0";

  src = ./..;

  # This needs to be updated whenever go.sum changes
  vendorHash = "sha256-tgONzmRkJoFLA2PvXbum5BdPCtlyA4s6jNIjpmyUjvc=";

  buildInputs = pcsc;

  nativeBuildInputs = lib.optionals stdenv.isLinux [ pkg-config ];

  meta = with lib; {
    description = "Utility for git signing using YubiKey PIV certificates";
    homepage = "https://github.com/cashapp/pivit";
    license = licenses.mit;
    maintainers = with maintainers; [ ddz yoavamit ];
  };
}
