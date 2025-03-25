{
  description = "Sign and verify data using x509 certificates on Yubikeys";

  # Use latest stable nixpkgs repository
  inputs.nixpkgs.url = "nixpkgs/nixos-24.11";

  outputs = { self, nixpkgs }:
    let
      supportedSystems = [
        "x86_64-linux" "x86_64-darwin" "aarch64-linux" "aarch64-darwin"
      ];

      # Helper function to generate an attrset
      # '{ x86_64-linux = f "x86_64-linux"; ... }'.
      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;

      # Nixpkgs instantiated for all supported system types.
      nixpkgsFor = forAllSystems (
        system: import nixpkgs { inherit system; }
      );

    in
    {
      devShells = forAllSystems (system:
        let
          pkgs = nixpkgsFor.${system};
        in
        {
          # Use mkShell derivation from shell.nix
          default = import ./nix/shell.nix { inherit pkgs; };
        });

      packages = forAllSystems (system:
        let
          pkgs = nixpkgsFor.${system};
        in
        {
          # Use buildGoModule derivation from default.nix
          default = import ./nix/default.nix { inherit pkgs; };
        });
    };
}
