let
  # Use nixpkgs revision from ../flake.lock
  lock = builtins.fromJSON (builtins.readFile ../flake.lock);
  rev = lock.nodes.nixpkgs.locked.rev;
  narHash = lock.nodes.nixpkgs.locked.narHash;  
in
  import (fetchTarball {
    url = "https://github.com/NixOS/nixpkgs/archive/${rev}.tar.gz";
    sha256 = narHash;
})
