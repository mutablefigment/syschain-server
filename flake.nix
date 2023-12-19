{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    
    flake-utils.lib.eachDefaultSystem
      (system:
        let
          overlays = [ ];
          pkgs = import nixpkgs {
            inherit system overlays;
          };
            dub2nix-src = fetchTarball {
                url = "https://github.com/lionello/dub2nix/archive/master.tar.gz";
                sha256 = "sha256:1gvxlgmr2gls8jmm7bvbqyy8k70hpph2qhzfh04260pil19ki5r1";
          };
          dub2nix = (import dub2nix-src) { inherit pkgs; };
        in
        with pkgs;
        {
          devShells.default = mkShell {
            buildInputs = [ dub2nix dub dmd dtools openssl gdb gf meson ninja ];
          };

          packages.syschain-server =
            with import ./mkDub.nix { inherit pkgs; };
            mkDubDerivation {
              src = ./.;
              version = "0.1.0"; # optional
              buildInputs = [ openssl git dub ];
            };
        }
      );
}