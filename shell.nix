{ pkgs ? import <nixpkgs> { } }:

pkgs.mkShell {
  packages = with pkgs; [
    nodejs_24

    # Linux sandbox runtime dependencies
    bubblewrap
    socat
    ripgrep
  ];
}
