{ pkgs ? import <nixpkgs> { } }:

let
  # sandbox-runtime's build:seccomp links its BPF generator statically, while
  # nixpkgs' regular libseccomp build only installs the shared library.
  libseccompStatic = pkgs.libseccomp.overrideAttrs (_: {
    dontDisableStatic = true;
    doCheck = false;
  });
in
pkgs.mkShell {
  packages = with pkgs; [
    # Project and sandbox-runtime builds
    nodejs_24
    bun
    gcc
    binutils
    glibc.static
    libseccompStatic.dev
    libseccompStatic.lib

    # Linux sandbox runtime dependencies
    bubblewrap
    socat
    ripgrep
  ];
}
