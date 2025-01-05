with import <nixpkgs> { };

pkgs.mkShell rec {
  # name = "vp";

  venvDir = "./.venv";
  buildInputs = [
    python312Packages.python
    python312Packages.venvShellHook
    python312Packages.jupyterlab
    python312Packages.matplotlib
    python312Packages.cryptography
  ];

  postVenvCreation = ''
    unset SOURCE_DATE_EPOCH
    # pip install -r requirements.txt
    '';

  postShellHook = ''
    # allow pip to install wheels
    unset SOURCE_DATE_EPOCH
    exec zsh
  '';
}
