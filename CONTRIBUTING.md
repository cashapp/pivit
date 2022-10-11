Contributing
============

If you would like to contribute code to Pivit you can do so through GitHub by
forking the repository and sending a pull request.

When submitting code, please make every effort to follow existing conventions
and style in order to keep the code as readable as possible. Please also make
sure your code compiles by running `make build`.

Before your code can be accepted into the project you must also sign the
[Individual Contributor License Agreement (CLA)][1].

Verified commits and releases
=============================

Pivit is a command line tool that deals with security, and as such, we require that 
every code change in it will be [signed as well][2].

These signatures help us attest that code changes were made by real people, and provide
and additional layer of security.

In addition to only allowing verified commits, we also require signing every Pivit release tag
with key that matches one of the allowed signers listed in `config/allowed_release_signers`.  
Release tags are verified during the release workflow in `.github/workflows/release.yaml`.

[1]: https://spreadsheets.google.com/spreadsheet/viewform?formkey=dDViT2xzUHAwRkI3X3k5Z0lQM091OGc6MQ&ndplr=1
[2]: https://docs.github.com/en/authentication/managing-commit-signature-verification/signing-commits