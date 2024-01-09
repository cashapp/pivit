# Building Pivit with Nix

## Development Environment using `nix-shell`

The [`shell.nix`](shell.nix) derivation can be used with `nix-shell`
to enter into a development environment that includes all of the
dependencies needed to build and test `pivit`:

```
% nix-shell
these 103 paths will be fetched (174.05 MiB download, 1109.32 MiB unpacked):
  /nix/store/zcri58i63hrkm4iz3k5isxj52yx76qck-Platforms
  /nix/store/rvr43gjzdpbcz9jvq0kxdcmr3ijnq0zg-SDKs
  /nix/store/by8f4kgi39hxihikxy3g5rq9lnjxl1ji-Toolchains
[...]

[nix-shell:~/src/github.com/cashapp/pivit]$ make
CGO_ENABLED=1 go build ./cmd/pivit
go: downloading github.com/github/smimesign v0.2.0
go: downloading github.com/pkg/errors v0.9.1
go: downloading github.com/pborman/getopt/v2 v2.1.0
go: downloading github.com/go-piv/piv-go v1.11.0
go: downloading github.com/certifi/gocertifi v0.0.0-20210507211836-431795d63e8d
go: downloading golang.org/x/crypto v0.17.0
go: downloading github.com/manifoldco/promptui v0.9.0
go: downloading github.com/chzyer/readline v1.5.1

[nix-shell:~/src/github.com/cashapp/pivit]$
```

## Building with `nix-build`

The [`default.nix`](default.nix) derivation can be used to build pivit
using `nix-build`:

```
% nix-build
this derivation will be built:
  /nix/store/v53x1i0bh9ldrd6jrv6m9q0rh73vbpah-pivit-0.6.0.drv
building '/nix/store/v53x1i0bh9ldrd6jrv6m9q0rh73vbpah-pivit-0.6.0.drv'...
Running phase: unpackPhase
unpacking source archive /nix/store/327m9aw6w4nji2gz9jcmw79p0rqchn0s-pivit
source root is pivit
Running phase: patchPhase
Running phase: updateAutotoolsGnuConfigScriptsPhase
Running phase: configurePhase
Running phase: buildPhase
Building subPackage ./cmd/pivit
Building subPackage ./cmd/pivit/status
Building subPackage ./cmd/pivit/utils
Building subPackage ./cmd/pivit/yubikey
Running phase: checkPhase
Running phase: installPhase
Running phase: fixupPhase
checking for references to /private/tmp/nix-build-pivit-0.6.0.drv-0/ in /nix/store/wfbdk46ywh5vza557jxdsxxcmbxfk5lg-pivit-0.6.0...
patching script interpreter paths in /nix/store/wfbdk46ywh5vza557jxdsxxcmbxfk5lg-pivit-0.6.0
stripping (with command strip and flags -S) in  /nix/store/wfbdk46ywh5vza557jxdsxxcmbxfk5lg-pivit-0.6.0/bin
/nix/store/wfbdk46ywh5vza557jxdsxxcmbxfk5lg-pivit-0.6.0
```

If the build was successful, it will create a symlink `result` that points to
the output path in the nix store. You can run `pivit` from its `bin/`
directory:

```
% ./result/bin/pivit
specify --help, --sign, --verify, --import, --generate, --reset or --print
```

### Updating `vendorHash`

When the contents of `go.sum` change, the nix build will also fail due to a
hash mismatch:

```
error: hash mismatch in fixed-output derivation '/nix/store/alrrfv23kdgm99bfn1vqp2vr5n522xga-pivit-0.6.0-go-modules.drv':
         specified: sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
            got:    sha256-S4Su9y10SjimxGAm/3k3tgritZ44ZB2N4CdwQEcGvQc=
error: 1 dependencies of derivation '/nix/store/cmvdxq4v7lwmcgpqpwjwnc3dngprqilj-pivit-0.6.0.drv' failed to build
```

When this occurs, the current go modules derivation hash (shown for "got")
needs to be set as `vendorHash` in [`default.nix`](default.nix).
