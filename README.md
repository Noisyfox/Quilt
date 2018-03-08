# Quilt

This is a POC project. Currently only build on windows with VS 2017.

## Prepare
- Clone project with all sub-modules.
- Run ```vcbuild vs2017 x86 debug nobuild``` inside ./libuv/
- Open solution in vs2017, update mbedtls to Windows SDK 10.0.16299.0 and toolset v141.
- Build & run.
