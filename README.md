# Quilt

This is a POC project. Currently only build on windows with VS 2017.

## Prepare
1. Clone project with all sub-modules.
2. Run ```vcbuild vs2017 x86 debug nobuild``` inside ./libuv/
3. Open solution in vs2017, update mbedtls to Windows SDK 10.0.16299.0 and toolset v141.
4. Build the solution.

## Run
1. Add ```127.0.0.1 www.noisyfox.io``` to your hosts file.
2. Run ```QuiltServer.exe```.
3. Run ```Quilt.exe``` and see the output in ```QuiltServer```.
4. Use chrome or any other web browser to visit ```https://www.noisyfox.io``` and see the output in ```QuiltServer```.
5. I bet you could tell the difference.
