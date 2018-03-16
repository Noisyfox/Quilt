# Quilt

This is a POC project. Currently build on windows with VS 2017 & linux with cmake.

## Build on Windows
1. Clone project with all sub-modules.
2. Run ```vcbuild vs2017 x86 debug nobuild``` inside ./libuv/
3. Open solution in vs2017, update mbedtls to Windows SDK 10.0.16299.0 and toolset v141.
4. Build the solution.

## Build on Linux
1. Clone project with all sub-modules.
2. Run ```cmake . && make all``` in project root dir.

## Run
1. Add ```127.0.0.1 www.noisyfox.io``` to your hosts file. Don't forget to remove this line once you've done otherwise you may miss tons of amazing things from my site and you and I will both be sad about that :worried:.
2. Run ```QuiltServer```.
3. Run ```Quilt``` and see the output in ```QuiltServer```.
4. Use chrome or any other web browser to visit [https://www.noisyfox.io:8043](https://www.noisyfox.io:8043) and see the output in ```QuiltServer```.
5. I bet you could tell the difference.
