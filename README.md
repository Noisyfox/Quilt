# Quilt

This is a POC project. Currently build on Windows with Visual Studio 2017 & Linux with cmake.

## Build on Windows
### Option 1
1. Clone project with all sub-modules.
2. Run `vcbuild vs2017 x86 debug nobuild` inside ./libuv/
3. Open solution in Visual Studio 2017, update mbedtls to Windows SDK 10.0.16299.0 and toolset v141.
4. Build the solution.

### Option 2 (Recommended)
1. Clone project with all sub-modules.
2. In Visual Studio 2017, select `File -> Open -> CMake`, open `CMakeList.txt` in project root dir.
3. Build the solution.

## Build on Linux
1. Clone project with all sub-modules.
2. Run `cd build && cmake .. && make all` in project root dir.

## Run
1. Add `127.0.0.1 www.noisyfox.io` to your hosts file. Don't forget to remove this line once you've done otherwise you may miss tons of amazing things from my site and you and I will both be sad about that :worried:.
2. Run `QuiltServer -p 1 -m www.noisyfox.io -i 172.104.122.122 -k "this is a key!" -l 8043 -v`.
3. Run `Quilt -s 127.0.0.1 -m www.noisyfox.io -k "this is a key!" -p 8043 -l 8042 -v`, connect to `127.0.0.1:8042` with a Telnet client (putty for example) and see the output in `QuiltServer`.
4. Use chrome or any other web browser to visit [https://www.noisyfox.io:8043](https://www.noisyfox.io:8043) and see the output in `QuiltServer`.
5. I bet you could tell the difference.
