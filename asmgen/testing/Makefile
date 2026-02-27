do:
	i686-w64-mingw32-gcc test.c -o sc.exe -Wl,--disable-nxcompat -Wl,--disable-dynamicbase -fno-stack-protector 
	mv sc.exe ~/Share/
	ls ~/Share

server:
	i686-w64-mingw32-gcc server.c -o server.exe -Wl,--disable-nxcompat -Wl,--disable-dynamicbase -fno-stack-protector -lws2_32
	cp server.exe ~/Share/
	ls ~/Share