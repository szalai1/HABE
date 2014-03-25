crypto: crypto.o hashs.o
	gcc -o crypto crypto.o hashs.o -I ~/.local/include/pbc -L ~/.local/lib -Wl,-rpath ~/.local/lib  -l pbc -l gmp -lcrypto
crypto.o: crypto.c  
	gcc -c crypto.c -I ~/.local/include/pbc -L ~/.local/lib -Wl,-rpath ~/.local/lib  -l pbc -l gmp -lcrypto 	
hashs.o: hashs.c
	gcc -c  hashs.c -I ~/.local/include/pbc -L ~/.local/lib -Wl,-rpath ~/.local/lib  -l pbc -l gmp -lcrypto


run:
	make -k
	./app < a.param
	echo "please press ENTER"
	read a

check-syntax:
	gcc -o nul -S ${CHK_SOURCES}
