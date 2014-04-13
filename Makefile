test: test.o crypto.o hashs.o user.o communication.o domain_manager.o root.o
	gcc -ggdb -o test test.o crypto.o hashs.o communication.o domain_manager.o root.o user.o -I ~/.local/include/pbc -L ~/.local/lib -Wl,-rpath ~/.local/lib  -l pbc -l gmp -lcrypto
test.o: test.c 
	gcc -ggdb  -c test.c -I ~/.local/include/pbc -L ~/.local/lib -Wl,-rpath ~/.local/lib  -l pbc -l gmp -lcrypto
crypto.o: crypto.c  
	gcc -ggdb -c crypto.c -I ~/.local/include/pbc -L ~/.local/lib -Wl,-rpath ~/.local/lib  -l pbc -l gmp -lcrypto 	
hashs.o: hashs.c
	gcc -ggdb -c  hashs.c -I ~/.local/include/pbc -L ~/.local/lib -Wl,-rpath ~/.local/lib  -l pbc -l gmp -lcrypto
#access_policy.o: access_policy.c
#	gcc -g -c  access_policy.c -I ~/.local/include/pbc -L ~/.local/lib -Wl,-rpath ~/.local/lib  -l pbc -l gmp -lcrypto
user.o: user.c
	gcc -ggdb -c  user.c -I ~/.local/include/pbc -L ~/.local/lib -Wl,-rpath ~/.local/lib  -l pbc -l gmp -lcrypto
domain_manager.o: domain_manager.c 
	gcc -ggdb -c  domain_manager.c -I ~/.local/include/pbc -L ~/.local/lib -Wl,-rpath ~/.local/lib  -l pbc -l gmp -lcrypto
root.o: root.c
	gcc -ggdb -c  root.c -I ~/.local/include/pbc -L ~/.local/lib -Wl,-rpath ~/.local/lib  -l pbc -l gmp -lcrypto
communication.o: communication.c
	gcc -g -c  communication.c -I ~/.local/include/pbc -L ~/.local/lib -Wl,-rpath ~/.local/lib  -l pbc -l gmp -lcrypto

run:
	make -k
	./crypto < a.param
	echo "please press ENTER"
	read a

check-syntax:
	gcc -o nul -S ${CHK_SOURCES}
