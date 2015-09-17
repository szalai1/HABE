CC=gcc
FLAGS=-I ~/.local/include/pbc -L ~/.local/lib -Wl,-rpath ~/.local/lib  -l pbc -l gmp -lcrypto
test: test.o crypto.o hashs.o user.o communication.o domain_manager.o root.o
	gcc -ggdb -o test test.o crypto.o hashs.o communication.o domain_manager.o root.o user.o
test.o: test.c 
	gcc -ggdb  -c test.c 
crypto.o: crypto.c  
	gcc -ggdb -c crypto.c 	
hashs.o: hashs.c
	gcc -ggdb -c  hashs.c 
#access_policy.o: access_policy.c
#	gcc -g -c  access_policy.c -I ~/.local/include/pbc -L ~/.local/lib -Wl,-rpath ~/.local/lib  -l pbc -l gmp -lcrypto
user.o: user.c
	gcc -ggdb -c  user.c 
domain_manager.o: domain_manager.c 
	gcc -ggdb -c  domain_manager.c 
root.o: root.c
	gcc -ggdb -c  root.c 
communication.o: communication.c
	gcc -g -c  communication.c 

run:
	make -k
	./crypto < a.param
	echo "please press ENTER"
	read a

check-syntax:
	gcc -o nul -S ${CHK_SOURCES}
