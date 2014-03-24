CC=gcc
CFLAGS=-c -Wall -lcrypto -I ~/.local/include/pbc -L ~/.local/lib -Wl,-rpath ~/.local/lib  -l pbc -l gmp
LDFLAGS=
SOURCES=crypto.c
OBJECTS=$(SOURCES:.c=.o)
EXECUTABLE=crypto

all: $(SOURCES) $(EXECUTABLE)
	
$(EXECUTABLE): $(OBJECTS) 
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@

.cpp.o:
	$(CC) $(CFLAGS) $< -o $@
