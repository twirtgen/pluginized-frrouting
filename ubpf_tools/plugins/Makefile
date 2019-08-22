CC=clang
SRC=$(shell find . -name '*.c')
OBJ=$(SRC:.c=.o)
CFLAGS=-I../.. -I../../lib -Wall -Wextra

all: $(SRC) $(OBJ)

$(OBJ): %.o

%.o: %.c
	$(CC) $(CFLAGS) -fno-stack-protector -O2 -emit-llvm -c $< -o - | llc -march=bpf -filetype=obj -o $@

copy: %.o
	cp ./list_plugins.json /etc/frr/list_plugins.json
	chmod 640 /etc/frr/list_plugins.json
	chown frr:frr /etc/frr/list_plugins.json
	cp $(OBJ) /

clean:
	rm -f $(OBJ)

.PHONY: %.o
