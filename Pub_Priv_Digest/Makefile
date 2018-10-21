TARGET = hash_enc_dec
CSRC = $(TARGET).c
COBJ = $(CSRC:.c=.o)

CC = gcc
CFLAGS = -c
LDFLAGS = -lssl -lcrypto

all: $(TARGET)

$(TARGET): $(COBJ)
	@echo "linking ..."
	$(CC) -o $@ $^ $(LDFLAGS)


%.o: %.c
	@echo "compiling $< ..."
	$(CC) -c $<


clean:
	rm -f $(TARGET) $(COBJ)

run:
	./$(TARGET) 

.PHONY: all clean run start end
