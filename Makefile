CC = cc
LD = $(CC)

TARGET = as17_0

OBJECTS = src/main.o

release: CFLAGS += -DNDEBUG -O2
debug: CFLAGS += -g

release debug: $(TARGET)

$(TARGET): $(OBJECTS)
	$(LD) $(LDFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $^

clean:
	rm -f $(TARGET) $(OBJECTS)
