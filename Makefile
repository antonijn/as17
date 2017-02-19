CC = cc
LD = $(CC)

TARGET = as17_0

OBJECTS = src/main.o

PREFIX = /usr/local

release: CFLAGS += -DNDEBUG -O2
debug: CFLAGS += -g

release debug: $(TARGET)

$(TARGET): $(OBJECTS)
	$(LD) $(LDFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $^

install:
	cp as17 as17_0 $(PREFIX)/bin

MANPAGES = man/as17.1
RONN = ronn
RONNFLAGS = -r

man: $(MANPAGES)

%.1: %.1.ronn
	$(RONN) $(RONNFLAGS) $^

clean:
	rm -f $(TARGET) $(OBJECTS) $(MANPAGES)
