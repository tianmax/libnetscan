CC ?= cc
CFLAGS += -fPIC -Wall -Wextra
LDFLAGS += -shared -ljansson
LIBNAME = netscan
TARGET = lib$(LIBNAME).so
	
SOURCES = $(wildcard ./src/*.c)	
OBJS = $(patsubst %.c,%.o,$(SOURCES))
	 
all: $(TARGET)

$(TARGET): $(OBJS)
	$(LD) $(LDFLAGS) -o $@ $(OBJS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(TARGET) $(OBJS)
