CC = gcc
CFLAGS = -Wall -Wextra
LDFLAGS = -lcheck -lm -lpthread -lrt -lsubunit
TARGET = test_account_create.exe
SOURCES = test_account_create.c ../src/account.c
OBJECTS = $(SOURCES:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(TARGET)