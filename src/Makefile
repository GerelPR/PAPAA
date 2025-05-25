CC = g++
CFLAGS = -fopenmp
LDFLAGS = -ltfhe-spqlios-fma -lm
SRCS = main.cpp adders.c
OBJS = main.o adders.o
TARGET = main

all: clean $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) $(LDFLAGS)

%.o: %.cpp
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET) $(OBJS)
	@echo "Cleaned build files."

.PHONY: all clean