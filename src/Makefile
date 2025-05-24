CC = gcc
CFLAGS = -fopenmp
LDFLAGS = -ltfhe-spqlios-fma -lm
SRCS = main1.c adders.c
OBJS = main1.o adders.o
TARGET = main1

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET) $(OBJS)
	@echo "Cleaned build files."

.PHONY: all clean
