# Имя исполняемого файла
TARGET = memory

# Компилятор и флаги компиляции
CC = gcc
CFLAGS = -Wall -O2

# Исходные файлы
SRCS = main.c

# Объектные файлы
OBJS = $(SRCS:.c=.o)

# Правило по умолчанию для сборки
all: $(TARGET)

# Правило для создания исполняемого файла
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS)

# Правило для создания объектного файла
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Правило для очистки временных файлов
clean:
	rm -f $(TARGET) $(OBJS)

# Правило для запуска программы
run: $(TARGET)
	./$(TARGET)

.PHONY: all clean run