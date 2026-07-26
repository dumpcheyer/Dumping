# oxdump — C++17 IL2CPP-дампер. Один бинарь, ноль внешних зависимостей.
#
#   make            собрать (release, -O2)
#   make debug      -O0 -g
#   make test       собрать и прогнать интеграционный тест
#   make clean

CXX      ?= g++
STD      ?= c++17
OPT      ?= -O2
CXXFLAGS ?= -std=$(STD) $(OPT) -Wall -Wextra -Wno-unused-parameter -Iinclude
LDFLAGS  ?= -lpthread

SRC_DIRS := src/crypto src/elf src/metadata src/model src/output src/cli
SRC      := $(wildcard src/*/*.cpp)
OBJ      := $(SRC:%.cpp=build/%.o)

# Самопроверка: те же объектные файлы, что и у oxdump, но БЕЗ main.o (у
# selftest свой main). Один бинарь на все категории тестов.
LIB_OBJ  := $(filter-out build/src/cli/main.o,$(OBJ))
SELFTEST := build/selftest

BIN      := build/oxdump

.PHONY: all clean debug test test-deflate test-arm64 selftest

all: $(BIN)

$(BIN): $(OBJ)
	@mkdir -p $(dir $@)
	$(CXX) $(OBJ) $(LDFLAGS) -o $@
	@printf "\n\033[32mсобрано:\033[0m $@ (%s байт)\n" "$$(stat -c%s $@)"

build/%.o: %.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -c $< -o $@

debug: OPT := -O0 -g
debug: all

test: $(BIN)
	@echo "=== integration test ==="
	./$(BIN) tests/nov_meta.dat tests/nov_bin.so -o /tmp/oxdump_test.zip -v

# Комплексная самопроверка: строит модель+генераторы в процессе, гоняет 12
# категорий (реальные сборки, восстановление ключа, замощение, сверка пар,
# упаковка, headerless, контейнеры, полный конвейер, ELF/Mach-O/PE, детерминизм).
# Выход 0 ⇔ все проверки прошли.
build/selftest.o: tests/selftest.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -c $< -o $@

selftest: build/selftest.o $(LIB_OBJ)
	$(CXX) build/selftest.o $(LIB_OBJ) $(LDFLAGS) -o $(SELFTEST)
	@printf "\n\033[32mсобрано:\033[0m $(SELFTEST) (%s байт)\n" "$$(stat -c%s $(SELFTEST))"

# Тест DEFLATE-энкодера. ТОЛЬКО этот тест линкует системный zlib (raw inflate)
# для проверки round-trip; основной бинарь oxdump zlib не использует.
# На этой машине нет libz.so/системного zlib.h — линкуемся с /lib64/libz.so.1
# напрямую, прототип берём из tests/zlib_min.h. Реальный dump.cs (если есть)
# передаётся через OXDUMP_DUMPCS для проверок ratio/timing.
ZLIB_SO ?= /lib64/libz.so.1
test-deflate:
	@mkdir -p build
	$(CXX) $(CXXFLAGS) tests/test_deflate.cpp $(ZLIB_SO) -o build/test_deflate
	LD_LIBRARY_PATH=$(dir $(ZLIB_SO)) ./build/test_deflate

# Модульный тест декодера AArch64 (oxdump::arm64). Самодостаточный: линкует
# только disasm.cpp. Часть проверок читает tests/nov_bin.so по mmap (если файла
# нет — эти проверки пропускаются). Выход 0 ⇔ все проверки прошли.
test-arm64:
	@mkdir -p build
	$(CXX) $(CXXFLAGS) tests/test_arm64.cpp src/arm64/disasm.cpp -o build/test_arm64
	./build/test_arm64

clean:
	rm -rf build
