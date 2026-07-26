# oxdump — C++17 IL2CPP-дампер

Наследник Python-дампера, переписанный на C++ ради скорости. Один exe без
внешних зависимостей, тот же формат вывода, но **в 10 раз быстрее**. Читает
Android ELF, iOS Mach-O, Windows PE.

```
$ time oxdump global-metadata.dat libil2cpp.so -o dump.zip

[   0.0s] Читаю входные файлы
[   0.1s] Восстанавливаю ключ шифрования
           ключ восстановлен: 0xA5C3F19D
             метод: стыковка секций (score=573, отрыв 454)
[   0.2s] Определяю таблицы метаданных
[   0.4s] Разбираю ELF и релокации  — 1,232,014 relocs
[   0.7s] Ищу MetadataRegistration
[   0.8s] Сверяю метаданные с бинарником — 100%
[   0.8s] Определяю раскладку Il2CppTypeDefinition — 9/9 из данных
[   0.9s] Ищу таблицу смещений полей
[   0.9s] Ищу таблицы адресов методов — 88,414 Assembly-CSharp
[   1.1s] Генерирую il2cpp.h / dump.cs / script.json / offsets.h / offsets.cs / types.txt
[   2.0s] Собираю отчёт + пишу архив

  ГОТОВО за 2.3s
  архив: dump.zip (99.5 МБ)

real  0m2.322s
```

## Возможности

Всё, что делал Python-дампер — плюс скорость и три формата бинарей:

- **Авто-XOR ключ** без хардкода: восстанавливается по инвариантам заголовка
  (стыковка секций + якорные строки + пустые поля).
- **Другие шифры**: ADD32/SUB32/XOR+ROL/XOR+индекс — перебираются, если XOR
  не сработал.
- **Bruteforce по якорю** `<Module>` — когда в заголовке нет пустых секций.
- **Headerless-режим**: если заголовок метадаты AES/RC4-нутый и нечитаем,
  карта секций восстанавливается сканированием тела файла (проверено — тело
  никогда не шифруется, слишком дорого игре расшифровывать 27 МБ на старте).
- **Раскладка TypeDefinition** выводится из данных (все 9 полей, проверено
  замощением). Никаких констант под конкретную версию Unity.
- **MetadataRegistration** ищется в libil2cpp/UnityFramework/GameAssembly
  по форме структуры.
- **Три формата бинарей**: ELF64 (Android/Linux), Mach-O 64-bit (iOS),
  PE64 (Windows). Формат определяется по сигнатуре, конвейер один и тот же.
- **Восстановление релокаций** сканированием, если DT_RELA / rebase / .reloc
  убрана.
- **Определение упаковки** — если сегмент с таблицами сжат, дампер честно
  говорит "снимай из памяти", а не выдаёт мусор.
- **Проверка пары файлов** — метадата и libil2cpp обязаны быть из одной
  сборки. Иначе отказ или `--skip-pair-check` для явного bypass.

## Выходы

```
dump.zip
├── dump.cs        — читаемое дерево классов с полями и методами
├── il2cpp.h       — C-структуры со смещениями (Il2CppDumper-совместимо)
├── script.json    — адреса методов для IDA / Ghidra / Binary Ninja
├── offsets.h      — namespace-per-class с constexpr-полями для C++/чита
├── offsets.cs     — параллельный public static class для C#-инструментов
├── types.txt      — плоский индекс всех классов (grep-friendly)
└── REPORT.txt     — что и как было определено, включая пометки о headerless
```

Файл `offsets.h` — самое ценное для читера. Дословно:

```cpp
#include "offsets.h"
uintptr_t player = ...;
auto* transform = *(void**)(player + ox::PlayerManager::worldCameraRoot);
```

## Сборка

Есть два способа собрать — простой `Makefile` (как и раньше) и `cmake`.
Оба дают идентичный бинарь; выбор за вами.

### Makefile (Linux, как раньше)

```
make          # release, -O2, около 5 секунд
make debug    # -O0 -g
make test     # прогон интеграционного теста на реальных файлах
make clean
```

### CMake (Linux / MacOS / Windows)

```
cmake -B build-native                 # Release по умолчанию
cmake --build build-native -j
./build-native/oxdump <metadata> <binary> -o dump.zip
```

Опции конфигурации:

| Опция                        | По умолчанию      | Что делает                       |
|------------------------------|-------------------|----------------------------------|
| `-DCMAKE_BUILD_TYPE=Release` | `Release`         | тип сборки                       |
| `-DBUILD_TESTS=ON`           | `OFF`             | собрать набор тестов (CTest)     |
| `-DENABLE_LTO=ON`            | `ON` в Release    | межпроцедурная оптимизация (LTO) |

Прогон тестов:

```
cmake -B build-native -DBUILD_TESTS=ON
cmake --build build-native -j
ctest --test-dir build-native --output-on-failure
```

Установка (бинарь + man-страница):

```
cmake --install build-native --prefix /usr/local
#  -> /usr/local/bin/oxdump
#  -> /usr/local/share/man/man1/oxdump.1
man oxdump
```

Требования: g++ 9+ или clang++ 10+ с C++17 (для CMake — 3.16+). Только
стандартная библиотека — никаких Boost, никаких zlib. `cmake/find_deps.cmake`
на этапе конфигурации проверяет, что тулчейн реально поддерживает C++17
(включая `<filesystem>`), и падает с понятным сообщением, если нет.

## Cross-compile

Кросс-сборка делается через CMake-тулчейны в каталоге `cmake/`. Исходники
портируемы: `FileMap` использует `mmap` на Linux/Mac и
`CreateFileMappingW`+`MapViewOfFile` на Windows; размеры/пути файлов — через
`std::filesystem`. Никаких `#ifdef` в бизнес-логике.

### Windows (MinGW-w64)

Нужен кросс-тулчейн `x86_64-w64-mingw32-*`:

```
# Debian/Ubuntu : sudo apt install mingw-w64
# Fedora/RHEL   : sudo dnf install mingw64-gcc-c++
# Arch          : sudo pacman -S mingw-w64-gcc
# macOS (brew)  : brew install mingw-w64

cmake -B build-win -DCMAKE_TOOLCHAIN_FILE=cmake/windows-toolchain.cmake
cmake --build build-win -j
file build-win/oxdump.exe        # -> PE32+ executable (console) x86-64
```

Бинарь линкуется статически (`-static-libgcc -static-libstdc++`), так что
запускается на голой Windows без MinGW-DLL. **Требование:** MinGW-w64 должен
быть установлен на хосте — без него конфигурация падает с сообщением, что
`x86_64-w64-mingw32-g++` не найден.

### MacOS (osxcross или macOS-хост)

```
# На самом Mac (проще всего) — тулчейн сам определит APPLE-хост:
cmake -B build-mac -DCMAKE_TOOLCHAIN_FILE=cmake/macos-toolchain.cmake
cmake --build build-mac -j

# Кросс с Linux — нужен osxcross с легально полученным macOS SDK:
export OSXCROSS_ROOT=/opt/osxcross
cmake -B build-mac -DCMAKE_TOOLCHAIN_FILE=cmake/macos-toolchain.cmake
cmake --build build-mac -j
```

Кросс-сборка под macOS **требует osxcross или macOS-хоста** (Apple не
распространяет SDK отдельно). Без них тулчейн падает с понятным сообщением.
Опции: `-DMACOS_ARCH=arm64` (по умолчанию `x86_64`),
`-DMACOS_MIN_VERSION=11.0`.

## Использование

```
oxdump <metadata> <binary> [опции]

  -o FILE              имя архива (по умолчанию oxide_dump.zip)
  -v, --verbose        подробный лог
  -q, --quiet          только путь к архиву (для скриптов)
  --skip-pair-check    не отказываться при несовпадающей паре
```

Файлы можно указывать в любом порядке — они распознаются по сигнатуре
(`AF 1B B1 FA` для метадаты; ELF/Mach-O/PE для бинаря).

## Формат бинарей

| Формат  | Магия           | Платформа        | Файл в игре           |
|---------|-----------------|------------------|-----------------------|
| ELF64   | `7F 45 4C 46`   | Android, Linux   | `libil2cpp.so`        |
| Mach-O  | `CF FA ED FE`   | iOS, MacOS       | `UnityFramework`      |
| FAT     | `CA FE BA BE`   | iOS multi-arch   | `UnityFramework`      |
| PE64    | `4D 5A ... PE`  | Windows          | `GameAssembly.dll`    |

## Ограничения

- **Chained fixups** (iOS 15+ / arm64e Mach-O) не поддержаны. Для таких
  сборок понадобится обычный не-arm64e билд. Дампер отклонит корректно с
  внятным сообщением, а не выдаст мусор.
- **PE end-to-end** не проверен на реальном `GameAssembly.dll` — только
  синтетический PE (27 assertions зелёные). Логика поиска таблиц побайтово
  параллельна ELF, поэтому шанс поломки низкий.
- В **headerless-режиме** параметры методов и список сборок (Image[]) не
  восстанавливаются — заголовок нужен был именно для их местоположения.
  Всё остальное (типы, поля, методы, RVA) работает.

## Что где

```
include/oxdump/         публичные заголовки (только объявления)
├── common.h            типы, ByteView, исключения
├── io/                 mmap-обёртка, ZIP-писатель
├── crypto/             преобразования заголовка, детект контейнера
├── binary/             BinaryImage — общий интерфейс для ELF/Mach-O/PE
├── elf/                ELF64 parser + relocations + MR-finder + codegen
├── macho/              Mach-O parser + LC_DYLD_INFO rebase walker
├── pe/                 PE64 parser + base relocations
├── metadata/           header (auto-key), layout, tdlayout, headerless, pairing
├── model/              Model — типы/поля/методы поверх сырых таблиц
└── output/             генераторы 7 файлов вывода

src/                    реализации (те же папки)
tests/                  test_elf.cpp, test_metadata.cpp, test_output.cpp,
                        test_macho.cpp, test_pe.cpp
build/                  результат сборки (bin + object files)
```

## Производительность

На 27 МБ метадаты + 200 МБ libil2cpp (arm64), от старта до готового архива:

| дампер   | время |
|----------|-------|
| Python   | 23 с  |
| C++      | 2.3 с |

10× ускорение достигнуто за счёт: mmap вместо чтения в память, отсутствия
allocation в горячем пути (Model::type_name), явных типов вместо
Python-объектов, и того что генератор пишет сразу в std::string без
промежуточных объектов.

## Лицензия

MIT. Инструмент для исследования и обучения.
