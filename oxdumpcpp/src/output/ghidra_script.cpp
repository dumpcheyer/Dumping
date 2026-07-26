// oxdump/output/ghidra_script.cpp — генерация ghidra_script.py.
//
// Парный к ida_script.py: тот же script.json, но через Python-API Ghidra 11+.
// Кладётся рядом с дампом; запускается из Script Manager (или Window -> Python).
// Находит функцию по адресу через FunctionManager, переименовывает
// (setName(name, SourceType.USER_DEFINED)), ставит plate-комментарий, при наличии
// il2cpp.h рядом — опционально заводит типы через DataTypeManager.
//
// Тело — статический шаблон; динамически подставляется только баннер (число
// методов, версия, дата). Ghidra в скрипт впрыскивает глобалы currentProgram,
// monitor, askYesNo и т.п. — на этапе `python3 -c compile` их нет, но проверка
// только парсит файл, поэтому глобалы разрешаются лениво внутри функций.
//
// Совместимость: Ghidra 11+ (Python 3 через PyGhidra), а также классический
// Jython. Всё, что может отсутствовать, берём через globals().get(...) и мягко
// деградируем, а не падаем. Разрешение базы такое же, как в IDA: RVA в
// script.json — рантайм-VA; если они относительны imageBase, прибавляем его,
// иначе используем как есть; какой вариант верен — определяем по числу попаданий
// в реальные начала функций на первых N методах.
#include "oxdump/output/generators.h"
#include <ctime>

namespace oxdump::output {

namespace {

std::string today() {
    std::time_t t = std::time(nullptr);
    std::tm tm{};
#if defined(_WIN32)
    localtime_s(&tm, &t);
#else
    localtime_r(&t, &tm);
#endif
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%04d-%02d-%02d",
                  tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday);
    return std::string(buf);
}

const char* GHIDRA_BODY = R"PY(
import os

try:
    import json
except Exception:
    json = None

# Ghidra injects these as globals when a script runs (currentProgram, monitor,
# getScriptArgs, ...). Resolve them lazily so `python3 -c compile` (which only
# parses) never trips over their absence, and so a plain import does not explode.
def _g(name, default=None):
    return globals().get(name, default)


def out(msg):
    # Ghidra scripts print to the console; println exists in the script scope.
    fn = _g("println")
    if fn is not None:
        fn("[il2cpp] " + msg)
    else:
        print("[il2cpp] " + msg)


def current_program():
    cp = _g("currentProgram")
    if cp is not None:
        return cp
    state = _g("state")
    if state is not None and hasattr(state, "getCurrentProgram"):
        return state.getCurrentProgram()
    return None


def source_user_defined():
    # ghidra.program.model.symbol.SourceType.USER_DEFINED
    try:
        from ghidra.program.model.symbol import SourceType
        return SourceType.USER_DEFINED
    except Exception:
        return None


def to_addr(program, value):
    # Turn an integer VA into a Ghidra Address in the program's default space.
    space = program.getAddressFactory().getDefaultAddressSpace()
    return space.getAddress(value)


def image_base_value(program):
    try:
        return program.getImageBase().getOffset()
    except Exception:
        return 0


def func_at(program, addr):
    # Function whose entry point is exactly addr (not merely containing it).
    fm = program.getFunctionManager()
    f = fm.getFunctionAt(addr)
    return f


def ensure_func(program, addr):
    # Return a function starting at addr, creating one if Ghidra missed it.
    f = func_at(program, addr)
    if f is not None:
        return f
    create = _g("createFunction")
    if create is not None:
        try:
            f = create(addr, None)
            if f is not None:
                return f
        except Exception:
            pass
    return func_at(program, addr)


# ---- optional data types from il2cpp.h --------------------------------------
# Best-effort: register the shared Il2CppObject header via the DataTypeManager so
# structures line up. Full C parsing is left to Ghidra's own "Parse C Source"
# (see structs.h); here we add just the 2-pointer header programmatically.
def create_object_header(program):
    try:
        from ghidra.program.model.data import (
            StructureDataType, PointerDataType, VoidDataType, CategoryPath,
        )
    except Exception:
        out("skipped Il2CppObject data type (data API unavailable)")
        return
    try:
        dtm = program.getDataTypeManager()
        path = CategoryPath("/il2cpp")
        existing = dtm.getDataType(path, "Il2CppObject")
        if existing is not None:
            out("Il2CppObject data type already present")
            return
        ptr = PointerDataType(VoidDataType.dataType)
        st = StructureDataType(path, "Il2CppObject", 0)
        st.add(ptr, "klass", "Il2CppClass*")
        st.add(ptr, "monitor", "MonitorData*")
        txn = program.startTransaction("il2cpp: add Il2CppObject")
        try:
            dtm.addDataType(st, None)
        finally:
            program.endTransaction(txn, True)
        out("Il2CppObject data type added to DataTypeManager")
    except Exception as e:
        out("could not add Il2CppObject data type: %s" % e)


# ---- signature / comment helpers --------------------------------------------
def build_comment(me):
    lines = []
    sig = me.get("Signature", "")
    if sig:
        lines.append(sig)
    tsig = me.get("TypeSignature", "")
    if tsig:
        lines.append("class: " + tsig)
    lines.append("il2cpp method")
    return "\n".join(lines)


def apply_signature(program, func, me):
    # Ghidra can parse a C prototype string; Signature is close but uses C#
    # names, so we keep it as the plate comment (set elsewhere) rather than force
    # a parse that would fail on 'System.String' etc. This hook is where a fuller
    # DataTypeParser pass would go; left conservative on purpose.
    return


# ---- base-address resolution -------------------------------------------------
# Same reasoning as the IDA script: script.json RVAs may be ImageBase-relative or
# already full VAs. Probe both on the first N methods, keep whichever lands more
# addresses on real function starts.
def resolve_base(program, methods, image_base):
    probe = methods[: min(len(methods), 200)]
    if not probe:
        return 0
    def score(delta):
        hits = 0
        for me in probe:
            try:
                addr = to_addr(program, me["Address"] + delta)
            except Exception:
                continue
            if func_at(program, addr) is not None:
                hits += 1
        return hits
    hits_direct = score(0)
    hits_based = score(image_base)
    out("base probe: as-is=%d hit, +imagebase(0x%X)=%d hit"
        % (hits_direct, image_base, hits_based))
    if hits_based > hits_direct:
        out("using +imagebase convention")
        return image_base
    out("using as-is (already full VA) convention")
    return 0


def load_methods(program):
    # script.json lives next to the analysed binary; getExecutablePath points at
    # it. Fall back to the script's own directory if that is unavailable.
    candidates = []
    try:
        exe = program.getExecutablePath()
        if exe:
            candidates.append(os.path.join(os.path.dirname(exe), "script.json"))
    except Exception:
        pass
    try:
        candidates.append(os.path.join(os.path.dirname(__file__), "script.json"))
    except Exception:
        pass
    path = None
    for c in candidates:
        if c and os.path.isfile(c):
            path = c
            break
    if path is None:
        out("ERROR: script.json not found (looked in: %s)" % ", ".join(candidates))
        return None
    if json is None:
        out("ERROR: json module unavailable")
        return None
    with open(path, "r") as f:
        data = json.load(f)
    methods = data.get("ScriptMethod", [])
    out("loaded %d ScriptMethod entries from %s" % (len(methods), path))
    return methods


def is_cancelled():
    monitor = _g("monitor")
    if monitor is not None and hasattr(monitor, "isCancelled"):
        try:
            return monitor.isCancelled()
        except Exception:
            return False
    return False


def run():
    out("=" * 60)
    out("%s Ghidra import  (methods expected: %s)" % (BANNER_PRODUCT, BANNER_COUNT))
    out("build date: %s" % BANNER_DATE)
    out("=" * 60)

    program = current_program()
    if program is None:
        out("ERROR: no current program (run this from Ghidra's Script Manager)")
        return

    methods = load_methods(program)
    if not methods:
        return

    create_object_header(program)

    image_base = image_base_value(program)
    out("imageBase=0x%X" % image_base)
    delta = resolve_base(program, methods, image_base)
    src = source_user_defined()

    renamed = 0
    commented = 0
    missing = 0
    total = len(methods)
    step = max(1, total // 20)

    txn = program.startTransaction("il2cpp: import script.json")
    try:
        for i, me in enumerate(methods):
            if is_cancelled():
                out("cancelled by user at %d / %d" % (i, total))
                break
            if i % step == 0:
                out("progress: %d / %d (%d%%)" % (i, total, (i * 100) // total))
            try:
                addr = to_addr(program, me["Address"] + delta)
            except Exception:
                continue
            func = ensure_func(program, addr)
            if func is None:
                missing += 1
                continue
            name = me.get("Name", "")
            if name:
                try:
                    if src is not None:
                        func.setName(name, src)
                    else:
                        func.setName(name)
                    renamed += 1
                except Exception:
                    pass
            try:
                func.setComment(build_comment(me))
                commented += 1
            except Exception:
                pass
            apply_signature(program, func, me)
    finally:
        program.endTransaction(txn, True)

    out("-" * 60)
    out("done: renamed=%d  commented=%d  unresolved=%d  total=%d"
        % (renamed, commented, missing, total))
    out("=" * 60)


run()
)PY";

} // namespace

std::string gen_ghidra_script(model::Model& m) {
    u64 method_count = 0;
    const u32 total = m.layout().typedef_count;
    for (u32 i = 0; i < total; ++i) {
        for (const auto& mo : m.methods_of(i)) {
            if (mo.rva) ++method_count;
        }
    }

    std::string out;
    out.reserve(16384);

    out +=
        "# ============================================================================\n"
        "# ghidra_script.py - auto-generated IL2CPP importer for Ghidra 11+\n"
        "# Generated by OxideDumper 1.0.0 (C++17)\n"
        "# Date: " + today() + "\n"
        "#\n"
        "# HOW TO RUN\n"
        "#   1. Import libil2cpp.so / GameAssembly.dll into Ghidra and analyze it.\n"
        "#   2. Window -> Script Manager, add this file's directory, run ghidra_script.py\n"
        "#      (or Window -> Python and exec() it). Keep script.json in the SAME\n"
        "#      directory as the analysed binary.\n"
        "#\n"
        "# What it does: reads script.json, finds each function via the FunctionManager,\n"
        "# renames it (SourceType.USER_DEFINED), sets a plate comment with class +\n"
        "# return type + args, and optionally adds the Il2CppObject data type. Progress\n"
        "# is printed to the console.\n"
        "#\n"
        "# @category IL2CPP\n"
        "# @menupath Tools.IL2CPP.Import script.json\n"
        "# ============================================================================\n"
        "\n"
        "BANNER_PRODUCT = \"OxideDumper\"\n"
        "BANNER_DATE = \"" + today() + "\"\n"
        "BANNER_COUNT = " + std::to_string(method_count) + "\n";

    out += GHIDRA_BODY;
    return out;
}

} // namespace oxdump::output
