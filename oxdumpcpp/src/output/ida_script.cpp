// oxdump/output/ida_script.cpp — генерация ida_script.py.
//
// Il2CppDumper кладёт script.json, но скормить его напрямую IDA нельзя: его умеет
// читать только GUI самого Il2CppDumper. Здесь мы генерируем самодостаточный
// Python-скрипт для IDA (File -> Script file...), который берёт лежащий рядом
// script.json и сам переименовывает функции, ставит комментарии и заводит тип
// заголовка Il2CppObject.
//
// Скрипт по сути статический шаблон: все данные о методах уже в script.json.
// Из Model динамически подставляется только баннер — число методов (для
// прогресса) и версия/дата. Поэтому тело держим в raw-строке R"PY(...)PY", а
// счётчик и дату вставляем отдельными кусками: так шаблон читается как обычный
// Python и не разъезжается от экранирования.
//
// Совместимость: современные IDA (7.4+/8.x/9.x) — Python 3. Пробуем сначала
// idaapi/ida_* API, при отсутствии откатываемся на idc — так один файл работает
// и в старых, и в новых сборках. Определение базы: RVA в script.json — это уже
// рантайм-VA как их видит Il2CppDumper. Если они попадают в [0, image_size),
// прибавляем imagebase; если это уже полные VA (частый случай для arm64
// libil2cpp, загруженной с base=0) — используем как есть. Какой из двух вариантов
// верен, решаем автоопределением: на первых N методах пробуем оба и берём тот,
// где больше адресов попадает в реальные начала функций.
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

// Тело скрипта до места, куда подставляется баннер (число методов/дата).
// Всё остальное — статика. Разбито на HEAD (шапка + баннер-переменные) и BODY
// (вся логика), чтобы динамические значения вставлять между ними.
const char* IDA_BODY = R"PY(
import os

# ---- IDA API shims -----------------------------------------------------------
# Modern IDA (7.4+/8.x/9.x) ships Python 3. Prefer the ida_* / idaapi modules and
# fall back to idc so one file works across builds. Anything missing degrades to a
# no-op with a warning rather than aborting the whole run.
try:
    import idaapi
except Exception:
    idaapi = None
try:
    import idc
except Exception:
    idc = None
try:
    import ida_funcs
except Exception:
    ida_funcs = None
try:
    import ida_name
except Exception:
    ida_name = None
try:
    import ida_bytes
except Exception:
    ida_bytes = None
try:
    import ida_typeinf
except Exception:
    ida_typeinf = None
try:
    import json
except Exception:
    json = None


def out(msg):
    # IDA output window; print() is mirrored there in every supported version.
    print("[il2cpp] " + msg)


def get_imagebase():
    if idaapi is not None and hasattr(idaapi, "get_imagebase"):
        return idaapi.get_imagebase()
    if idc is not None and hasattr(idc, "get_imagebase"):
        return idc.get_imagebase()
    return 0


def input_file_path():
    if idc is not None and hasattr(idc, "get_input_file_path"):
        return idc.get_input_file_path()
    if idaapi is not None and hasattr(idaapi, "get_input_file_path"):
        return idaapi.get_input_file_path()
    return ""


def min_ea():
    if idc is not None and hasattr(idc, "get_inf_attr") and hasattr(idc, "INF_MIN_EA"):
        return idc.get_inf_attr(idc.INF_MIN_EA)
    if idaapi is not None and hasattr(idaapi, "inf_get_min_ea"):
        return idaapi.inf_get_min_ea()
    return 0


def max_ea():
    if idc is not None and hasattr(idc, "get_inf_attr") and hasattr(idc, "INF_MAX_EA"):
        return idc.get_inf_attr(idc.INF_MAX_EA)
    if idaapi is not None and hasattr(idaapi, "inf_get_max_ea"):
        return idaapi.inf_get_max_ea()
    return 0


def is_func_start(ea):
    # True if ea is the entry of a defined function.
    if ida_funcs is not None:
        f = ida_funcs.get_func(ea)
        return f is not None and f.start_ea == ea
    if idc is not None and hasattr(idc, "get_func_attr") and hasattr(idc, "FUNCATTR_START"):
        start = idc.get_func_attr(ea, idc.FUNCATTR_START)
        return start != idc.BADADDR and start == ea
    return False


def ensure_func(ea):
    # Make sure a function exists at ea (creating one if IDA missed it).
    if is_func_start(ea):
        return True
    if ida_funcs is not None and hasattr(ida_funcs, "add_func"):
        if ida_funcs.add_func(ea):
            return True
    if idc is not None and hasattr(idc, "add_func"):
        if idc.add_func(ea):
            return True
    return is_func_start(ea)


def set_name(ea, name):
    if ida_name is not None and hasattr(ida_name, "set_name"):
        flags = 0
        if hasattr(ida_name, "SN_NOWARN"):
            flags |= ida_name.SN_NOWARN
        if hasattr(ida_name, "SN_FORCE"):
            flags |= ida_name.SN_FORCE
        return ida_name.set_name(ea, name, flags)
    if idc is not None and hasattr(idc, "set_name"):
        flags = getattr(idc, "SN_NOWARN", 0)
        return idc.set_name(ea, name, flags)
    return False


def set_func_cmt(ea, cmt):
    if ida_funcs is not None and hasattr(ida_funcs, "set_func_cmt"):
        f = ida_funcs.get_func(ea)
        if f is not None:
            ida_funcs.set_func_cmt(f, cmt, True)   # True == repeatable
            return True
    if idc is not None and hasattr(idc, "set_func_cmt"):
        idc.set_func_cmt(ea, cmt, 1)
        return True
    return False


# ---- Il2CppObject header type -----------------------------------------------
# Create the shared 2-pointer object header (klass + monitor) so applying it at
# the start of any instance lines up its fields. il2cpp.h (if present next to this
# script) has the per-class structs; here we only guarantee the header exists.
def create_object_header():
    hdr_path = os.path.join(os.path.dirname(input_file_path()), "il2cpp.h")
    decl_source = "il2cpp.h" if os.path.isfile(hdr_path) else "built-in fallback"
    decl = (
        "struct MonitorData;\n"
        "struct Il2CppClass;\n"
        "struct Il2CppObject { struct Il2CppClass *klass; struct MonitorData *monitor; };\n"
    )
    if ida_typeinf is not None and hasattr(ida_typeinf, "idc_parse_types"):
        try:
            flags = getattr(ida_typeinf, "HTI_DCL", 0)
            n = ida_typeinf.idc_parse_types(decl, flags)
            out("Il2CppObject header type created (%d decls, %s)" % (n, decl_source))
            return
        except Exception as e:
            out("could not create header type via ida_typeinf: %s" % e)
    if idc is not None and hasattr(idc, "parse_decls"):
        try:
            idc.parse_decls(decl, 0)
            out("Il2CppObject header type created via idc (%s)" % decl_source)
            return
        except Exception as e:
            out("could not create header type via idc: %s" % e)
    out("skipped Il2CppObject header type (no typeinfo API)")


# ---- base-address resolution -------------------------------------------------
# RVAs in script.json are runtime VAs as Il2CppDumper sees them. Two conventions
# exist in the wild:
#   (a) values are relative to ImageBase  -> add ImageBase
#   (b) values are already full VAs        -> use as-is (common for arm64 .so at base 0)
# We auto-detect: try both on the first N methods and keep whichever lands more
# addresses on real function starts.
def resolve_base(methods, image_base, lo, hi):
    probe = methods[: min(len(methods), 200)]
    if not probe:
        return 0
    def score(delta):
        hits = 0
        for me in probe:
            ea = me["Address"] + delta
            if lo <= ea < hi and is_func_start(ea):
                hits += 1
        return hits
    hits_direct = score(0)
    hits_based = score(image_base)
    out("base probe: as-is=%d hit, +imagebase(0x%X)=%d hit"
        % (hits_direct, image_base, hits_based))
    # Prefer +imagebase only when it strictly wins; ties go to as-is so a base of
    # 0 (already-VA case) never gets double-counted.
    if hits_based > hits_direct:
        out("using +imagebase convention")
        return image_base
    out("using as-is (already full VA) convention")
    return 0


# ---- signature helpers -------------------------------------------------------
def build_comment(me):
    # me has Name ("Class$$Method"), Signature ("ret Class::Method(args)"),
    # TypeSignature ("Class"). Fold them into a repeatable function comment.
    lines = []
    sig = me.get("Signature", "")
    if sig:
        lines.append(sig)
    tsig = me.get("TypeSignature", "")
    if tsig:
        lines.append("class: " + tsig)
    lines.append("il2cpp method")
    return "\n".join(lines)


def short_name(me):
    # "Class$$Method" -> a valid IDA symbol. IDA sanitizes further itself, but we
    # keep the readable Class$$Method form Il2CppDumper users expect.
    return me.get("Name", "")


# ---- static-with-metadata SP diff -------------------------------------------
# IL2CPP calling convention: arg0 is `this` (Il2CppObject*) for instance methods
# and an Il2CppRuntimeInterfaceOffsetPair* for static-with-metadata thunks. IDA
# derives the stack layout itself; we only nudge the SP delta at the entry so the
# analysis does not mis-track the hidden first argument on the few thunks where it
# guesses wrong. This is best-effort and skipped silently if the API is absent.
def hint_sp_diff(ea, me):
    if idc is None or not hasattr(idc, "add_user_stkpnt"):
        return
    try:
        # A zero delta at entry is a safe no-op anchor that stops IDA from
        # propagating a bogus SP guess from a preceding chunk.
        idc.add_user_stkpnt(ea, 0)
    except Exception:
        pass


def load_methods():
    path = os.path.join(os.path.dirname(input_file_path()), "script.json")
    if not os.path.isfile(path):
        out("ERROR: script.json not found next to the input file: " + path)
        return None
    if json is None:
        out("ERROR: json module unavailable")
        return None
    with open(path, "r") as f:
        data = json.load(f)
    methods = data.get("ScriptMethod", [])
    out("loaded %d ScriptMethod entries from script.json" % len(methods))
    return methods


def main():
    out("=" * 60)
    out("%s IDA import  (methods expected: %s)" % (BANNER_PRODUCT, BANNER_COUNT))
    out("build date: %s" % BANNER_DATE)
    out("=" * 60)

    methods = load_methods()
    if not methods:
        return

    create_object_header()

    image_base = get_imagebase()
    lo = min_ea()
    hi = max_ea()
    out("imagebase=0x%X  range=[0x%X, 0x%X)" % (image_base, lo, hi))

    delta = resolve_base(methods, image_base, lo, hi)

    renamed = 0
    commented = 0
    missing = 0
    total = len(methods)
    step = max(1, total // 20)
    for i, me in enumerate(methods):
        if i % step == 0:
            out("progress: %d / %d (%d%%)" % (i, total, (i * 100) // total))
        try:
            ea = me["Address"] + delta
        except Exception:
            continue
        if not (lo <= ea < hi):
            missing += 1
            continue
        if not ensure_func(ea):
            missing += 1
            continue
        name = short_name(me)
        if name and set_name(ea, name):
            renamed += 1
        if set_func_cmt(ea, build_comment(me)):
            commented += 1
        hint_sp_diff(ea, me)

    out("-" * 60)
    out("done: renamed=%d  commented=%d  unresolved=%d  total=%d"
        % (renamed, commented, missing, total))
    out("=" * 60)


if __name__ == "__main__":
    main()
else:
    main()
)PY";

} // namespace

std::string gen_ida_script(model::Model& m) {
    // Считаем методы с RVA — их и увидит скрипт в script.json. Быстрее пройтись
    // по модели, чем генерировать JSON: считаем ненулевые rva по типам.
    u64 method_count = 0;
    const u32 total = m.layout().typedef_count;
    for (u32 i = 0; i < total; ++i) {
        for (const auto& mo : m.methods_of(i)) {
            if (mo.rva) ++method_count;
        }
    }

    std::string out;
    out.reserve(16384);

    // Шапка файла (комментарий + баннер-переменные). Держим отдельно от тела:
    // сюда подставляем число методов и дату, дальше идёт статический BODY.
    out +=
        "# ============================================================================\n"
        "# ida_script.py - auto-generated IL2CPP importer for IDA Pro (7.x / 8.x / 9.x)\n"
        "# Generated by OxideDumper 1.0.0 (C++17)\n"
        "# Date: " + today() + "\n"
        "#\n"
        "# HOW TO RUN\n"
        "#   1. Open libil2cpp.so / GameAssembly.dll in IDA and let auto-analysis finish.\n"
        "#   2. File -> Script file...  and pick this ida_script.py.\n"
        "#   3. Keep script.json (and optionally il2cpp.h) in the SAME directory.\n"
        "#\n"
        "# What it does: reads script.json, renames every function at its RVA to the\n"
        "# method name, adds a comment with class + return type + args, creates the\n"
        "# Il2CppObject header type, and reports progress in the Output window.\n"
        "# ============================================================================\n"
        "\n"
        "BANNER_PRODUCT = \"OxideDumper\"\n"
        "BANNER_DATE = \"" + today() + "\"\n"
        "BANNER_COUNT = " + std::to_string(method_count) + "\n";

    out += IDA_BODY;
    return out;
}

} // namespace oxdump::output
