"""logmask — маскирование чувствительных данных в логах.

Примеры:
  logmask service.log                  -> service.masked.log рядом с исходником
  logmask service.log -o safe.log
  logmask ./logs/ -o ./logs_masked/    -> вся папка (включая .gz), структура сохраняется
  type app.log | logmask - > safe.log  -> через pipe
  logmask --check service.log          -> только проверить, код выхода 1 если что-то нашлось
"""
from __future__ import annotations

import argparse
import gzip
import os
import sys
from collections import Counter
from pathlib import Path

from masker import Config, Masker, hide_digits

EXIT_OK, EXIT_FOUND, EXIT_ERROR = 0, 1, 2
ERRORS = "surrogateescape"   # непонятные байты сохраняются как есть


# ---------------------------------------------------------------- файлы

def detect_encoding(path: Path) -> str:
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rb") as f:
        head = f.read(1 << 20)
    if head.startswith(b"\xef\xbb\xbf"):
        return "utf-8-sig"
    try:
        head.decode("utf-8")
        return "utf-8"
    except UnicodeDecodeError as e:
        # обрезанный многобайтовый символ в конце куска — это всё ещё utf-8
        if e.start >= len(head) - 3:
            return "utf-8"
        return "cp1251"


def open_text(path: Path, mode: str, encoding: str):
    if path.suffix == ".gz":
        return gzip.open(path, mode + "t", encoding=encoding, errors=ERRORS, newline="")
    return open(path, mode, encoding=encoding, errors=ERRORS, newline="")


def default_output(src: Path) -> Path:
    # service.log -> service.masked.log ; app.log.gz -> app.masked.log.gz
    name, gz = (src.name[:-3], ".gz") if src.name.endswith(".gz") else (src.name, "")
    stem, dot, ext = name.partition(".")
    new = f"{stem}.masked.{ext}" if dot else f"{stem}.masked"
    return src.with_name(new + gz)


def collect(paths: list[Path], cfg: Config) -> list[tuple[Path, Path | None]]:
    """Список (файл, корень папки или None)."""
    out = []
    for p in paths:
        if p.is_dir():
            found = set()
            for g in cfg.file_globs:
                found.update(f for f in p.rglob(g) if f.is_file() and ".masked" not in f.name)
            out.extend((f, p) for f in sorted(found))
        elif p.is_file():
            out.append((p, None))
        else:
            raise FileNotFoundError(f"не найден: {p}")
    return out


def target_for(src: Path, root: Path | None, out: Path | None, many: bool) -> Path:
    if out is None:
        return default_output(src)
    if root is not None:                       # папка -> зеркалим структуру
        return out / src.relative_to(root)
    if many or out.is_dir():
        return out / src.name
    return out


# ---------------------------------------------------------------- обработка

def mask_stream(masker: Masker, src, dst) -> int:
    n = 0
    for n, line in enumerate(src, 1):
        dst.write(masker.mask_line(line))
    return n


def check_stream(masker: Masker, src, name: str, limit: int, shown: list[int]) -> int:
    n = 0
    for n, line in enumerate(src, 1):
        before = sum(masker.stats.values())
        masked = masker.mask_line(line)
        found = masked != line or sum(masker.stats.values()) != before
        suspects = masker.last_suspects
        if found or suspects:
            if shown[0] < limit:
                # печатаем только замаскированную строку, подозрительные числа — частично скрытыми
                preview = masked.rstrip("\r\n")
                for num in suspects:
                    preview = preview.replace(num, f"«?{hide_digits(num)}»")
                preview = preview if len(preview) <= 200 else preview[:197] + "..."
                print(f"{'?' if suspects and not found else '!'} {name}:{n}: {preview}")
            shown[0] += 1
    return n


def fmt_stats(stats: Counter, suspects: int = 0) -> str:
    text = "   ".join(f"{k}: {v}" for k, v in sorted(stats.items(), key=lambda kv: -kv[1])) or "ничего не найдено"
    if suspects:
        text += f"   ⚠ нераспознанных длинных чисел: {suspects} (проверьте: --check)"
    return text


def process_file(masker: Masker, src: Path, dst: Path, force: bool) -> int:
    if dst.resolve() == src.resolve():
        raise ValueError(f"выходной файл совпадает с исходным: {src}")
    if dst.exists() and not force:
        raise FileExistsError(f"уже существует: {dst} (добавьте --force, чтобы перезаписать)")
    dst.parent.mkdir(parents=True, exist_ok=True)
    enc = detect_encoding(src)
    tmp = dst.with_name("~" + dst.name)       # недописанный файл не выглядит готовым
    try:
        with open_text(src, "r", enc) as fin, open_text(tmp, "w", enc) as fout:
            lines = mask_stream(masker, fin, fout)
        os.replace(tmp, dst)
    finally:
        tmp.unlink(missing_ok=True)
    return lines


# ---------------------------------------------------------------- CLI

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="logmask",
        description="Маскирует пароли, токены, карты, email, телефоны и другие данные в логах. "
                    "Исходные файлы никогда не изменяются.",
        epilog="Примеры:" + __doc__.split("Примеры:", 1)[1],
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("paths", nargs="*", help="файлы или папки; «-» — читать из stdin")
    p.add_argument("-o", "--output", help="файл или папка для результата; «-» — в stdout")
    p.add_argument("-c", "--config", help="свой файл правил (по умолчанию rules.toml рядом со скриптом)")
    p.add_argument("--check", action="store_true",
                   help="ничего не записывать, только показать найденное (код выхода 1, если найдено)")
    p.add_argument("--max-report", type=int, default=50, help="сколько строк показывать в --check (50)")
    p.add_argument("--style", choices=["numbered", "plain", "hash"], help="вид меток (перекрывает конфиг)")
    p.add_argument("--strict", action="store_true",
                   help="маскировать и нераспознанные длинные числа как [NUM_1] (suspects.mode = mask)")
    p.add_argument("-f", "--force", action="store_true", help="перезаписывать существующие .masked файлы")
    p.add_argument("-q", "--quiet", action="store_true", help="без сводки")
    return p


def main(argv: list[str] | None = None) -> int:
    for s in (sys.stdout, sys.stderr):
        s.reconfigure(encoding="utf-8", errors="replace")
    args = build_parser().parse_args(argv)
    say = (lambda *a: None) if args.quiet else (lambda *a: print(*a, file=sys.stderr))

    try:
        cfg = Config.load(Path(args.config)) if args.config else Config.load()
    except Exception as e:
        print(f"ошибка в конфиге: {e}", file=sys.stderr)
        return EXIT_ERROR
    if args.style:
        cfg.style = args.style
    if args.strict:
        cfg.suspects = "mask"
    masker = Masker(cfg)

    paths = args.paths
    if not paths:
        if sys.stdin.isatty():
            build_parser().print_help()
            return EXIT_ERROR
        paths = ["-"]

    # ---- stdin -> stdout
    if paths == ["-"]:
        sys.stdin.reconfigure(encoding="utf-8", errors=ERRORS, newline="")
        if args.check:
            shown = [0]
            check_stream(masker, sys.stdin, "stdin", args.max_report, shown)
            stats, sus = masker.reset_stats()
            say(f"stdin — {fmt_stats(stats, sus)}")
            return EXIT_FOUND if stats else EXIT_OK
        sys.stdout.reconfigure(errors=ERRORS, newline="")
        mask_stream(masker, sys.stdin, sys.stdout)
        say(f"stdin — {fmt_stats(*masker.reset_stats())}")
        return EXIT_OK

    # ---- файлы и папки
    try:
        items = collect([Path(p) for p in paths], cfg)
    except FileNotFoundError as e:
        print(f"ошибка: {e}", file=sys.stderr)
        return EXIT_ERROR
    if not items:
        print("ошибка: подходящих файлов не найдено", file=sys.stderr)
        return EXIT_ERROR

    out = Path(args.output) if args.output and args.output != "-" else None
    total, total_sus, failed, shown = Counter(), 0, 0, [0]

    for src, root in items:
        try:
            if args.check:
                with open_text(src, "r", detect_encoding(src)) as f:
                    lines = check_stream(masker, f, str(src), args.max_report, shown)
                sys.stdout.flush()                 # сводка — после строк отчёта
                stats, sus = masker.reset_stats()
                say(f"{'!' if stats else '✔'} {src} — {lines} строк — {fmt_stats(stats, sus)}")
            elif args.output == "-":
                with open_text(src, "r", detect_encoding(src)) as f:
                    sys.stdout.reconfigure(errors=ERRORS, newline="")
                    lines = mask_stream(masker, f, sys.stdout)
                stats, sus = masker.reset_stats()
                say(f"✔ {src} — {lines} строк — {fmt_stats(stats, sus)}")
            else:
                dst = target_for(src, root, out, many=len(items) > 1)
                lines = process_file(masker, src, dst, args.force)
                stats, sus = masker.reset_stats()
                say(f"✔ {dst} — {lines} строк — {fmt_stats(stats, sus)}")
            total.update(stats)
            total_sus += sus
        except (OSError, ValueError) as e:
            failed += 1
            masker.reset_stats()
            print(f"✘ {src}: {e}", file=sys.stderr)

    if len(items) > 1:
        say(f"\nИтого: {len(items) - failed} из {len(items)} файлов — {fmt_stats(total, total_sus)}")
    if args.check and shown[0] > args.max_report:
        say(f"(показано {args.max_report} из {shown[0]} строк, см. --max-report)")

    if failed:
        return EXIT_ERROR
    if args.check and total:
        return EXIT_FOUND
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
