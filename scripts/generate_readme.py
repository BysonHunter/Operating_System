#!/usr/bin/env python3
"""Generate the root readme.md from the current repository contents."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from urllib.parse import quote


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "readme.md"

EXCLUDED_DIRS = {
    ".git",
    ".idea",
    ".vscode",
    "__pycache__",
    ".pytest_cache",
}

EXCLUDED_FILES = {
    OUTPUT,
    ROOT / ".DS_Store",
}

TOP_LEVEL_DESCRIPTIONS = {
    "ИВТ": "09.03.01 «Информатика и вычислительная техника»",
    "КБ": "10.05.01 «Компьютерная безопасность»",
    "ПИ": "09.03.04 «Программная инженерия»",
}

DOCUMENT_EXTENSIONS = {
    ".md",
    ".pdf",
    ".doc",
    ".docx",
    ".ppt",
    ".pptx",
    ".xls",
    ".xlsx",
    ".csv",
    ".txt",
}

IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp"}

FORMAT_LABELS = {
    ".md": "Markdown",
    ".pdf": "PDF",
    ".doc": "Word",
    ".docx": "Word",
    ".ppt": "PowerPoint",
    ".pptx": "PowerPoint",
    ".xls": "Excel",
    ".xlsx": "Excel",
    ".csv": "CSV",
    ".txt": "Текст",
    ".png": "PNG",
    ".jpg": "JPEG",
    ".jpeg": "JPEG",
    ".gif": "GIF",
    ".svg": "SVG",
    ".webp": "WebP",
    ".py": "Python",
    ".yml": "YAML",
    ".yaml": "YAML",
}


def sort_key(path: Path) -> tuple[str, str]:
    return (path.name.casefold(), path.as_posix().casefold())


def is_excluded(path: Path) -> bool:
    if path in EXCLUDED_FILES:
        return True
    return any(part in EXCLUDED_DIRS for part in path.relative_to(ROOT).parts)


def directories() -> list[Path]:
    result = [ROOT]
    result.extend(
        sorted(
            (path for path in ROOT.rglob("*") if path.is_dir() and not is_excluded(path)),
            key=lambda path: (
                len(path.relative_to(ROOT).parts),
                path.relative_to(ROOT).as_posix().casefold(),
            ),
        )
    )
    return result


def files_in(directory: Path) -> list[Path]:
    return sorted(
        (
            path
            for path in directory.iterdir()
            if path.is_file() and not is_excluded(path)
        ),
        key=sort_key,
    )


def subdirectories_in(directory: Path) -> list[Path]:
    return sorted(
        (
            path
            for path in directory.iterdir()
            if path.is_dir() and not is_excluded(path)
        ),
        key=sort_key,
    )


def relative_url(path: Path) -> str:
    relative = path.relative_to(ROOT).as_posix()
    return "./" + quote(relative, safe="/._-()")


def markdown_title(path: Path) -> str | None:
    if path.suffix.casefold() != ".md":
        return None

    try:
        with path.open("r", encoding="utf-8-sig", errors="replace") as source:
            in_fence = False
            for index, line in enumerate(source):
                if index >= 250:
                    break
                stripped = line.strip()
                if stripped.startswith(("```", "~~~")):
                    in_fence = not in_fence
                    continue
                if in_fence:
                    continue
                match = re.match(r"^#\s+(.+?)\s*$", stripped)
                if match:
                    return re.sub(r"\s+#+$", "", match.group(1)).strip()
    except OSError:
        return None

    return None


def humanized_stem(path: Path) -> str:
    title = markdown_title(path)
    if title:
        return title
    return re.sub(r"[_-]+", " ", path.stem).strip() or path.name


def format_label(path: Path) -> str:
    return FORMAT_LABELS.get(path.suffix.casefold(), path.suffix.lstrip(".").upper() or "Файл")


def count_repository() -> tuple[int, int, int, int]:
    dirs = [path for path in directories() if path != ROOT]
    files = [
        path
        for path in ROOT.rglob("*")
        if path.is_file() and not is_excluded(path)
    ]
    documents = sum(path.suffix.casefold() in DOCUMENT_EXTENSIONS for path in files)
    images = sum(path.suffix.casefold() in IMAGE_EXTENSIONS for path in files)
    return len(dirs), len(files), documents, images


def tree_lines(directory: Path, prefix: str = "") -> list[str]:
    children = subdirectories_in(directory) + files_in(directory)
    lines: list[str] = []
    for index, child in enumerate(children):
        last = index == len(children) - 1
        branch = "└── " if last else "├── "
        label = child.name + ("/" if child.is_dir() else "")
        lines.append(prefix + branch + label)
        if child.is_dir():
            extension = "    " if last else "│   "
            lines.extend(tree_lines(child, prefix + extension))
    return lines


def render_file_table(items: list[Path]) -> list[str]:
    lines = [
        "| Файл | Содержание | Формат |",
        "|---|---|---|",
    ]
    for path in items:
        lines.append(
            f"| [{path.name}]({relative_url(path)}) | {humanized_stem(path)} | {format_label(path)} |"
        )
    return lines


def render_directory_section(directory: Path) -> list[str]:
    relative = directory.relative_to(ROOT)
    title = "Корень репозитория" if directory == ROOT else relative.as_posix()
    children = subdirectories_in(directory)
    items = files_in(directory)
    lines = [f"### {title}", ""]

    if children:
        lines.extend(["**Подкаталоги**", ""])
        for child in children:
            child_relative = child.relative_to(ROOT).as_posix()
            description = TOP_LEVEL_DESCRIPTIONS.get(child.name, "Материалы раздела")
            lines.append(f"- [{child.name}]({relative_url(child)}) — {description}; `{child_relative}/`")
        lines.append("")

    if items:
        image_items = [item for item in items if item.suffix.casefold() in IMAGE_EXTENSIONS]
        regular_items = [item for item in items if item not in image_items]

        if regular_items:
            lines.extend(["**Файлы**", ""])
            lines.extend(render_file_table(regular_items))
            lines.append("")

        if image_items:
            lines.extend(
                [
                    f"<details>",
                    f"<summary>Изображения: {len(image_items)}</summary>",
                    "",
                ]
            )
            lines.extend(render_file_table(image_items))
            lines.extend(["", "</details>", ""])

    if not children and not items:
        lines.extend(["Каталог пока не содержит материалов.", ""])

    return lines


def generate() -> str:
    directory_count, file_count, document_count, image_count = count_repository()
    top_level = [
        path
        for path in subdirectories_in(ROOT)
        if path.name not in {"scripts", ".github"}
    ]

    lines = [
        "# Операционные системы",
        "",
        "Учебно-методические материалы по дисциплине **«Операционные системы»**: лекции, практические и контрольные работы, рабочие программы и фонды оценочных средств.",
        "",
        "> Этот файл формируется автоматически из текущей структуры репозитория. Не редактируйте его вручную: изменения будут заменены при следующем запуске генератора.",
        "",
        "## Направления подготовки",
        "",
        "| Каталог | Направление |",
        "|---|---|",
    ]

    for path in top_level:
        description = TOP_LEVEL_DESCRIPTIONS.get(path.name, "Материалы курса")
        lines.append(f"| [{path.name}]({relative_url(path)}) | {description} |")

    lines.extend(
        [
            "",
            "## Состав репозитория",
            "",
            f"- каталогов: **{directory_count}**;",
            f"- файлов: **{file_count}**;",
            f"- учебных документов: **{document_count}**;",
            f"- изображений и схем: **{image_count}**.",
            "",
            "## Структура каталогов",
            "",
            "```text",
            "Operating_System/",
        ]
    )
    lines.extend(tree_lines(ROOT))
    lines.extend(["```", "", "## Содержание каталогов", ""])

    for directory in directories():
        lines.extend(render_directory_section(directory))

    lines.extend(
        [
            "## Как обновляется этот файл",
            "",
            "После изменения содержимого ветки `main` GitHub Actions запускает `scripts/generate_readme.py`. Если структура или набор файлов изменились, workflow создаёт новый `readme.md` и фиксирует его отдельным коммитом.",
            "",
            "Локальная генерация:",
            "",
            "```bash",
            "python scripts/generate_readme.py",
            "```",
            "",
            "Проверка актуальности без изменения файла:",
            "",
            "```bash",
            "python scripts/generate_readme.py --check",
            "```",
            "",
            "## Правила безопасной работы",
            "",
            "> Все действия по настройке, диагностике и проверке безопасности выполняются только в разрешённой учебной среде. Воздействие на сторонние системы и сети запрещено.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="return a non-zero status when readme.md is out of date",
    )
    args = parser.parse_args()

    generated = generate()
    current = OUTPUT.read_text(encoding="utf-8") if OUTPUT.exists() else ""

    if args.check:
        if current == generated:
            print("readme.md is up to date")
            return 0
        print("readme.md is out of date", file=sys.stderr)
        return 1

    if current == generated:
        print("readme.md is already up to date")
        return 0

    OUTPUT.write_text(generated, encoding="utf-8", newline="\n")
    print("readme.md updated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
