"""Small shared parser for the documented six-column task table."""
import re
import shlex


def visible_lines(lines):
    fence = None
    for line in lines:
        marker = re.match(r'^\s{0,3}(`{3,}|~{3,})', line)
        if marker:
            token = marker.group(1)
            if fence is None:
                fence = token
            elif token[0] == fence[0] and len(token) >= len(fence) and not line[marker.end():].strip():
                fence = None
            yield ''
        else:
            yield line if fence is None else ''


def cells(line, *, decode=True):
    text = line.strip()
    if not (text.startswith('|') and text.endswith('|')):
        raise ValueError('task table row must start and end with a pipe')
    parts, current, slashes = [], '', 0
    for char in text[1:-1]:
        if char == '|' and slashes % 2 == 0:
            parts.append(current.strip())
            current = ''
        else:
            current += char
        slashes = slashes + 1 if char == '\\' else 0
    parts.append(current.strip())
    if len(parts) != 6:
        raise ValueError('task table requires exactly six columns; escape literal pipes')
    return [re.sub(r"\\([\\|])", r"\1", part) for part in parts] if decode else parts


def split_dependencies(value, known_ids=None):
    value = (value or '').strip()
    if not value or value == '-': return []
    lexer = shlex.shlex(value, posix=True)
    lexer.whitespace += ','
    lexer.whitespace_split = True
    lexer.commenters = ''
    tokens = list(lexer)
    if known_ids is not None and value in known_ids and len(tokens) > 1:
        if all(token in known_ids for token in tokens):
            raise ValueError('Ambiguous dependency; quote an ID containing spaces')
        return [value]
    return tokens


def validate_graph(rows):
    indexed = {parts[0]: parts for _, parts in rows if parts[0]}
    if len(indexed) != len(rows): raise ValueError('Invalid task graph: duplicate or empty task ID')
    remaining, children = {}, {key: [] for key in indexed}
    for key, parts in indexed.items():
        dependencies = set(split_dependencies(parts[4], indexed))
        for dependency in dependencies:
            if dependency not in indexed: raise ValueError(f'Invalid task graph: unknown dependency {dependency}')
            children[dependency].append(key)
        remaining[key] = len(dependencies)
    ready = [key for key, count in remaining.items() if count == 0]
    completed = 0
    while ready:
        key = ready.pop(); completed += 1
        for child in children[key]:
            remaining[child] -= 1
            if remaining[child] == 0: ready.append(child)
    if completed != len(indexed):
        raise ValueError('Invalid task graph: dependency cycle: ' + ', '.join(sorted(key for key, count in remaining.items() if count)[:8]))


def require_index_rows(rows):
    if not rows:
        raise ValueError('tasks.md missing canonical index rows')
    return rows


def table_rows(lines):
    visible = list(visible_lines(lines))
    # Recognize a task table before validating its columns, but do not confuse
    # a data row whose task ID is literally "Task ID" with another header.
    headers = [i for i, line in enumerate(visible)
               if (i == 0 or not visible[i - 1].lstrip().startswith('|'))
               and re.match(r'^\s*\|\s*Task ID\s*\|', line, re.I)]
    if len(headers) > 1:
        raise ValueError('multiple active task indexes are ambiguous')
    if not headers:
        return []
    header = headers[0]
    names = [part.casefold() for part in cells(visible[header])]
    if names[:4] != ["task id", "title", "owner", "status"] or names[4] not in {"depends on", "depends"} or names[5] not in {"verify gate", "gate"}:
        raise ValueError(f"invalid task table columns at line {header + 1}")
    if header + 1 >= len(visible) or not all(re.fullmatch(r":?-{3,}:?", part) for part in cells(visible[header + 1])):
        raise ValueError(f"missing task table separator at line {header + 2}")
    rows = []
    for i in range(header + 2, len(visible)):
        line = visible[i].strip()
        if not line.startswith('|'):
            break
        rows.append((i, cells(line)))
    validate_graph(rows)
    return rows


def task_files(repo_root):
    """Walk this checkout, excluding only Git-registered nested worktrees."""
    import os
    import ast
    import subprocess
    from pathlib import Path
    excluded = set()
    try:
        top = subprocess.run(["git", "rev-parse", "--show-toplevel"], cwd=repo_root, capture_output=True, text=True, check=True).stdout.strip()
        if Path(top).resolve() == repo_root.resolve():
            raw = subprocess.run(["git", "-c", "core.quotePath=false", "worktree", "list", "--porcelain"], cwd=repo_root, capture_output=True, text=True, check=True).stdout
            for field in raw.splitlines():
                if field.startswith("worktree "):
                    value = field[len("worktree "):]
                    if value.startswith('"'):
                        value = ast.literal_eval(value)
                    path = Path(value).resolve()
                    if path != repo_root.resolve() and path.is_relative_to(repo_root.resolve()):
                        excluded.add(path)
    except (OSError, ValueError, SyntaxError, subprocess.CalledProcessError):
        pass  # Non-Git products have no registered worktree exclusions.
    for directory, children, files in os.walk(repo_root, followlinks=False):
        children[:] = [name for name in children if (Path(directory) / name).resolve() not in excluded]
        if "tasks.md" in files:
            yield Path(directory) / "tasks.md"
