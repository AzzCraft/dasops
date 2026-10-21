# Task Markdown Format

`tasks.md` is the canonical task index for a change folder.

## Required Table Columns

- `Task ID`
- `Title`
- `Owner`
- `Status`
- `Depends on`
- `Verify gate`

## Rules

- The canonical table must live in `openspec/changes/<change-id>/tasks.md`.
- Task IDs are stable and sequential.
- Each task must carry a verify gate command.
- Worker-facing detail sections may exist below the table, but must not contradict the table.

## Invalid Shapes

- Any stray `tasks.md` outside `openspec/changes/<change-id>/tasks.md`
- Missing task index table
- Missing verify gate column

## Parser and identifier rules

Change/task IDs may contain Unicode and internal spaces, but not path separators,
`.` / `..`, or control characters. Quote a dependency ID containing spaces in the
`Depends on` cell (for example, `"任务 一"`); separate multiple IDs with commas or
spaces. Quote each ambiguous ID rather than relying on whitespace splitting.
An index has exactly six cells; escape a literal pipe in a title as `\|`.
Tables and task-detail headings inside fenced examples are ignored. Keep one
active index table, and use the exact task ID in its detail heading.
When one declared ID prefixes another (`build` and `build app`), detail lookup
matches the longest declared ID before interpreting the remaining heading title.
CLI owner labels use the same canonical form for claim, renew and reclaim:
spaces and unsupported characters become hyphens (`Worker A` → `Worker-A`).
The SDK requires the canonical owner value. The task's Verify gate may run any
nonempty command; its filename need not contain the word `verify`.
