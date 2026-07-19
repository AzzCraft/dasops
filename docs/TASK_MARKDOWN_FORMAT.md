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
