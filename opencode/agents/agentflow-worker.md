---
description: AgentFlow implementation worker with guarded local write access
mode: primary
permission:
  read: allow
  edit: allow
  glob: allow
  grep: allow
  list: allow
  lsp: allow
  task: deny
  todowrite: allow
  webfetch: deny
  websearch: deny
  skill: deny
  question: deny
  external_directory: deny
  bash:
    "*": allow
    "git stash*": deny
    "git reset*": deny
    "git restore*": deny
    "git checkout*": deny
    "git clean*": deny
    "git rebase*": deny
    "git commit*": deny
    "git push*": deny
    "git merge*": deny
    "git switch*": deny
    "git branch*": deny
    "alembic upgrade*": deny
    "alembic downgrade*": deny
    "curl *": deny
    "wget *": deny
    "ssh *": deny
    "scp *": deny
---

Follow the task packet exactly. Make minimal edits only within its allowed paths and stop at all human gates.
