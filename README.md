# leaked-key-lab

A secret scanner and a git pre-commit hook that stop API keys and private keys from being committed, so they never reach GitHub in the first place.

## Why I built it

In November 2026 Microsoft reported attackers searching GitHub for leaked app secrets and AI API keys. In one intrusion, an AI agent went from finding a key on GitHub to pulling secrets out of Azure Key Vault in about five minutes. No human team responds that fast, so the defence that matters most is the one that stops the key leaking at all. Deleting a leaked key from a repo afterwards does not help either: the key keeps working until it is revoked.

Maps to MITRE ATT&CK T1552.001, Unsecured Credentials: Credentials in Files.

## How it works

`secret-sniffer.ps1` walks a folder, including hidden files like `.env`, and checks each file against six key shapes: Groq, OpenAI-style, GitHub classic and fine-grained tokens, AWS access keys, and private key headers. It skips noise like `.venv`, `node_modules`, `.git` and binary files. Each hit is reported with the file, line and key type, and only the first eight characters of the key are shown, followed by `****`, so running the scanner never puts a full secret on screen. It exits with code 1 if anything is found, which is what lets the hook block a commit.

`hooks/check-staged.ps1` asks git which files are about to be committed and scans only those. `hooks/pre-commit` is the small shell script git runs on every commit, and it calls the check. If a key is found, the commit is refused.

## What testing taught me

My first version was a plain text search for prefixes like `sk-` and `gsk_`. Run across my own projects it flagged 18 files and every one was wrong: `sk-` appears inside ordinary words like "risk-" and "task-", and Python library folders are full of them. A scanner that cries wolf 18 times gets ignored, and then it misses the real key. So the patterns now match the shape of a key (prefix plus a minimum length, with a word boundary where it matters), and library folders and binaries are skipped.

I also stopped trusting empty results. Each time a scan came back clean, I planted a fake canary key and checked the scanner found it, so "no secrets found" meant the scanner worked, not that it was broken. My test set has three files that recreate the cases above: a key-shaped fake in a hidden `.env`, a README placeholder like `GROQ_API_KEY=...`, and a note containing "risk-management". The scanner flags only the first one.

With the hook installed, a clean commit goes through and a commit containing a fake key is blocked. `git log` afterwards shows the key never entered the history.

## Using it

Scan any folders:

```powershell
.\secret-sniffer.ps1 -Path C:\projects, C:\dev
```

Turn on the hook in a repo that contains the `hooks` folder:

```powershell
git config core.hooksPath hooks
```

## Known limits

It only knows six key shapes, so database passwords, Azure keys or Slack tokens get through. It reads files as they are on disk, not their full git history, so a key committed and later deleted needs a history scan. And the hook runs on the developer's machine, which means `git commit --no-verify` skips it and a fresh clone does not have it turned on. That is why this belongs alongside server-side protection like GitHub push protection, not instead of it.
