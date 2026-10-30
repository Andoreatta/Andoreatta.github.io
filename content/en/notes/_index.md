+++
title = 'Andoreatta Pentesting Notes and Methodology'
description = 'Andoreatta pentesting notes and methodology: commands, privilege escalation, web attacks, protocols, and lab writeups.'
date = 2026-10-30
type = 'notes'
weight = 0
toc = false
credit = "These notes began as an adaptation of [sfoffo's Pentesting Notes](https://notes.sfoffo.com/) and have since been substantially expanded and reworked. Credit and thanks to sfoffo for the original material and inspiration."
+++

Personal field notes for penetration testing, with an **OSCP** study track. The
goal is practical recall: exact commands, prerequisites, and the edge cases that
decide whether a technique works in a lab or on a real engagement.

{{< hint danger >}}
All techniques here are for **authorized** labs, CTFs, and exam environments only. Never test against systems without explicit written permission.
{{< /hint >}}

## How to use these notes

Each section card below says what the section covers and how many pages it holds. Use it to choose a track before you start reading.

- **Studying a topic?** Start with the section map below: Active Directory, Linux or Windows privilege escalation, Web Applications, or Protocols and Services.
- **Need a command fast?** Use the [Command Checklist](/notes/oscp-labs/commands/) — phase-by-phase, copy-paste templates with placeholders.
- **Stuck on a box?** Use the [Lab Field Manual](/notes/oscp-labs/) — per-machine edge cases, a [pattern library](/notes/oscp-labs/patterns/), and a [machine index](/notes/oscp-labs/machine-index/).
- **Planning an engagement or the exam?** Start with the [Pentesting Methodology](/notes/oscp-labs/methodology/).
- **Enumerating?** The [Information Gathering](/notes/web-applications/information-gathering/) page covers the first pass; the `Enumerating Attack Vectors` pages are checklists.
- **Looking for a term or command?** Use the search in the header. It indexes the full text of every note; the [tag index](/tags/) groups pages by topic.

Commands use placeholders such as `<IP>`, `<USER>`, and `$TARGET`. Replace them;
never paste a placeholder into a live target.

## Conventions

- `$TARGET` / `<IP>` — target address; `$ATTACKER` / `<LHOST>` — your attacker address.
- Commands are shown for Linux; adapt paths and package names on other distributions.
- "Exam note" callouts highlight behaviour that commonly differs between lab boxes and the exam (timeouts, lockouts, egress filtering, AV).
- Hashcat modes and tool names are checked against current tool releases (NetExec replaces CrackMapExec; Impacket scripts use the `impacket-` prefix).

## Legal

These notes are a study aid, not an authorization. You are responsible for
staying within the scope of your engagement, lab, or exam. The notes are
published in English only.
