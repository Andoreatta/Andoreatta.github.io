+++
title = 'Lab Field Manual'
description = 'Methodology, command checklist, pattern library, machine index, and HTB lab notes.'
date = 2026-10-30
type = 'notes'
weight = 10
toc = false
tags = ['oscp', 'methodology']
credit = "Box selection: [Lainkusanagi's OSCP-like list](https://docs.google.com/spreadsheets/d/18weuz_Eeynr6sXFQ87Cd5F0slOj9Z6rt/). Credit for the list is Lainkusanagi's; the annotations are mine."
+++

Worked examples from the **OSCP-like HTB list**, organised as a field manual rather than a walkthrough collection. The commands, patterns and methodology are generic pentesting material — OSCP is one application of them, not the frame.

{{< hint warning >}}
**Spoilers ahead.** The machine pages describe intended and common unintended paths. Attempt each box first, then compare methodology. Only test systems you are authorized to test.
{{< /hint >}}

{{< hint info >}}
**A companion to the list, not a replacement.** The [machine index](/notes/oscp-labs/machine-index/)
and [pattern library](/notes/oscp-labs/patterns/) are meant to sit next to
[Lainkusanagi's list](https://docs.google.com/spreadsheets/d/18weuz_Eeynr6sXFQ87Cd5F0slOj9Z6rt/) —
open them when you are stuck mid-box in exam practice or in a practice CTF, or
when you want the technique behind a path you already found. Try the box first;
they work as a check, not a shortcut.
{{< /hint >}}

**No spoilers?** Every machine page names the foothold, the privesc, and often
the CVE. If you want to solve boxes unaided, stay out of this section and use
the neutral tracks instead — [Methodology](/notes/oscp-labs/methodology/),
[Command Checklist](/notes/oscp-labs/commands/), and the
[Linux](/notes/linux-privilege-escalation/), [Windows](/notes/windows-privilege-escalation/),
[Active Directory](/notes/active-directory/), [Web](/notes/web-applications/)
and [Protocols and Services](/notes/protocols-and-services/) notes. Those cover
pentesting technique and recall for any target, not one lab.

## The five layers

| Layer | Use it when… | Page |
| ----- | ------------ | ---- |
| **Methodology** | You need the order of operations, a decision gate, or the reporting structure | [Pentesting Methodology](/notes/oscp-labs/methodology/) |
| **Command checklist** | You know what to do and need the exact command with placeholders | [Command Checklist](/notes/oscp-labs/commands/) |
| **Pattern library** | You need to recognise a situation and choose a technique | [Pattern Library](/notes/oscp-labs/patterns/) |
| **Machine index** | You want to revise, tick off rooted boxes, or pick a box by technique | [Machine Index](/notes/oscp-labs/machine-index/) |
| **Machine pages** | You are stuck on a specific box and want the non-obvious step | [Linux](/notes/oscp-labs/linux/) · [Windows](/notes/oscp-labs/windows/) · [Active Directory](/notes/oscp-labs/ad/) |

## How to use this section

1. **New target / new engagement:** start with [Methodology](/notes/oscp-labs/methodology/) Phase 0–2, run the [pre-flight](/notes/oscp-labs/commands/#one-page-pre-flight--linux-host), and keep the [command checklist](/notes/oscp-labs/commands/) open.
2. **Stuck mid-box:** skim the [pattern library](/notes/oscp-labs/patterns/) phase for your situation (foothold, privesc, AD), then open the matching machine entry.
3. **Revising:** use the [machine index](/notes/oscp-labs/machine-index/) — read the row, explain the path aloud, then check the machine page.
4. **After rooting:** add the technique to your notes and update the machine's `Done` tick. If you found a new edge case, add it to the machine page under the same structure (Path / Edge cases / Commands / Notes).

## Machine pages at a glance

| Page | Scope | Machines |
| ---- | ----- | -------- |
| [Linux](/notes/oscp-labs/linux/) | Standalone Linux boxes | 39 |
| [Windows](/notes/oscp-labs/windows/) | Standalone Windows boxes | 18 |
| [Active Directory](/notes/oscp-labs/ad/) | AD sets, assumed-breach chains, plus 3 non-AD boxes | 16 (+3) |
| [Machine Index](/notes/oscp-labs/machine-index/) | One-line path + tool/CVE for every box, with study tracks | 76 |

## Recurring reflexes

* **Full port scan + UDP** before service enumeration — footholds hide on 4555, 61616, 22022, 1337, 8765 and 161/udp.
* **Vhosts before directories** — the IP root is often a decoy; a 403 is a finding.
* **Credential reuse** across every service, including DB passwords, configs, `.git` history and mail.
* **Privilege escalation order:** `sudo -l` → SUID/capabilities → cron/timers → groups → credentials → kernel.
* **Windows:** `whoami /priv` → service ACLs → stored creds → token abuse → LSASS/SAM/NTDS → kernel.
* **AD:** any account → BloodHound → Kerberos roast/ACL → delegation/ADCS → DCSync; sync the clock first.
* **Stage payloads** when the target is Java/Groovy/PHP-FPM — pipes and quotes get mangled.
* **Record the failed path and why**; that is what stops you repeating it under time pressure.

## Sources and accuracy

Each machine entry ends with the writeup(s) used. Research was cross-checked against public writeups (0xdf, Ippsec, HackTricks, HTB official) and local tool versions where possible. Items that could not be verified are marked **(unverified)**. If a box is retired, patched, or you find a better path, update the entry.

Box names come from [Lainkusanagi's OSCP-like list](https://docs.google.com/spreadsheets/d/18weuz_Eeynr6sXFQ87Cd5F0slOj9Z6rt/),
and only from its Hack The Box column — this section is HTB-only. These pages are
a snapshot, not a mirror: the sheet may gain boxes that are not covered here, and
the pattern library is written by hand, so it is not re-cut when the list changes.
Proving Grounds boxes will be added if I get access to the platform or plan an
OSCP attempt.
