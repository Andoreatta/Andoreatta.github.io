#!/usr/bin/env python3
"""Import the GitBook-style Pentesting-Notes repository into this Hugo site.

The source notes live outside this repository. The importer is intentionally
one-way: it converts the source tree into `content/en/notes/`, rewrites links,
copies referenced screenshots, and adds Hugo front matter.

Usage:
    python3 scripts/import-notes.py
    python3 scripts/import-notes.py --source ~/Workspace/Pentesting-Notes

The root `content/en/notes/_index.md` is maintained by hand and is preserved
when the importer runs.
"""

from __future__ import annotations

import argparse
import html
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SOURCE = Path.home() / "Workspace" / "Pentesting-Notes"
CONTENT_ROOT = PROJECT_ROOT / "content" / "en" / "notes"
STATIC_IMAGES = PROJECT_ROOT / "static" / "images" / "notes"

DATE = "2026-10-30"

SKIP_DIRS = {
    ".git",
    ".gitbook",
    ".obsidian",
    ".vscode",
    "LainkusanagiOSCPLikeList",
    "node_modules",
    "resources",
}
SKIP_FILES = {"SUMMARY.md"}

SECTION_WEIGHTS = {
    "oscp-labs": 10,
    "active-directory": 20,
    "linux-privilege-escalation": 30,
    "windows-privilege-escalation": 40,
    "web-applications": 50,
    "web-applications/web-attacks": 30,
    "web-applications/web-technologies": 40,
    "protocols-and-services": 60,
    "utilities-scripts-and-payloads": 70,
    "bug-bounty-hunting": 80,
    "cloud-red-team": 90,
}

# Curated order derived from the old GitBook SUMMARY.md, plus newer material.
PAGE_WEIGHTS = {
    # Active Directory
    "active-directory/initial-access.md": 10,
    "active-directory/internal-enumeration-and-lateral-movement.md": 20,
    "active-directory/ntlm-relay.md": 30,
    "active-directory/kerberos-delegation.md": 40,
    "active-directory/adcs-attacks.md": 50,
    "active-directory/privilege-escalation-to-domain-admin-using-known-exploits.md": 60,
    "active-directory/domain-trusts.md": 70,
    "active-directory/CHECKLIST.md": 80,
    # Linux privilege escalation
    "linux-privilege-escalation/enumerating-attack-vectors.md": 10,
    "linux-privilege-escalation/privileged-groups.md": 20,
    "linux-privilege-escalation/environment-variables-abuse.md": 30,
    "linux-privilege-escalation/capabilities-abuse.md": 40,
    "linux-privilege-escalation/programs-jobs-and-services.md": 50,
    "linux-privilege-escalation/miscellaneous-techniques.md": 60,
    "linux-privilege-escalation/CHECKLIST.md": 70,
    # Windows privilege escalation
    "windows-privilege-escalation/enumerating-attack-vectors.md": 10,
    "windows-privilege-escalation/excessive-user-rights-abuse.md": 20,
    "windows-privilege-escalation/built-in-groups-abuse.md": 30,
    "windows-privilege-escalation/file-system-acls.md": 40,
    "windows-privilege-escalation/unquoted-service-paths.md": 50,
    "windows-privilege-escalation/user-account-control-uac-bypass.md": 60,
    "windows-privilege-escalation/living-off-the-land.md": 70,
    "windows-privilege-escalation/CHECKLIST.md": 80,
    # Web applications
    "web-applications/information-gathering.md": 10,
    "web-applications/fuzzing.md": 20,
    "web-applications/web-attacks/README.md": 30,
    "web-applications/web-technologies/README.md": 40,
    # Web attacks
    "web-applications/web-attacks/cross-site-scripting-xss.md": 10,
    "web-applications/web-attacks/csrf.md": 20,
    "web-applications/web-attacks/file-uploads.md": 30,
    "web-applications/web-attacks/nosql-injection.md": 40,
    "web-applications/web-attacks/json-web-tokens-jwts.md": 50,
    "web-applications/web-attacks/sql-injection.md": 60,
    "web-applications/web-attacks/ssrf.md": 70,
    "web-applications/web-attacks/oauth-attacks.md": 80,
    "web-applications/web-attacks/saml-attacks.md": 90,
    "web-applications/web-attacks/insecure-direct-object-references-idor.md": 100,
    "web-applications/web-attacks/os-command-injection.md": 110,
    "web-applications/web-attacks/web-cache-poisoning.md": 120,
    "web-applications/web-attacks/local-file-inclusion-lfi.md": 130,
    "web-applications/web-attacks/remote-file-inclusion-rfi.md": 140,
    "web-applications/web-attacks/xml-external-entities-xxe.md": 150,
    "web-applications/web-attacks/xpath-injection.md": 160,
    "web-applications/web-attacks/ldap-injection.md": 170,
    "web-applications/web-attacks/http-verb-tampering.md": 180,
    # Web technologies
    "web-applications/web-technologies/tomcat.md": 10,
    "web-applications/web-technologies/cgi-applications.md": 20,
    "web-applications/web-technologies/wordpress.md": 30,
    "web-applications/web-technologies/pdf-generators.md": 40,
    "web-applications/web-technologies/microsoft-iis.md": 50,
    "web-applications/web-technologies/webdav.md": 60,
    "web-applications/web-technologies/ibm-websphere.md": 70,
    "web-applications/web-technologies/sap-netweaver.md": 80,
    "web-applications/web-technologies/joomla.md": 90,
    "web-applications/web-technologies/drupal.md": 100,
    "web-applications/web-technologies/gitlab.md": 110,
    "web-applications/web-technologies/jenkins.md": 120,
    # Utilities
    "utilities-scripts-and-payloads/shells-and-payloads.md": 10,
    "utilities-scripts-and-payloads/metasploit-framework.md": 20,
    "utilities-scripts-and-payloads/file-transfers.md": 30,
    "utilities-scripts-and-payloads/pivoting-tunneling-port-forwarding.md": 40,
    "utilities-scripts-and-payloads/password-attacks.md": 50,
    # Lab field manual
    "oscp-labs/methodology.md": 10,
    "oscp-labs/commands.md": 20,
    "oscp-labs/patterns.md": 30,
    "oscp-labs/machine-index.md": 40,
    "oscp-labs/linux.md": 50,
    "oscp-labs/windows.md": 60,
    "oscp-labs/ad.md": 70,
    # Bug bounty
    "bug-bounty-hunting/bug-bounty-tools.md": 10,
    # Cloud red team
    "cloud-red-team/aws-cloud-red-teaming.md": 10,
    "cloud-red-team/azure-cloud-red-teaming.md": 20,
    "cloud-red-team/gcp-cloud-red-teaming.md": 30,
}

TITLE_OVERRIDES = {
    "active-directory/CHECKLIST.md": "Active Directory Checklist",
    "linux-privilege-escalation/CHECKLIST.md": "Linux Privilege Escalation Checklist",
    "windows-privilege-escalation/CHECKLIST.md": "Windows Privilege Escalation Checklist",
    "oscp-labs/machine-index.md": "OSCP Machine Index",
    "bug-bounty-hunting/README.md": "Bug Bounty Hunting",
    "protocols-and-services/README.md": "Protocols and Services",
    "utilities-scripts-and-payloads/README.md": "Utilities, Scripts and Payloads",
    "web-applications/README.md": "Web Applications",
    "oscp-labs/README.md": "Lab Field Manual",
    "cloud-red-team/README.md": "Cloud Red Team",
}

SECTION_INTROS = {
    "cloud-red-team": (
        "Operator notes for AWS, Azure, and GCP red teaming. The sections focus on "
        "enumeration, credential access, persistence, and the mistakes that make "
        "cloud identities exploitable."
    ),
}

SECTION_TAGS = {
    "active-directory": ["active-directory"],
    "linux-privilege-escalation": ["linux", "privilege-escalation"],
    "windows-privilege-escalation": ["windows", "privilege-escalation"],
    "web-applications": ["web"],
    "web-applications/web-attacks": ["web", "web-attacks"],
    "web-applications/web-technologies": ["web", "web-technologies"],
    "protocols-and-services": ["protocols", "services"],
    "utilities-scripts-and-payloads": ["utilities", "payloads"],
    "oscp-labs": ["oscp", "methodology"],
    "bug-bounty-hunting": ["bug-bounty"],
    "cloud-red-team": ["cloud", "red-team"],
}

PAGE_TAGS = {
    # Active Directory
    "active-directory/initial-access.md": ["initial-access", "enumeration"],
    "active-directory/internal-enumeration-and-lateral-movement.md": [
        "enumeration",
        "lateral-movement",
        "bloodhound",
    ],
    "active-directory/ntlm-relay.md": ["ntlm", "relay", "coercion"],
    "active-directory/kerberos-delegation.md": ["kerberos", "delegation"],
    "active-directory/adcs-attacks.md": ["adcs", "certificates"],
    "active-directory/privilege-escalation-to-domain-admin-using-known-exploits.md": [
        "privilege-escalation",
        "domain-admin",
        "exploits",
    ],
    "active-directory/domain-trusts.md": ["trusts", "domain-admin"],
    "active-directory/CHECKLIST.md": ["checklist"],
    # Linux
    "linux-privilege-escalation/enumerating-attack-vectors.md": ["enumeration", "sudo", "suid"],
    "linux-privilege-escalation/privileged-groups.md": ["groups", "sudo"],
    "linux-privilege-escalation/environment-variables-abuse.md": ["environment", "path-hijack"],
    "linux-privilege-escalation/capabilities-abuse.md": ["capabilities", "linux"],
    "linux-privilege-escalation/programs-jobs-and-services.md": ["services", "cron", "systemd"],
    "linux-privilege-escalation/miscellaneous-techniques.md": ["kernel", "container-escape"],
    "linux-privilege-escalation/CHECKLIST.md": ["checklist"],
    # Windows
    "windows-privilege-escalation/enumerating-attack-vectors.md": ["enumeration", "tokens"],
    "windows-privilege-escalation/excessive-user-rights-abuse.md": ["tokens", "privileges"],
    "windows-privilege-escalation/built-in-groups-abuse.md": ["groups", "privileges"],
    "windows-privilege-escalation/file-system-acls.md": ["acls", "services"],
    "windows-privilege-escalation/unquoted-service-paths.md": ["services", "path-hijack"],
    "windows-privilege-escalation/user-account-control-uac-bypass.md": ["uac", "bypass"],
    "windows-privilege-escalation/living-off-the-land.md": ["living-off-the-land", "lolbins"],
    "windows-privilege-escalation/CHECKLIST.md": ["checklist"],
    # Web attacks
    "web-applications/web-attacks/cross-site-scripting-xss.md": ["xss"],
    "web-applications/web-attacks/csrf.md": ["csrf"],
    "web-applications/web-attacks/file-uploads.md": ["file-upload"],
    "web-applications/web-attacks/nosql-injection.md": ["nosql", "injection"],
    "web-applications/web-attacks/json-web-tokens-jwts.md": ["jwt", "authentication"],
    "web-applications/web-attacks/sql-injection.md": ["sql-injection"],
    "web-applications/web-attacks/ssrf.md": ["ssrf"],
    "web-applications/web-attacks/oauth-attacks.md": ["oauth", "authentication"],
    "web-applications/web-attacks/saml-attacks.md": ["saml", "authentication"],
    "web-applications/web-attacks/insecure-direct-object-references-idor.md": ["idor", "authorization"],
    "web-applications/web-attacks/os-command-injection.md": ["command-injection"],
    "web-applications/web-attacks/web-cache-poisoning.md": ["cache-poisoning"],
    "web-applications/web-attacks/local-file-inclusion-lfi.md": ["lfi", "file-inclusion"],
    "web-applications/web-attacks/remote-file-inclusion-rfi.md": ["rfi", "file-inclusion"],
    "web-applications/web-attacks/xml-external-entities-xxe.md": ["xxe", "xml"],
    "web-applications/web-attacks/xpath-injection.md": ["xpath", "injection"],
    "web-applications/web-attacks/ldap-injection.md": ["ldap", "injection"],
    "web-applications/web-attacks/http-verb-tampering.md": ["http", "bypass"],
    # Web technologies
    "web-applications/web-technologies/tomcat.md": ["tomcat", "java"],
    "web-applications/web-technologies/cgi-applications.md": ["cgi"],
    "web-applications/web-technologies/wordpress.md": ["wordpress", "cms"],
    "web-applications/web-technologies/pdf-generators.md": ["pdf", "ssrf"],
    "web-applications/web-technologies/microsoft-iis.md": ["iis", "windows"],
    "web-applications/web-technologies/webdav.md": ["webdav", "iis"],
    "web-applications/web-technologies/ibm-websphere.md": ["websphere", "java"],
    "web-applications/web-technologies/sap-netweaver.md": ["sap", "java"],
    "web-applications/web-technologies/joomla.md": ["joomla", "cms"],
    "web-applications/web-technologies/drupal.md": ["drupal", "cms"],
    "web-applications/web-technologies/gitlab.md": ["gitlab", "cicd"],
    "web-applications/web-technologies/jenkins.md": ["jenkins", "cicd"],
    # Utilities
    "utilities-scripts-and-payloads/shells-and-payloads.md": ["shells", "payloads"],
    "utilities-scripts-and-payloads/metasploit-framework.md": ["metasploit"],
    "utilities-scripts-and-payloads/file-transfers.md": ["file-transfer"],
    "utilities-scripts-and-payloads/pivoting-tunneling-port-forwarding.md": [
        "pivoting",
        "tunneling",
        "port-forwarding",
    ],
    "utilities-scripts-and-payloads/password-attacks.md": ["password-attacks", "hashcat"],
    # OSCP labs
    "oscp-labs/methodology.md": ["methodology", "oscp"],
    "oscp-labs/commands.md": ["commands", "oscp"],
    "oscp-labs/patterns.md": ["patterns", "oscp"],
    "oscp-labs/machine-index.md": ["htb", "machine-index", "oscp"],
    "oscp-labs/linux.md": ["htb", "linux", "writeups"],
    "oscp-labs/windows.md": ["htb", "windows", "writeups"],
    "oscp-labs/ad.md": ["htb", "active-directory", "writeups"],
    # Other
    "bug-bounty-hunting/bug-bounty-tools.md": ["bug-bounty", "tools"],
    "web-applications/information-gathering.md": ["recon", "osint"],
    "web-applications/fuzzing.md": ["fuzzing", "ffuf"],
    "cloud-red-team/aws-cloud-red-teaming.md": ["aws", "cloud"],
    "cloud-red-team/azure-cloud-red-teaming.md": ["azure", "cloud"],
    "cloud-red-team/gcp-cloud-red-teaming.md": ["gcp", "cloud"],
}

# The working tree moved/removed a few pages after the old SUMMARY was written.
LINK_ALIASES = {
    "information-gathering.md": "web-applications/information-gathering.md",
}
CONTEXT_LINK_ALIASES = {
    ("oscp-labs", "CHECKLIST.md"): "active-directory/CHECKLIST.md",
}
ANCHOR_ALIASES = {
    ("oscp-labs/commands.md", "one-page-pre-flight"): "one-page-pre-flight--linux-host",
}
SAME_PAGE_LINK_ALIASES = {
    ("linux-privilege-escalation/CHECKLIST.md", "#writable-etcpasswd--etcshadow"):
        ("linux-privilege-escalation/enumerating-attack-vectors.md", "writable-etcpasswd--etcshadow"),
    ("linux-privilege-escalation/CHECKLIST.md", "#ldsopreload--universal-linker-hijack"):
        ("linux-privilege-escalation/enumerating-attack-vectors.md", "ldsopreload--universal-linker-hijack"),
    ("linux-privilege-escalation/CHECKLIST.md", "#linux-capabilities"):
        ("linux-privilege-escalation/enumerating-attack-vectors.md", "linux-capabilities"),
    ("linux-privilege-escalation/CHECKLIST.md", "#logrotate"):
        ("linux-privilege-escalation/enumerating-attack-vectors.md", "logrotate"),
    ("linux-privilege-escalation/CHECKLIST.md", "#systemd-unit-abuse"):
        ("linux-privilege-escalation/enumerating-attack-vectors.md", "systemd-unit-abuse"),
    ("linux-privilege-escalation/CHECKLIST.md", "#suid-shared-library-and-linker-abuse"):
        ("linux-privilege-escalation/enumerating-attack-vectors.md", "suid-shared-library-and-linker-abuse"),
}

LINK_RE = re.compile(r"(?<!!)\[([^\]]+)\]\(([^)\s]+)\)")
FENCE_RE = re.compile(r"^\s*(```|~~~)")
H1_RE = re.compile(r"^#\s+(.+?)\s*$")
EMOJI_PREFIX_RE = re.compile(
    r"^(?:[\U0001F000-\U0001FAFF\u2600-\u27BF\u2B00-\u2BFF\uFE0F]+\s*)+"
)


def eprint(*args: object) -> None:
    print(*args, file=sys.stderr)


def toml_string(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def clean_title(value: str) -> str:
    value = html.unescape(value).strip()
    value = EMOJI_PREFIX_RE.sub("", value)
    return value.strip()


def split_front_matter(text: str) -> str:
    if text.startswith("---"):
        match = re.match(r"^---\s*\n.*?\n---\s*\n", text, re.S)
        if match:
            return text[match.end() :]
    return text


def strip_leading_h2(body: str) -> str:
    """Drop a duplicated checklist heading at the top of the body."""
    lines = body.splitlines()
    in_fence = False
    for index, line in enumerate(lines):
        if FENCE_RE.match(line):
            in_fence = not in_fence
            continue
        if in_fence or not line.strip():
            continue
        if re.match(r"^##\s+\S", line):
            return "\n".join(lines[:index] + lines[index + 1 :])
        break
    return body


def promote_headings(body: str) -> str:
    """Move checklist phase headings up one level after removing the old H2."""
    lines = body.splitlines()
    in_fence = False
    out: list[str] = []
    for line in lines:
        if FENCE_RE.match(line):
            in_fence = not in_fence
        elif not in_fence:
            match = re.match(r"^(#{3,6})(\s+.*)$", line)
            if match:
                line = match.group(1)[1:] + match.group(2)
        out.append(line)
    return "\n".join(out)


def extract_h1(body: str) -> tuple[str | None, str]:
    """Remove the first level-one heading outside fenced code blocks."""
    lines = body.splitlines()
    in_fence = False
    title: str | None = None
    out: list[str] = []
    for line in lines:
        if FENCE_RE.match(line):
            in_fence = not in_fence
            out.append(line)
            continue
        if not in_fence and title is None:
            match = H1_RE.match(line)
            if match:
                title = clean_title(match.group(1))
                continue
        out.append(line)
    return title, "\n".join(out)


def url_for(rel: Path) -> str:
    parts = list(rel.with_suffix("").parts)
    if parts and parts[-1].lower() == "readme":
        parts = parts[:-1]
    parts = [part.lower() for part in parts]
    if not parts:
        return "/notes/"
    return "/notes/" + "/".join(parts) + "/"


def tags_for(rel: Path) -> list[str]:
    if rel.name.lower() == "readme.md":
        return list(SECTION_TAGS.get(rel.parent.as_posix(), []))

    tags: list[str] = []
    parts = rel.parts
    parent = rel.parent.as_posix()
    tags.extend(SECTION_TAGS.get(parent, []))
    if parts[0] == "web-applications":
        tags.append("web")
    if parts[0] in {"protocols-and-services"}:
        tags.append(rel.stem.lower())
    tags.extend(PAGE_TAGS.get(rel.as_posix(), []))

    seen: set[str] = set()
    result: list[str] = []
    for tag in tags:
        tag = tag.strip().lower()
        if tag and tag not in seen:
            seen.add(tag)
            result.append(tag)
    return result


def front_matter(
    title: str,
    weight: int,
    tags: list[str],
    *,
    toc: bool = True,
    task: bool = False,
    extra: dict[str, str] | None = None,
) -> str:
    lines = [
        "+++",
        f"title = {toml_string(title)}",
        f"date = {DATE}",
        "type = 'notes'",
        f"weight = {weight}",
        f"toc = {'true' if toc else 'false'}",
    ]
    if task:
        lines.append("task = true")
    if tags:
        lines.append("tags = [" + ", ".join(toml_string(tag) for tag in tags) + "]")
    if extra:
        for key, value in extra.items():
            lines.append(f"{key} = {value}")
    lines.append("+++")
    return "\n".join(lines) + "\n"


def convert_shortcodes(text: str) -> str:
    def hint_repl(match: re.Match[str]) -> str:
        level = match.group(1).strip().lower()
        inner = match.group(2).strip()
        return f"{{{{< hint {level} >}}}}\n{inner}\n{{{{< /hint >}}}}"

    text = re.sub(
        r"\{%\s*hint\s+style=\"([^\"]+)\"\s*%\}\s*\n(.*?)\n\s*\{%\s*endhint\s*%\}",
        hint_repl,
        text,
        flags=re.S,
    )
    text = re.sub(
        r"\{%\s*code[^%]*%\}\s*\n(.*?)\n\s*\{%\s*endcode\s*%\}",
        r"\1",
        text,
        flags=re.S,
    )
    return text


def copy_image(
    src: str,
    rel: Path,
    source: Path,
    warnings: list[str],
) -> tuple[str, int | None, int | None] | None:
    if not src or src.startswith(("http://", "https://", "data:")):
        return None
    image_path = Path(src)
    if not image_path.is_absolute():
        image_path = (source / rel.parent / image_path).resolve()
    if not image_path.exists():
        warnings.append(f"missing image in {rel}: {src}")
        return None

    STATIC_IMAGES.mkdir(parents=True, exist_ok=True)
    try:
        from PIL import Image

        destination = STATIC_IMAGES / (image_path.stem + ".webp")
        with Image.open(image_path) as image:
            width, height = image.size
            mode = "RGBA" if "A" in image.getbands() else "RGB"
            if image.mode != mode:
                image = image.convert(mode)
            image.save(destination, "WEBP", quality=82, method=6)
    except Exception as error:  # pragma: no cover - fallback for odd images
        warnings.append(f"could not convert {src} to WebP ({error}); copied original")
        destination = STATIC_IMAGES / image_path.name
        shutil.copy2(image_path, destination)
        return f"/images/notes/{destination.name}", None, None

    old_destination = STATIC_IMAGES / image_path.name
    if old_destination != destination and old_destination.exists():
        old_destination.unlink()

    return f"/images/notes/{destination.name}", width, height


def convert_figures(text: str, rel: Path, source: Path, warnings: list[str]) -> str:
    pattern = re.compile(
        r"<figure>\s*<img\s+src=\"([^\"]+)\"[^>]*>\s*"
        r"<figcaption>\s*<p>(.*?)</p>\s*</figcaption>\s*</figure>",
        re.S,
    )

    def repl(match: re.Match[str]) -> str:
        src, caption = match.group(1), match.group(2)
        image = copy_image(src, rel, source, warnings)
        if not image:
            return match.group(0)
        image_url, width, height = image
        caption = html.unescape(re.sub(r"<[^>]+>", "", caption)).strip()
        alt = html.escape(caption, quote=True)
        dimensions = ""
        if width and height:
            dimensions = f' width="{width}" height="{height}"'
        return (
            f'<figure class="notes-figure">\n'
            f'  <img src="{image_url}" alt="{alt}"{dimensions} loading="lazy">\n'
            f'  <figcaption>{html.escape(caption)}</figcaption>\n'
            f"</figure>"
        )

    return pattern.sub(repl, text)


def clean_entities(text: str) -> str:
    text = text.replace("&#x20;", " ").replace("&#x25;", "%")
    return text


def rewrite_links(
    text: str,
    rel: Path,
    file_map: dict[str, str],
    warnings: list[str],
) -> str:
    out: list[str] = []
    in_fence = False
    for line in text.splitlines():
        if FENCE_RE.match(line):
            in_fence = not in_fence
            out.append(line)
            continue
        if in_fence or "](" not in line:
            out.append(line)
            continue

        def repl(match: re.Match[str]) -> str:
            label, destination = match.group(1), match.group(2)
            if destination.startswith("#"):
                alias = SAME_PAGE_LINK_ALIASES.get((rel.as_posix(), destination))
                if alias:
                    target_rel, fragment = alias
                    if target_rel in file_map:
                        return f"[{label}]({file_map[target_rel]}#{fragment})"
                return match.group(0)
            if destination.startswith(("/", "http://", "https://", "mailto:")):
                return match.group(0)
            path, separator, fragment = destination.partition("#")
            if not path.lower().endswith(".md"):
                return match.group(0)

            resolved: str | None = None
            for base in (rel.parent, Path(".")):
                candidate = Path(os.path.normpath((base / path).as_posix())).as_posix()
                if candidate in file_map:
                    resolved = candidate
                    break
            if not resolved:
                alias = CONTEXT_LINK_ALIASES.get((rel.parent.as_posix(), path))
                alias = alias or LINK_ALIASES.get(path)
                if alias in file_map:
                    resolved = alias
            if not resolved:
                warnings.append(f"broken link in {rel}: {destination}")
                return match.group(0)

            url = file_map[resolved]
            if separator:
                fragment = ANCHOR_ALIASES.get((resolved, fragment), fragment)
                url += "#" + fragment
            return f"[{label}]({url})"

        out.append(LINK_RE.sub(repl, line))
    return "\n".join(out)


def git_show(source: Path, rel: str) -> str | None:
    try:
        result = subprocess.run(
            ["git", "-C", str(source), "show", f"HEAD:{rel}"],
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    return result.stdout


def section_title(rel: Path) -> str:
    override = TITLE_OVERRIDES.get(rel.as_posix())
    if override:
        return override
    return clean_title(rel.name.replace("-", " ").title())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source",
        type=Path,
        default=DEFAULT_SOURCE,
        help=f"Pentesting-Notes checkout (default: {DEFAULT_SOURCE})",
    )
    args = parser.parse_args()
    source = args.source.expanduser().resolve()
    if not source.is_dir():
        eprint(f"source directory not found: {source}")
        return 1

    warnings: list[str] = []
    source_files: list[Path] = []
    section_dirs: set[Path] = set()

    for root, dirs, files in os.walk(source):
        root_path = Path(root)
        dirs[:] = [
            name
            for name in sorted(dirs)
            if name not in SKIP_DIRS and not name.startswith(".")
        ]
        md_files = [name for name in sorted(files) if name.endswith(".md")]
        if md_files:
            rel_dir = root_path.relative_to(source)
            if rel_dir != Path("."):
                section_dirs.add(rel_dir)
        for name in md_files:
            rel = (root_path / name).relative_to(source)
            if rel.name in SKIP_FILES or rel.as_posix() == "README.md":
                continue
            source_files.append(rel)

    file_map = {rel.as_posix(): url_for(rel) for rel in source_files}

    # Preserve the hand-written landing page.
    root_index = CONTENT_ROOT / "_index.md"
    root_index_content = root_index.read_text(encoding="utf-8") if root_index.exists() else None

    if CONTENT_ROOT.exists():
        shutil.rmtree(CONTENT_ROOT)
    CONTENT_ROOT.mkdir(parents=True)
    if root_index_content is not None:
        root_index.write_text(root_index_content, encoding="utf-8")

    written = 0
    for rel in source_files:
        if rel.name == "README.md":
            continue
        raw = (source / rel).read_text(encoding="utf-8")
        body = split_front_matter(raw)
        body = body.replace("S# Machine Index", "# Machine Index", 1)
        body = convert_shortcodes(body)
        body = convert_figures(body, rel, source, warnings)
        body = clean_entities(body)
        body = body.replace('<mark style="color:red;">', "<mark>")

        title, body = extract_h1(body)
        title = TITLE_OVERRIDES.get(rel.as_posix(), title)
        if not title:
            title = clean_title(rel.stem.replace("-", " ").title())
        title = clean_title(title)

        task = rel.name.lower() == "checklist.md"
        if task:
            body = strip_leading_h2(body)
            body = promote_headings(body)

        body = rewrite_links(body, rel, file_map, warnings).strip("\n") + "\n"
        weight = PAGE_WEIGHTS.get(rel.as_posix(), 500)
        meta = front_matter(
            title,
            weight,
            tags_for(rel),
            toc=True,
            task=task,
        )

        out_rel = rel
        if rel.name.lower() == "checklist.md":
            out_rel = rel.with_name("checklist.md")
        destination = CONTENT_ROOT / out_rel
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(meta + "\n" + body.lstrip("\n"), encoding="utf-8")
        written += 1

    # Section index pages.
    for rel_dir in sorted(section_dirs, key=lambda p: p.as_posix()):
        readme_rel = rel_dir / "README.md"
        raw: str | None = None
        readme_path = source / readme_rel
        if readme_path.exists():
            raw = readme_path.read_text(encoding="utf-8")
        elif (fallback := git_show(source, readme_rel.as_posix())) is not None:
            raw = fallback
            warnings.append(f"used git HEAD README for deleted {readme_rel.as_posix()}")
        if raw is not None:
            body = split_front_matter(raw)
            body = convert_shortcodes(body)
            body = convert_figures(body, readme_rel, source, warnings)
            body = clean_entities(body)
            body = body.replace('<mark style="color:red;">', "<mark>")
            title, body = extract_h1(body)
            title = TITLE_OVERRIDES.get(readme_rel.as_posix(), title)
            if not title:
                title = section_title(rel_dir)
            title = clean_title(title)
            body = rewrite_links(body, readme_rel, file_map, warnings)
        else:
            title = section_title(rel_dir)
            body = SECTION_INTROS.get(rel_dir.as_posix(), "")

        weight = SECTION_WEIGHTS.get(rel_dir.as_posix(), 500)
        meta = front_matter(
            title,
            weight,
            tags_for(readme_rel),
            toc=False,
        )
        destination = CONTENT_ROOT / rel_dir / "_index.md"
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(meta + "\n" + body.strip("\n") + "\n", encoding="utf-8")
        written += 1

    print(f"Imported {written} files into {CONTENT_ROOT.relative_to(PROJECT_ROOT)}")
    if warnings:
        print("\nWarnings:")
        for warning in warnings:
            print(f"  - {warning}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
