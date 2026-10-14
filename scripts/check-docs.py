#!/usr/bin/env python3
"""Validate local Markdown navigation and public source-package hygiene."""
from pathlib import Path
import re
import sys
import unicodedata
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]
LINK = re.compile(r'\]\(([^\s)]+)(?:\s+"[^"]*")?\)')
BUILD = re.compile(r'\bv\d{2,3}\b(?!\.)', re.IGNORECASE)
RETIRED = re.compile(r'(?:review-v\d|repair-v\d|validation-v\d)', re.IGNORECASE)
OBSOLETE_FIXTURE = re.compile(r'(?:\.golden(?:\.|$)|prior[-_]contract|prior[-_]expected|(?:^|[/_.-])v1[._-]\d|v120)', re.IGNORECASE)
NONRELEASE_HEADING = re.compile(
    r'^#{1,6}\s+(?:remaining work|future work|future improvements|roadmap|backlog|internal revisions?)\b',
    re.IGNORECASE,
)


def anchors(text):
    result, counts = set(), {}
    fenced = False
    for line in text.splitlines():
        if re.match(r'^\s*(```|~~~)', line):
            fenced = not fenced
            continue
        if fenced:
            continue
        match = re.match(r'^#{1,6}\s+(.+?)\s*#*$', line)
        if not match:
            continue
        title = re.sub(r'<[^>]+>', '', match[1]).lower()
        title = re.sub(r'\[([^]]+)\]\([^)]*\)', r'\1', title)
        slug = ''.join(c for c in title if c in ' -_' or unicodedata.category(c)[0] in 'LN')
        slug = slug.replace(' ', '-')
        count = counts.get(slug, 0)
        counts[slug] = count + 1
        result.add(slug if count == 0 else f'{slug}-{count}')
    result.update(re.findall(r'<a\s+(?:id|name)=["\']([^"\']+)', text))
    return result


def main():
    errors, links = [], 0
    documents = sorted(ROOT.rglob('*.md'))
    expected = {'README.md', 'ansible_role/openstack_instance_exporter/README.md'}
    actual = {p.relative_to(ROOT).as_posix() for p in documents}
    if actual != expected:
        errors.append(f'Markdown inventory must match the exporter and role guides: missing={sorted(expected - actual)}, extra={sorted(actual - expected)}')
    for path in ROOT.rglob('*'):
        relative_path = path.relative_to(ROOT).as_posix()
        if RETIRED.search(relative_path) or OBSOLETE_FIXTURE.search(relative_path):
            errors.append(f'{path.relative_to(ROOT)}: obsolete release or internal review artifact')
    for path in documents:
        text = path.read_text()
        relative = path.relative_to(ROOT)
        for number, line in enumerate(text.splitlines(), 1):
            if NONRELEASE_HEADING.search(line):
                errors.append(f'{relative}:{number}: non-release planning section')
            if BUILD.search(line) or RETIRED.search(line):
                errors.append(f'{relative}:{number}: internal build reference')
        # Ignore examples of Markdown syntax inside fenced code blocks.
        prose = re.sub(r'^\s*(```|~~~).*?^\s*\1\s*$', '', text, flags=re.M | re.S)
        for match in LINK.finditer(prose):
            url = match[1]
            if re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*:', url) or url.startswith('//'):
                continue
            target, _, fragment = unquote(url).partition('#')
            destination = (path.parent / target).resolve() if target else path
            links += 1
            if not destination.is_relative_to(ROOT):
                errors.append(f'{relative}: link escapes source package: {url}')
            elif not destination.exists():
                errors.append(f'{relative}: missing link target: {url}')
            elif fragment and destination.suffix == '.md' and fragment not in anchors(destination.read_text()):
                errors.append(f'{relative}: missing heading: {url}')
    if errors:
        print('\n'.join(errors))
        return 1
    print(f'Documentation: {len(documents)} Markdown files, {links} local links; no broken targets or internal build references.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
