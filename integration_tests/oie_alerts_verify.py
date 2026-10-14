#!/usr/bin/env python3
"""Fail-closed native verification of the shipped OIE policy.

Temporary native rules and fixtures are test artifacts, not deployment files.
No live metrics are injected, and no PromQL is evaluated by this Python program.
"""
from __future__ import annotations
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time


NATIVE_PARTS = 2
NATIVE_OUTPUT_LIMIT = 200000
NATIVE_TEMPLATE_ERRORS = re.compile(r'error (?:executing|expanding) template|<error expanding|%!|panic:', re.I)


def case_assertions(case):
    return len(case.get('promql_expr_test', [])) + len(case.get('alert_rule_test', []))


def partition_cases(cases):
    """Balance independent test groups without changing any input or assertion."""
    if not cases:
        raise ValueError('Native verification requires at least one scenario')
    parts = [[] for _ in range(min(NATIVE_PARTS, len(cases)))]
    loads = [0] * len(parts)
    weights = []
    for case in cases:
        checks = case.get('promql_expr_test', []) + case.get('alert_rule_test', [])
        weights.append(max((sum(int(amount) * {'s': 1, 'm': 60, 'h': 3600, 'd': 86400}[unit]
                                for amount, unit in re.findall(r'(\d+)([smhd])', str(check['eval_time'])))
                            for check in checks), default=0))
    for index in sorted(range(len(cases)), key=lambda i: (-weights[i], i)):
        target = min(range(len(parts)), key=lambda p: (loads[p], p))
        parts[target].append(index)
        loads[target] += weights[index]
    return [{'indices': sorted(indices), 'cases': [cases[i] for i in sorted(indices)]}
            for indices in parts]


def validate_parts(cases, parts):
    """Fail closed if scheduling drops, duplicates or replaces a test group."""
    if len(parts) != min(NATIVE_PARTS, len(cases)) or not cases:
        raise ValueError('Native scenario partition count differs from the complete inventory')
    indices = [i for part in parts for i in part['indices']]
    if sorted(indices) != list(range(len(cases))):
        raise ValueError('Native scenario partitions do not cover every scenario exactly once')
    for part in parts:
        if not part['indices'] or len(part['indices']) != len(part['cases']):
            raise ValueError('Native scenario partition is empty or incomplete')
        if any(case is not cases[index] for index, case in zip(part['indices'], part['cases'])):
            raise ValueError('Native scenario partition changed a scenario')
    if sum(case_assertions(case) for part in parts for case in part['cases']) != sum(map(case_assertions, cases)):
        raise ValueError('Native scenario partitions changed the assertion inventory')


def native_output(stdout, stderr):
    def decoded(value):
        return value.decode(errors='replace') if isinstance(value, bytes) else (value or '')
    return decoded(stdout) + decoded(stderr)


def run_native_part(tool, test_file, part_number, part, timeout):
    started = time.monotonic()
    row = {'part': part_number, 'status': 'FAIL', 'scenarios': len(part['cases']),
           'assertions': sum(map(case_assertions, part['cases'])), 'case_indices': part['indices']}
    output = ''
    try:
        result = subprocess.run([tool, 'test', 'rules', str(test_file)], text=True,
                                capture_output=True, timeout=timeout)
        output = native_output(result.stdout, result.stderr)
        row['returncode'] = result.returncode
        if result.returncode == 0 and not NATIVE_TEMPLATE_ERRORS.search(output):
            row['status'] = 'PASS'
        else:
            row['reason'] = 'Native rules or template verification failed'
    except subprocess.TimeoutExpired as exc:
        output = native_output(exc.stdout, exc.stderr)
        row['reason'] = 'Native part timed out'
    except OSError as exc:
        row['reason'] = 'Cannot execute native verification: ' + str(exc)
    except Exception as exc:
        row['reason'] = 'Native verification raised ' + type(exc).__name__ + ': ' + str(exc)
    if row['status'] != 'PASS' and output:
        row['output'] = output[-NATIVE_OUTPUT_LIMIT:]
    row['elapsed_seconds'] = round(time.monotonic() - started, 2)
    return row


def run_native_batch(tool, root, rules, definitions, cases, evaluation, timeout, progress=None):
    """Run two lossless parts against the same complete shipped rule group."""
    parts = partition_cases(cases)
    validate_parts(cases, parts)
    files = []
    for number, part in enumerate(parts, 1):
        spec = {'rule_files': [str(rules)], 'evaluation_interval': evaluation,
                'group_eval_order': [g['name'] for g in definitions['groups']], 'tests': part['cases']}
        path = root / f'test-part-{number}.yml'
        # Every part retains the full rule file. Only independent test groups are scheduled separately.
        import yaml
        path.write_text(yaml.safe_dump(spec, sort_keys=False, allow_unicode=True, width=100000))
        files.append(path)
    rows = []
    with ThreadPoolExecutor(max_workers=NATIVE_PARTS) as pool:
        futures = {pool.submit(run_native_part, tool, path, number, part, timeout): (number, part)
                   for number, (path, part) in enumerate(zip(files, parts), 1)}
        for future in as_completed(futures):
            number, part = futures[future]
            try:
                row = future.result()
            except Exception as exc:
                row = {'part': number, 'status': 'FAIL', 'scenarios': len(part['cases']),
                       'assertions': sum(map(case_assertions, part['cases'])), 'case_indices': part['indices'],
                       'elapsed_seconds': None,
                       'reason': 'Native worker raised ' + type(exc).__name__ + ': ' + str(exc)}
            rows.append(row)
            if progress:
                progress(row)
    rows.sort(key=lambda row: row['part'])
    complete = (len(rows) == len(parts) and [row['part'] for row in rows] == list(range(1, len(parts) + 1))
                and sorted(i for row in rows for i in row['case_indices']) == list(range(len(cases)))
                and sum(row['scenarios'] for row in rows) == len(cases)
                and sum(row['assertions'] for row in rows) == sum(map(case_assertions, cases)))
    return {'status': 'PASS' if complete and all(row['status'] == 'PASS' and row.get('returncode') == 0
                                               for row in rows) else 'FAIL',
            'scenarios': len(cases), 'assertions': sum(map(case_assertions, cases)), 'parts': rows}


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, help='Plain OIE YAML file containing alerts and their helpers')
    parser.add_argument('--promtool', default=os.environ.get('PROMTOOL') or shutil.which('promtool'))
    parser.add_argument('--evaluation-intervals', nargs='+', choices=['15s', '30s', '60s'], default=['15s', '30s', '60s'])
    parser.add_argument('--scrape-intervals', nargs='+', type=int, choices=[15, 30, 60], default=[15, 30, 60])
    parser.add_argument('--report', type=Path, help='Write a machine-readable result outside the source tree')
    parser.add_argument('--list', action='store_true', help='List coverage without claiming validation')
    parser.add_argument('--timeout', type=int, default=3600, help='Seconds allowed for each of two parallel native parts')
    return parser.parse_args()


def main():
    args = arguments()
    if args.source:
        os.environ['OIE_ALERT_SOURCE'] = str(args.source.resolve())
    try:
        import yaml
        from oie_alerts_test import render, SOURCE
        from oie_alerts_lifecycle_test import (DEFINITIONS, positive_fixtures, lifecycle_cases,
                                               normal_cases, mitigation_cases, disk_policy_cases,
                                               regression_cases, notification_noise_cases, resample_case)
        definitions = yaml.safe_load(render())
    except (ImportError, OSError, ValueError, KeyError) as exc:
        print('BLOCKED: cannot load the alert policy/test dependencies: ' + str(exc), file=sys.stderr)
        return 2
    if set(positive_fixtures()) != set(DEFINITIONS):
        print('FAIL: test inventory differs from the alert file. Missing: ' +
              ', '.join(sorted(set(DEFINITIONS) - set(positive_fixtures()))), file=sys.stderr)
        return 1
    report = {'source': str(SOURCE), 'validation': 'native Prometheus synthetic rules',
              'status': 'NOT_TESTED', 'alerts': {name: {'status': 'NOT_TESTED', 'hold': r.get('for', '0s'),
              'checks': ['normal', 'pending', 'firing', 'healthy recovery']} for name, r in DEFINITIONS.items()},
              'batches': [], 'live_exporter_or_notification_delivery_tested': False}
    def save():
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, indent=2) + '\n')
    if args.list:
        for name, entry in report['alerts'].items():
            print(f'{name} | for={entry["hold"]} | normal / pending / firing / recovery')
        save()
        return 0
    tool = args.promtool
    if not tool or not (Path(tool).is_file() and os.access(tool, os.X_OK)):
        report['status'] = 'BLOCKED'
        report['reason'] = 'An executable promtool is required; structural checks are not native validation.'
        save()
        print('BLOCKED: ' + report['reason'], file=sys.stderr)
        return 2
    version = subprocess.run([tool, '--version'], capture_output=True, text=True, timeout=15)
    if version.returncode:
        print('BLOCKED: promtool could not run.', file=sys.stderr)
        return 2
    report['promtool_version'] = (version.stdout + version.stderr).strip()
    started = time.monotonic()
    failed = False
    with tempfile.TemporaryDirectory(prefix='oie-rule-tests-') as temp:
        root = Path(temp)
        rules = root / 'rules.yml'
        rules.write_text(yaml.safe_dump(definitions, sort_keys=False, allow_unicode=True))
        result = subprocess.run([tool, 'check', 'rules', str(rules)], text=True, capture_output=True, timeout=60)
        if result.returncode:
            print(result.stdout + result.stderr, file=sys.stderr)
            report.update(status='FAIL', reason='Rendered rules failed native syntax/annotation validation')
            save()
            return 1
        all_lifecycle = lifecycle_cases() + normal_cases()
        other = mitigation_cases() + disk_policy_cases() + regression_cases() + notification_noise_cases()
        for evaluation in args.evaluation_intervals:
            for scrape in args.scrape_intervals:
                batch_name = f'evaluation={evaluation}; scrape={scrape}s'
                # The complete raw-input suite is exercised at every combination.
                cases = [resample_case(c, scrape) for c in all_lifecycle + other]
                print('RUN ' + batch_name + f' | {len(cases)} scenarios in two parallel parts', flush=True)
                def progress(row):
                    print(row['status'] + ' ' + batch_name + f'; part={row["part"]}' +
                          f' | {row["scenarios"]} scenarios; {row["elapsed_seconds"]}s', flush=True)
                    if row['status'] != 'PASS':
                        print(row.get('reason', 'Native verification failed') + '\n' + row.get('output', ''),
                              file=sys.stderr)
                batch = {'name': batch_name, **run_native_batch(tool, root, rules, definitions, cases,
                                                               evaluation, args.timeout, progress)}
                ok = batch['status'] == 'PASS'
                failed |= not ok
                report['batches'].append(batch)
                print(batch['status'] + ' ' + batch_name, flush=True)
                save()
    report['status'] = 'FAIL' if failed else 'PASS'
    for entry in report['alerts'].values():
        entry['status'] = 'NOT_VERIFIED' if failed else 'PASS'
    report['elapsed_seconds'] = round(time.monotonic() - started, 2)
    save()
    print(f'{report["status"]}: {len(DEFINITIONS)} alert definitions; {len(report["batches"])} native cadence combinations')
    return 1 if failed else 0


if __name__ == '__main__':
    raise SystemExit(main())
