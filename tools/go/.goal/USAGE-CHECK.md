# Check remaining Codex usage

Use this procedure when resuming the migration. It was verified on 2026-10-21:
the `codex` weekly window reported 52% used, so 48% remained. That observation
is historical; query again rather than using it as the current allowance.

The supported read-only RPC is `account/rateLimits/read`, after `initialize`
and `initialized`. See the [official app-server documentation](https://learn.chatgpt.com/docs/app-server#6-rate-limits-chatgpt).
This does not invoke the interactive `/status` command or start an inference turn.

## Run the bounded query

Run from `tools/go`. This uses the installed Codex executable and its existing
login. It creates one owned stdio child, reads rate-limit metadata, saves a receipt,
and closes that child. It never reads or prints credential files.

```bash
python3 - <<'PY'
import datetime, json, pathlib, selectors, subprocess, time

checked_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
child = subprocess.Popen(
    ['nice', '-n', '19', 'codex', 'app-server', '--listen', 'stdio://'],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE,
    stderr=subprocess.DEVNULL, text=True, bufsize=1,
)
selector = selectors.DefaultSelector()
selector.register(child.stdout, selectors.EVENT_READ)
result = None
deadline = time.monotonic() + 30
try:
    child.stdin.write(json.dumps({
        'id': 1, 'method': 'initialize',
        'params': {'clientInfo': {
            'name': 'codex_usage_probe', 'title': 'Read-only usage check',
            'version': '1.0',
        }},
    }) + '\n')
    child.stdin.flush()
    while time.monotonic() < deadline:
        if not selector.select(min(1, max(0, deadline - time.monotonic()))):
            if child.poll() is not None:
                break
            continue
        line = child.stdout.readline()
        if not line:
            break
        message = json.loads(line)
        if message.get('id') not in (1, 2):
            continue
        if 'error' in message:
            raise SystemExit('Quota query rejected; remaining usage is unknown')
        if message['id'] == 1:
            child.stdin.write(json.dumps({
                'method': 'initialized', 'params': {},
            }) + '\n')
            child.stdin.write(json.dumps({
                'id': 2, 'method': 'account/rateLimits/read',
            }) + '\n')
            child.stdin.flush()
        else:
            result = message['result']
            result.pop('accountId', None)
            break
finally:
    selector.close()
    child.stdin.close()
    if child.poll() is None:
        child.terminate()
    try:
        child.wait(timeout=5)
    except subprocess.TimeoutExpired:
        child.kill()
        child.wait(timeout=5)

if result is None:
    raise SystemExit('No quota reply within 30 seconds; remaining usage is unknown')
receipt = {
    'checked_at': checked_at, 'method': 'account/rateLimits/read',
    'result': result, 'owned_child_pid': child.pid,
    'owned_child_terminal': child.poll() is not None,
    'read_only': True, 'new_thread_or_turn': False,
}
pathlib.Path('.goal/usage-latest.json').write_text(
    json.dumps(receipt, indent=2) + '\n',
)
bucket = result.get('rateLimitsByLimitId', {}).get('codex')
if bucket is None:
    bucket = result.get('rateLimits')
if not bucket or bucket.get('limitId') != 'codex':
    raise SystemExit('Codex bucket unavailable; do not substitute another bucket')
for name in ('primary', 'secondary'):
    window = bucket.get(name)
    if window is None:
        continue
    used = window.get('usedPercent')
    if not isinstance(used, (int, float)) or not 0 <= used <= 100:
        raise SystemExit('Invalid usage percentage; remaining usage is unknown')
    print(name, {
        'used_percent': used, 'remaining_percent': 100 - used,
        'window_minutes': window.get('windowDurationMins'),
        'resets_at': window.get('resetsAt'),
    })
PY
```

## Interpret and act

- `remaining = 100 - usedPercent`. Do not interpret 52% used as 52% remaining.
- Prefer `rateLimitsByLimitId.codex`; use `rateLimits` only if its `limitId` is
  `codex`. Other model/bucket limits must not be silently substituted.
- Inspect both non-null `primary` and `secondary` windows. `windowDurationMins`
  describes their duration; 10080 minutes means one week. Do not assume the
  primary window is always weekly. `resetsAt` is a Unix timestamp in seconds.
- The latest owner instruction is to continue until **10% remaining**. Poll every
  15 minutes and before substantial batches; record the observation/deadline in
  [work-limit.json](work-limit.json). When a material Codex window reaches 10% or
  lower, checkpoint current work, record running jobs, call the native goal pause
  tool under this owner instruction, and stop migration work.
- A timeout, missing bucket/window, or rejected query means **unknown**, not 0%.
  Recheck and disclose an ongoing telemetry failure; do not invent a time limit.
- The native goal's `tokensUsed` and unbounded token budget are separate from
  account quota. They cannot determine the remaining subscription allowance.
- Sampling and rounded percentages cannot guarantee an exact 10.00% stop. Poll
  more frequently near the threshold and avoid starting a large batch near it.

Keep the read-only boundary: no thread/turn start, login/logout, reset-credit
consumption, credits purchase, settings changes, owner emails, auth-file output,
or interaction with the existing app-server daemon. Terminate only the child
created by this query. No background polling daemon is needed.
