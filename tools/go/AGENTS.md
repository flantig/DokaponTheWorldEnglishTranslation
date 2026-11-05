# Go migration rules

This directory owns the registry-driven Go replacement. Recover `.goal/GOAL.md`
and recent `.goal/JOURNAL.md` before continuing. The broader feature session and
its root `.goal` are outside scope. The user explicitly authorized persistent
migration work and separate scratch patching; do not repeatedly request permission.

## Reuse is mandatory

- NEVER create a new function if there is an opportunity to enhance an existing one.
- Use the Serena MCP to inspect the relevant symbols and referencing callers first.
  Search the existing Go functions before implementing new behavior.
- Extend existing planners, encoders, validators, copy writers and tests where
  appropriate. Keep patch-specific facts in purpose-grouped recipe tables, keyed by
  registry ID. Do not introduce one handler or function per historical script.
- Before an unavoidable new function, record the existing candidates considered,
  their callers, and the concrete reason none can be safely enhanced. Tests are
  included in this rule: extend an existing test/table where suitable.
- Prefer standard-library operations over new helpers. Preserve safety/error
  handling; do not compress readable code into cryptic statements.
- Give complex functions concise Go doc comments covering their contract and gotchas;
  avoid basic syntax explanations and step-by-step narration.
- Review for another developer: name domain decisions, group related rules, keep error
  precedence obvious, and use switch for mutually exclusive operation dispatch.
  Concision must preserve validation and make intent easier to read.
- Judge boundaries by which design decision they contain and how many places a
  change reaches. File size alone does not establish reuse or maintainability.
  Keep domain names informative and the successful path easy to follow. Complexity
  metrics identify review candidates; they are not proof of readable code.
- Count deleted behavior duplication across source AND recipes, including adapters.
  Moving declarations is organization, and capability growth is a cost until it
  demonstrably replaces historical responsibilities. Keep those claims separate.

## Adversarial Astra audit every two hours

While the migration goal is active, check `.goal/astra-audits.json` and UTC time
at each continuation and before each substantive batch. Every two hours launch one
`gpt-6-astra` agent (read-only, purely adversarial) to challenge reuse, needless
appends, duplication and unsupported reduction/retirement claims. Compare against
the previous audit snapshot. Require concrete file/line findings and minimal
consolidation or deletion directions; the auditor must not edit code. Record its
report, disposition and next due time. Do not overlap auditors. Keep this
cadence in the native goal loop; do not install a polling daemon. Respect the
protected resources and the two low-priority analysis-worker limit below.
The auditor is solely a challenger: no implementation, no approval authority and
no requirement to find something positive. Require reproducible counterexamples;
the main agent evaluates findings and owns fixes.

## Verification and accounting

The user explicitly changed verification pacing on2026-10-20: use focused tests
for changed shared behavior during development; defer the complete test/race
suite until the integrated toolkit checkpoint. Continue build/vet/gofmt, scoped
whitespace and credential checks. A focused pass is not a full-suite pass. Compare
historical/new complete bytes, refusals and input preservation using synthetic
fixtures. Measure all Go source, imports, adapters, module configuration and recipe
data together; list test/analysis/evidence overhead separately. Count supported
responsibilities honestly: moving files or passing one family is not full migration.

## Protected resources

Original, shipping and custom-art ISOs and the canonical registry are read-only.
Real patch applications create new isolated outputs only, with two independent
fresh reviews, byte guards, source identity, readback and full-image containment.
Keep approved art unchanged. Never control the running story probe or use its
virtual controller/PINE socket. The owner-authorized concurrent RAM technique
requires a separate native profile, data root, socket, display, logs and BIOS copy,
disabled shared input/cards, low priority and exact owned-PID cleanup. Vulkan can
still contend for the shared GPU; no visual/gameplay claim follows from RAM matches.

## User work limit

The latest owner instruction on2026-10-21 explicitly revokes the10% allowance
pause: continue migration past that threshold. Respect actual system limits.
`.goal/work-limit.json` records this override; `.goal/USAGE-CHECK.md` retains
the optional verified read-only usage query. Never change account settings or
stop a shared daemon. Native goal counters are not account quota.

## Resume and scope

Keep durable next actions and evidence in this directory's `.goal/`. Do not mark the
persistent migration complete at a checkpoint. Existing rework inventories, Python
implementations and historical receipts remain references; preserve their history.
