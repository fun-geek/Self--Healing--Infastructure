---
doc_id: TRB-PROC-001
title: Troubleshooting - Unknown or Masquerading Process
classification: internal
trust_level: authoritative
version: "1.5"
owner: security-operations@xyz.example
---
# Troubleshooting: Unknown or Masquerading Process

## Detection

RULE-PROC-001 fires when a process name is not in the approved process inventory.
RULE-PROC-002 fires when an approved name runs from an unexpected executable path or
as an unexpected user. A process named like a system daemon but executing from /tmp,
/dev/shm or /var/tmp is treated as critical.

## Investigation questions

- What is the full executable path and command line?
- Which user owns the process?
- When did it start relative to the last known-good telemetry?
- Does it hold any listening sockets?
- Is the parent process approved?

## Response

Treat a forbidden-path process running as root as active compromise. Contain the
workload, preserve the process table as evidence, rebuild from the approved baseline,
and validate VAL-PROC-001 and VAL-PROC-002. Do not whitelist the binary. Do not rely
on killing the process alone, because persistence may recreate it.
