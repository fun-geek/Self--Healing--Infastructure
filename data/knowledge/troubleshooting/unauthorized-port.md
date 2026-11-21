---
doc_id: TRB-PORT-001
title: Troubleshooting - Unauthorized Listening Port
classification: internal
trust_level: authoritative
version: "1.6"
owner: network-security@xyz.example
---
# Troubleshooting: Unauthorized Listening Port

## Symptoms

RULE-PORT-001 reports a listening port that is absent from the baseline. Severity is
critical when the port is on the high-risk list, bound to an unapproved process, or
bound by a privileged user.

## Common causes

- reverse shell or command-and-control listener;
- cryptocurrency miner with a Stratum listener;
- debugging endpoint left enabled;
- legitimate new service deployed without a baseline change.

## Investigation

1. Identify the bound process, executable, user and PID.
2. Check whether the process name and executable are approved.
3. Correlate with process findings and image drift.
4. Check for an approved change record covering the port (rare; ports are normally
   baseline-only).

## Containment

Drain the resource from the load balancer, quarantine it, and preserve the socket
table. Do not simply kill the process: the persistence mechanism may remain and the
workload may still be compromised. Rebuild from the approved baseline and validate
VAL-PORT-001 before returning to service.
