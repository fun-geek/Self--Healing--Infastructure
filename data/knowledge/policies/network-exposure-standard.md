---
doc_id: POL-NET-001
title: Network Exposure Standard for Order Platform Workloads
classification: internal
trust_level: authoritative
version: "1.4"
owner: network-security@xyz.example
---
# Network Exposure Standard

## Approved ports only

Every listening port must be explicitly approved for the resource in the baseline.
The baseline port entry records the port number, protocol, purpose and exposure
class (internal, public or management). Any additional listening socket is an
unauthorized exposure.

## High-risk ports

The following ports are treated as critical when observed without approval because
they are commonly used for reverse shells, miners or command-and-control:
4444, 1337, 31337, 5555, 6667, 4443 and 9001. A high-risk port bound to an
unapproved process running as root is an active-compromise indicator.

## Containment order

Network containment must happen in this order:

1. Remove the resource from the simulated load balancer (ACT-004).
2. Apply network quarantine (ACT-005).
3. Preserve the observed socket table as evidence.

Quarantine must not be attempted while the resource is still receiving traffic.
The policy engine rejects ACT-005 if the resource is still attached to the load
balancer.

## Validation

VAL-PORT-001 requires that every listening port after restoration is present in the
approved baseline. A single unapproved listening port fails the rule and blocks
return to service.
