---
doc_id: POL-CM-001
title: Change Management and Approved Configuration Policy
classification: internal
trust_level: authoritative
version: "1.8"
owner: change-advisory-board@xyz.example
---
# Change Management and Approved Configuration Policy

## Principle

Observed infrastructure is never assumed to be approved. A configuration hash that
differs from the baseline is drift unless a time-bounded approved change record
covers that exact resource and value.

## Approved change records

Approved changes are recorded in the baseline under `approved_changes` with a
change identifier (for example CHG-1042), the resource, the field, the approved
value, the approver, the approval time and an expiry time. Detection suppresses a
configuration-drift finding only when all of the following are true:

- the resource matches;
- the field is `config_hash`;
- the observed value exactly equals the approved value;
- the approval time is not in the future;
- the change has not expired.

Expired changes are treated as drift. A change record does not authorize
containment, restoration or any other action; it only explains a known deviation.

## Emergency changes

Emergency changes must still be recorded. If a change cannot be recorded before it
is applied, the security team must open a retroactive change record within one
business day and annotate the incident. Automated remediation must not be disabled
to accommodate an unrecorded change.

## Mutable image tags

Image tags are mutable and are not identity. A tag difference is informational when
the image digest matches the approved digest. A digest or registry reference
mismatch is a critical supply-chain finding.
