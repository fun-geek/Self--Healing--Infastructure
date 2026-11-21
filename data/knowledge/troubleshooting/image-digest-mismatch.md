---
doc_id: TRB-IMG-001
title: Troubleshooting - Image Digest Mismatch
classification: internal
trust_level: authoritative
version: "1.7"
owner: platform-reliability@xyz.example
---
# Troubleshooting: Image Digest Mismatch

## Symptoms

RULE-IMG-001 reports that the running image digest differs from the approved digest,
or the registry reference is not approved. The workload may still answer health
checks, which is why image identity is validated independently of health.

## Why tags are not trusted

Tags are mutable. A workload can report tag `latest` while running an unapproved
digest. Detection therefore compares the digest and registry reference, never the
tag alone. A tag difference with a matching digest produces only RULE-IMG-002
informational output.

## Investigation

1. Compare the observed digest with the baseline digest.
2. Check the artefact mirror for tampering or a stale cache.
3. Confirm the workload was not rebuilt from an unapproved registry.
4. Review recent change records for an approved image update.

## Remediation

Restore from the approved baseline (ACT-006). If the poisoned artefact persists after
restoration, validation fails and the resource remains quarantined. Escalate to the
platform team to repair the artefact source. Do not add the untrusted digest to the
baseline to make validation pass.
