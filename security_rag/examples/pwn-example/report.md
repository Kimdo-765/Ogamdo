# Fictional reference lifetime case

## Root Cause: stale reference
A test object can outlive the resource it points to.

## Primitive: stale object access
The test demonstrates access through the stale reference.

## Technique: lifetime analysis
The case compares ownership and cleanup paths to identify the missing guard.

## Outcome: reproduced in a test harness
The behavior was reproduced only in the fictional test harness.

## Constraints: cleanup guard
A guard that invalidates references when the resource is released blocks the observed path.
