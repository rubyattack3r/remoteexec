# Operator recovery

remoteexec does not automatically remove artifacts or retain a recovery journal. Each result reports artifacts created or changed before success or failure, along with recovery guidance. Save structured stdout when those details matter to the engagement.

Before a service-change run, preflight reads the existing service configuration. The execution result includes that original value with the changed-service artifact. Operator recovery is: stop the changed service if safe; compare current state with the result; restore the recorded configuration with approved administrative tooling; remove only the digest-matched staged executable; and restore the original run state.

For `SCMCreateService`, stop and delete only the exact temporary service name in the result, verify that it no longer exists, and then remove the digest-matched staged executable. There is no original service configuration to restore.

For `TaskSchedExec`, delete the exact registered task path in the result and remove the staged payload when present. For `WMIProvider`, remove the exact provider instance and associated registration key in the result, then remove the staged DLL. For other file-backed techniques, wait until the launched process releases the payload and remove the exact staged path.

For a direct `command` payload, no file is staged. `TaskSchedExec` still creates a temporary task that the operator may delete; other command-capable techniques have no persistent remoteexec artifact to remove. Raw command text and launcher arguments are represented by SHA-256 invocation identifiers rather than persisted as engagement metadata. A process artifact records the executable name and, where the API provides it, the launched PID.

remoteexec cannot infer changes made by an arbitrary user-supplied command. Its files, child processes, registry changes, accounts, or other effects remain the operator's responsibility.

Before recovery, compare every artifact, digest, and original value with current target state. Never delete similarly named services, tasks, provider registrations, files, or registry keys by wildcard.
