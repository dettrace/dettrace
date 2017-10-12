# DetTrace
Determinizing behavior of a program using tracing.

## Details
This project uses the system call ptrace, to intercept and determinize all system call the tracee
project does. This way we can sandbox and restrict the behavior of the traced process to only
deterministic behavior.