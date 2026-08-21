# The session pass verifier, in three places

This directory is a COPY of `conductor/src/services/sessions/pass.ts` and `strictJson.ts`, and the
copy is deliberate rather than laziness.

Three programs verify a session pass: conductor mints them, the session gate admits them, and this
workspace admits what the gate forwards. They are three separate images with three separate release
cycles, and a shared library between two repos and a container image would mean a version skew none
of them can see.

**What keeps the copies honest is `testdata/passes.json`, not discipline.** It is the same file the
gate's Go verifier and conductor's TypeScript verifier read, byte for byte, and all three suites
assert the same verdict and the same decoded payload for all 67 vectors. A copy that drifts fails
its own tests.

When the verifier changes: change it in conductor, copy it here and regenerate the vectors in
`sessiongate` (`go test ./internal/pass -run TestUpdateVectors -update`), then run all three suites.
The drift test in each repo fails if a copy is stale.
