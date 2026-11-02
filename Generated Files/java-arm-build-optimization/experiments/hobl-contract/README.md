# Matched HOBL-contract reproduction: original wrapper, not mvnd

This separate lane pins Petclinic **6feeae0f13e0e258eedc99832416b42bb13779b1 /Boot4.0.0-M3**, native Microsoft **25.0.5.0.2+1-LTS**, original Maven Wrapper3.3.4/**Maven3.9.11**. It is not current17 or the separate **online Maven3.9.16 versus mvnd normalizedHobl25** screen. Those existing lanes are unchanged.

The original HOBL source reference is `microsoft/HOBL@df120528374c0a5de5cb5a526175973d1ea2b53f`. This safe reconstruction repairs its Windows checkout/Mac unpinned-source ambiguity with an ordinary full clone; it does not execute HOBL installers, profiles, firewall/credential changes or tracing. Selected JDK patch differs from original requested25.0.0.36; actual original DUT runtime is unknown. No official HOBL score or device parity claim.

## Local invocation after explicit exclusive-slot authorization

Prepare a **new ordinary full clone**, never a linked worktree. From an existing retained full local clone:

```powershell
git clone --local --no-hardlinks --no-checkout $RetainedFullClone $NewOwnedProject
git -C $NewOwnedProject checkout --detach 6feeae0f13e0e258eedc99832416b42bb13779b1
git -C $NewOwnedProject remote set-url origin https://github.com/spring-projects/spring-petclinic
```

Use the existing checksum-verified native JDK25; no SDK installation or version probe is needed during preparation. `$ExistingCache` is the explicit prepared Maven repository (locally `m2-hobl`). `$FreshOutput` must not exist and must be outside source. Inspect/resolve injected option or user-settings rejections explicitly; the local runner never clears unknown options.

```powershell
& '.\Invoke-HoblContract.ps1' -ProjectFullClone $NewOwnedProject `
  -JavaHome $VerifiedJava25Home -LocalCache $ExistingCache -OutputDirectory $FreshOutput `
  -ExclusiveSlotApproved -AcknowledgeContractReconstruction -LoopbackTests
```

No sample-count switch: a successful contract run has **exactly five loops**. Online `dependency:go-offline -DskipTests` and `clean verify` occur first, outside timers. The latter is retained as a distinct **online full-artifact sidecar**. Each loop has untimed online clean, timed offline package with skipTests, then separately timed offline test. No Maven batch/daemon/JIT/JaCoCo optimization is added.

Windows retains the `Measure-Command` wrapper/redirection boundary and unrounded TotalSeconds; immediate native-exit capture also falls inside this block. Mac retains `/usr/bin/time -p` real/user/sys text with its **native hundredth-second precision**, without inventing sub-centisecond samples. The outer harness/process launch/redirection uses PowerShell7 rather than sourcing the original Mac shell profile. Scenario totals are each build+test pair; the scenario median is the median of those five raw sums, not the sum of phase medians. Windows additionally retains the original round-phases-then-sum value separately. No warmup/outlier samples are discarded.

Two explicit safety/evidence deviations: common `-Dserver.address=127.0.0.1` on both platforms, and an additional **untimed** offline JaCoCo report after each test. Log/artifact copying occurs outside timers. The original POM's report runs at prepare-package, before the separate test, so this audit goal is necessary to retain fresh test coverage without changing score commands.

Offline CycloneDX requires-online skipping and missing packaged SBOM are intentional and checked; offline outputs are **not full-online-fidelity PASS**. Main/test/dependency hashes, full coverage keys and test identities must still match the online control. Packaged Git must identify actual clean6feeae0. Raw Git/build/POM/manifest metadata bytes are retained, plus online SBOM bytes/graph and every whole JAR.

Required old-pin universes come from retained verified full-clone evidence, not current17: **56 recursive tests /54pass /2skip,726 complete counters,296 source lines,30 main classes,25 test binaries,98 dependencies**. A platform with different skips fails for review instead of adapting the expectation.

## Offline checks and inactive fork workflow

```powershell
& '.\Test-HoblContract.ps1' -FixtureRoot $NewOwnedStaticFixtureDirectory
```

This invokes no Java/Maven/network. `hobl-contract.workflow.yml` is deliberately outside `.github`; root must review and separately publish it only to **yeelam-gordon/spring-petclinic**, configure environment **hobl-contract-approval with required reviewers**, and obtain an explicit allocation before manual dispatch. The hard fork guard blocks upstream. The manual acknowledgement is `I_HAVE_APPROVAL_AND_BUDGET`; matrix jobs are Windows11ARM and macos15, each five loops.

The template reuses pinned official JDK25 archive hashes/setup-java action and always-uploaded setup outcomes. Action-generated Maven credentials/settings are directed to a separate unused owned folder, not the baseline's user Maven settings. It needs no mvnd, JNI prototype, MSVC or driver download. It receipts/normalizes only the explicitly reviewed Windows image default `MAVEN_OPTS=-Xms256m` to the common empty baseline; unknown options fail. That is a reconstruction deviation, not an observed historical HOBL environment.

Hosted hardware differs across OS and from physical DUTs. Actual runtime qualification of this new entrypoint, both-platform execution, general performance conclusions and any later optimization remain separately gated. Four public payload files live in this directory; private evidence is not a publication input.

### Replaying this fork after validation settings are restored

The published workflow lives on `perf/hobl-arm64-contract`. This investigation restores the fork's original default branch and Actions-disabled setting after validation; that does not remove the branch or its source.

For another authorized run, the repository owner must:

1. Temporarily enable repository Actions and make `perf/hobl-arm64-contract` the fork's default branch so GitHub can discover its manual workflow.
2. Enable only `hobl-contract-arm64.yml`, dispatch it on that branch with the acknowledgement above, and approve the configured `hobl-contract-approval` environment.
3. Wait for both platform jobs and artifact uploads to complete.
4. Disable the benchmark workflow and restore the original default branch and Actions setting, leaving unrelated workflow states unchanged.

These are fork-only administrative steps, not upstream changes or automatic spending authority.
