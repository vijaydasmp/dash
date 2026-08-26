## CI Scripts

This directory contains scripts for each build step in each build stage.

### Configurations

Configurations live in `ci/test/00_setup_env*.sh` and are selected by
`BUILD_TARGET` in `ci/dash/matrix.sh`, driven by the GitHub Actions workflows
in `.github/workflows`. They are constructed to test a wide range of
configurations, rather than a single pass/fail. This helps to catch build
failures and logic errors that present on platforms other than the ones the
author has tested.

Some builders use the dependency-generator in `./depends`, rather than using
the system package manager to install build dependencies. This guarantees that
the tester is using the same versions as the release builds, which also use
`./depends`.

If values are left out, `00_setup_env.sh` is used as the default configuration
with fallback values.

### Cache

In order to avoid rebuilding all dependencies for each build, the binaries are
cached and reused when possible. Changes in the dependency-generator will
trigger cache-invalidation and rebuilds as necessary.
