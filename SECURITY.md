# Security Policy

## Reporting a vulnerability

Please do **not** open a public issue for security problems. Report them privately through
GitHub's "Report a vulnerability" (private security advisory) on this repository, or contact
the maintainers directly. Include the version, macOS version, and steps to reproduce.
Expect an acknowledgement within a few days.

## Scope

This tool is designed to delete only what the user explicitly selects. The following are
treated as security bugs: deleting or modifying anything on the hard deny list, following a
symlink out of a rule root, any network access (the tool makes none), running with elevated
privileges without the user knowingly doing so, and tests or CI touching a real home directory.

## Supported versions

Only the latest released version receives fixes (the project is pre-1.0).
