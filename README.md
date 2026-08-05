# usb-bouncer

macOS tool that vets unknown USB devices for BadUSB red flags and keystroke injection.

## Development

The protected branch requires the fixed `ci-ok` check to pass and requires the
branch to be up to date before merging. Force-pushes and deletion are
disallowed, and `enforce_admins` is off so an administrator override remains
available. `ci-ok` is separate from the test matrix because branch protection
matches check-run names literally, while matrix jobs become `test (3.11)` and
`test (3.14)`. Its `if: always()` is load-bearing: without it, the job is
skipped when a dependency fails, and the skipped required check reads as
neutral rather than failed.

Pull requests and approvals are not enforced. GitHub prevents self-approval,
making a required approval unsatisfiable on a solo repository. Its settings UI
nests approvals under the pull-request requirement, so dropping the approval
rule also drops the PR requirement; I accepted that rather than route around
the UI. I still follow one issue, one branch, one PR, comment-based
self-review, and squash merges. That workflow is a convention I practise, not a
control this repository enforces.
