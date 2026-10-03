# Failure-classifier audit

When a request fails, VoAPI²⁺⁺ classifies the failure as `dependency_error`,
`parameter_error`, or `unknown`, which selects the repair branch. This directory holds
a hand-labelled sample of 100 of those verdicts.

## Files

| file | content |
|---|---|
| `summary.csv` | accuracy per application, plus an `ALL` row |
| `cases.json` | the 100 sampled cases with what the classifier was shown: the failing request and the response |
| `predictions.json` | the classifier's verdict, reason, and missing fields for each case |
| `labels.csv` | the ground truth for each case |

Join the files on the case id (`C001`–`C100`). Credentials in requests are replaced by
`[REDACTED-CREDENTIAL]`.

## labels.csv

| column | meaning |
|---|---|
| `label` | `dependency`, `parameter`, `both`, or `neither` |
| `minimal_fix` | the smallest change that makes the request succeed |
| `anchor` | the source location (`path/File.ext:LINE`) or probe request that supports the label |
| `evidence` | `source` or `probe`, i.e. what `anchor` is |
| `decidable_from_response` | `yes` if the request and response alone are enough to reach the label |
| `note` | the reasoning behind the label |

A prediction is correct when `dependency_error` ↔ `dependency`, `parameter_error` ↔
`parameter`, or `unknown` ↔ `neither`.

## summary.csv

| column | meaning |
|---|---|
| `n_sampled` | cases from this application |
| `*_ruleA` | accuracy where a `both` case counts as correct if the prediction names either half |
| `ci95_low` / `ci95_high` | 95% Wilson interval for `accuracy_ruleA` |
| `*_ruleC` | accuracy with `both` cases removed from the denominator |
| `decidable_yes_*` / `decidable_no_*` | correct / total, split by `decidable_from_response` |
| `truth_*` | count of each ground-truth label |
