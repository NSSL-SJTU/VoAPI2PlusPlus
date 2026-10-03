# API functionality ground truth

Ground truth for the keyword filter that decides which endpoints are tested for each
vulnerability class. 791 sampled endpoints, each labelled for six functionalities.

## Files

| file | content |
|---|---|
| `summary.csv` | precision and recall per application × vulnerability class, plus an `ALL` row per class |
| `labels.csv` | one row per endpoint × functionality: `label` (`yes` / `no` / `unclear`), the `params` that carry the value (`;`-separated), a source `anchor`, and a `note` |
| `samples.json` | per application: the sampling strata (population sizes and which endpoints were drawn) and the endpoints with what the filter selected |

Join the files on application + `endpoint` (`METHOD /path`).

## Functionalities

| functionality | vulnerability class | meaning |
|---|---|---|
| `NET_REQUEST` | SSRF | a request value steers the destination of a server-side outbound call |
| `FILE_UPLOAD` | UNRESTRICTED_UPLOAD | the endpoint accepts an uploaded file |
| `FILE_PATH` | PATH_TRAVERSAL | a request value reaches a filesystem path |
| `COMMAND_EXEC` | COMMAND_INJECTION | a request value reaches process execution or an interpreter |
| `DB_QUERY` | SQLi | a request value reaches an unbound position in query text |
| `RENDERED_TEXT` | XSS | a request value is stored or reflected as text that is later rendered |

## summary.csv

| column | meaning |
|---|---|
| `population_selected` / `population_notselected` | endpoints the filter did / did not select, out of all endpoints of the application |
| `sampled_selected` / `sampled_notselected` | how many of each were sampled and labelled |
| `tp` `fp` `fn` `tn` | selected-and-has-functionality, selected-but-not, not-selected-but-has, neither |
| `unclear` | sampled endpoints whose label is `unclear`; excluded from the four counts |
| `precision` | `tp / (tp + fp)`; empty when nothing was selected |
| `recall` | `tp / (tp + fn)`; empty when no sampled endpoint has the functionality |

The sample is stratified (selected / not selected), not proportional; use the
`population_*` columns to weight the strata.
