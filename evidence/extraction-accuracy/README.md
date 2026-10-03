# Source-code extraction accuracy — data

Per-parameter comparison of what the Spring source extractor recovers against ground truth,
for 120 sampled endpoints across three Java applications.

| | endpoints | parameters | recall | precision | type | location |
|---|---|---|---|---|---|---|
| Chat2DB 3.4.1 | 40 | 174 | 1.0000 | 1.0000 | 173/173 | 1.0000 |
| Halo 1.6.1 | 40 | 96 | 1.0000 | 1.0000 | 96/96 | 1.0000 |
| novel-plus 5.2.0 | 40 | 163 | 1.0000 | 1.0000 | 142/142 | 1.0000 |
| **total** | **120** | **433** | **1.0000** | **1.0000** | **411/411** | **1.0000** |

## Files

| file | rows | content |
|---|---|---|
| `summary.csv` | 4 | the table above |
| `endpoints.csv` | 120 | one row per endpoint |
| `parameters.csv` | 433 | one row per parameter |
| `ground-truth.json` | 120 | the ground truth, with each endpoint's handler and notes |
| `sample.json` | — | which endpoints were drawn, from which stratum, and what the extractor output for each |

Join `endpoints.csv` and `parameters.csv` on `app` + `method` + `url`.

## parameters.csv

`source_*` is the ground truth; `tool_*` is what the extractor produced. `expected_type`
is `source_java_type` expressed in the extractor's type vocabulary, so it is `expected_type`
and `tool_type` that are compared.

| column | meaning |
|---|---|
| `app` `method` `url` | which endpoint this parameter belongs to |
| `parameter` | parameter name |
| `source_location` | where ground truth says it is bound: `path`, `query`, `header`, `body` |
| `source_java_type` | its declared Java type, e.g. `Long`, `List<Integer>` |
| `expected_type` | that type mapped to `string` / `integer` / `number` / `boolean` / `date` / `datetime` / `array` / `object` / `file` |
| `tool_location` | where the extractor put it |
| `tool_type` | the type the extractor assigned |
| `outcome` | `matched`, `MISSED` (ground truth has it, extractor does not), `FALSE_POSITIVE` (extractor has it, ground truth does not) |
| `type_check` | `ok`, `WRONG`, or `not_compared` when the Java type maps to no single type (a field declared `Object`, or a key with no declared type) |
| `location_check` | `ok` or `WRONG` |

Parameter names are compared as sets within an endpoint: the intersection is `matched`,
ground-truth-only is `MISSED`, extractor-only is `FALSE_POSITIVE`. `type_check` and
`location_check` are only meaningful on a `matched` row.

## endpoints.csv

| column | meaning |
|---|---|
| `app` `method` `url` | the endpoint |
| `handler` | the Java file and line of its handler method, to check a row against source |
| `stratum` | the sampling stratum: `body`, `query`, `path`, or `none` by the locations its parameters occupy |
| `parameters` `matched` `missed` `false_positive` | per-endpoint counts |

## summary.csv

`recall` = `matched` / `parameters`. `precision` = `matched` / (`matched` + `false_positive`).
`type_accuracy` = `type_correct` / `type_compared`, where `type_compared` excludes the
`not_compared` rows counted in `type_not_compared`. `location_accuracy` is over matched
parameters.
