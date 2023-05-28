Exprerimental native MSM circuits in halo2. 

Bucket method and sliding window method are explored. There are two implementations for both approach. While the first one is named as *narrow* and uses 5 advice columns, the other one is called *wide* and uses 9 advice columns. Branching is applied using dynamic lookups rather than conditional selection in order to get rid of list scanning for bit slices. Some benchmarks for each approach is below.

| method  | layout | window | number of points | row cost | area cost |
|---|---|---|---|---|---|
| sliding window  | narrow | 4 | 10000 | 177 | 885 |
| sliding window  | wide   | 4 | 10000 | 98  | 882 |
| bucket          | narrow | 8 | 10000 | 137 | 425 |
| bucket          | wide   | 8 | 10000 | 71  | 223 |

