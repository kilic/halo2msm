Exprerimental native MSM circuits in halo2. 

Bucket method and sliding window method are explored. There are two implementations for both approach. While the first one is named as *narrow* and uses 5 advice columns, the other one is called *wide* and uses 9 advice columns. Branching is applied using dynamic lookups rather than conditional selection in order to get rid of list scanning for bit slices. Some benchmarks for each approach is below while additional subset argument witnesses are excluded.

| method  | layout | window | number of terms `a_i * P_i` | row cost per term | area cost per term |
|---|---|---|---|---|---|
| sliding window  | narrow | 4 | 10000 | 177 | 885 |
| sliding window  | wide   | 4 | 10000 | 98  | 882 |
| bucket          | narrow | 8 | 10000 | 137 | 685 |
| bucket          | wide   | 8 | 10000 | 71  | 639 |
| bucket          | narrow | 6 | 10000 | 86  | 430 |

Note that area cost is only measures area of frontend cells. Additional cost of lookup and permutation argument is not included.

Bucket method consumes 3 subset arguments:

* Ranging windowed scalars i.e address values for reads write operation (small elements)
* Read/Write consistency
  * Notice that in bucket method memory is a one-to-one map between application queries and sorted queries, so we can use shuffle argument instead of subset argument to reduce number of additional witness columns
* Timestamp difference ranging. (This can be integrated to first lookup argument so we can have only 2 subset arguments)

Sliding window method consumes 2 subset arguments:

* Ranging windowed scalars i.e address values for reads write operation (small elements)
* Write-once windowed point table. Dynamic with variable base fixed with fixed base. So we can just use wider windows for fixed case

TODO

* [x] Fixed base MSM
* [ ] Explore optimisations for single term (good for folding)
* [ ] Explore [Eagen-MSM](https://eprint.iacr.org/2022/596.pdf)