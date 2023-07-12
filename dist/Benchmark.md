# Benchmarking of the solution

The benchmarked solutions:
**Method 1**: wrap the method of a structure, structure name is saved
**Method 2**: wrap the structure, alternative structure name

### The test file

Each method use the next code to benchmark solution

```js
let s = lib.Scalar.one(); // create an instance with some non zero data
console.time('test');     // start timer
for(let i = 0; i < 3e7; i++)
  s = s.double();         // call method
console.timeEnd('test');  // end timer

console.log(s.to_bytes()); // use result to prevent nodejs optimization
```

### The benchmark results

| Run | Method 1 | Method 2 |
|----:|:--------:|:--------:|
|   1 |   9.048  |   9.134  |
|   2 |   8.925  |   8.754  |
|   3 |   9.228  |   9.304  |
|   4 |   9.228  |   8.936  |
|   5 |   9.256  |   9.112  |
|   6 |   8.978  |   8.891  |
|   7 |   9.281  |   9.208  |
|   8 |   9.292  |   8.807  |
|   9 |   9.191  |   9.005  |
|  10 |   8.921  |   9.018  |

Average time of **Method 1**: 9.135

Average time of **Method 2**: 9.017

The delta is ~1%.

### Conclusion

We can use any of the methods but it is much simpler to use alternative structure.
