# Regulator

Regulator is a fuzzer for detecting performance bugs in regular expressions.

We currently only support fuzzing the V8 regexp engine [irregexp](https://blog.chromium.org/2009/02/irregexp-google-chromes-new-regexp.html), as implemented in nodejs. The irregexp engine is also found in chromium and [firefox](https://hacks.mozilla.org/2020/06/a-new-regexp-engine-in-spidermonkey/).


## Building

To build locally:

1. Get dependencies:\
`apt-get update &&
apt-get install -y git build-essential python3 python3-distutils libicu-dev`

2. Build nodejs so we can extract the built artifacts `make node` (NOTE: you may wish to use `make -j<number> node` to increase parallelism

3. Build the fuzzer: `make`

## Testing

We use the test framework [catch2](https://github.com/catchorg/Catch2), all test files can be found under `test/`. To run the tests, first ensure that the project builds as described above, then use `make test`.

The tests compile to a binary at `build/tests`. Use this either for debugging or for manually passing command-line flags to catch2 for changing the test suite configuration.

## Running

The built fuzzer lives at `build/fuzzer`. Use `./build/fuzzer --help` for a full listing of options.

### Example

`./build/fuzzer --timeout=360 -r 'http://(b|[b])*c' -l 17 -w 1 --debug`

Explanation: Run the fuzzer for 360 seconds against the regexp `http://(b|[b])*c`, with a subject length of 17 characters, a character width of 1 byte, and debug output on.


## Architecture Overview


```
  +-------------+ invokes  +---------------------+
  | fuzz-driver |--------->| regexp-executor.cpp |
  +-------------+          +---------------------+
    |                       ^
    | creates & fills       | executes, reports coverage
    v                       v
  +--------+               +------------------+
  | Corpus |               | V8 RegExp Engine |
  +--------+               +------------------+
    |
    | has many
    v
  +-------------+
  | CorpusEntry |
  +-------------+
    |
    | has one
    v
  +-----------------+
  | CoverageTracker |
  +-----------------+
```

Some notes:
* Mutation takes place within Corpus
* Any modifications to underlying node/v8 source are found in `mod/`.
