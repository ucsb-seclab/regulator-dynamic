# REGULATOR

Regulator is a fuzzer / dynamic analysis to detect ReDoS in JavaScript regular
expressions.

Regulator is published in USENIX Security '22.

## Building

First, build the fuzzer. See the README.md under `fuzzer/`

Install the driver requirements:

```
cd driver
pip install -r requirements.txt
```

## Running

The system is run from `driver/main.py`:

```
export REGULATOR_FUZZER=`realpath fuzzer/build/fuzzer_stripped`
cd driver
python3 main.py --help
```

## Artifacts

Artifacts as used in the paper can be found at [https://doi.org/10.5281/zenodo.5669243](https://doi.org/10.5281/zenodo.5669243).

This contains a docker container and a pre-compiled binary. However, the experiment is set up to run our extracted regular expressions: if you would like to run your own, you may wish to use this repository.

## A Note about Byte Width

Irregexp compiles two separate bytecode programs for a regular expression: one for the latin1 charset, and one for the UC16 charset.
The fuzzer can target either one-byte wide (latin1) or two-byte wide (UC16) subject strings.
In most cases, latin1 charset will do fine.

Since v8 automatically collapses latin1-only strings to one-byte width, all subject strings in UC16 mode _must_ include at least one character beyond latin1. This may lead to a false-negative if the attack string must not include any UC16 characters. Likewise, if the attack string must include a UC16 character, then this could also lead to a false-negative when fuzzing in latin1 mode.

