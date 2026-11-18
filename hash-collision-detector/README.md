# Hash Collision Detector

A command-line tool that hashes a set of inputs with MD5, SHA-1, SHA-256 and SHA-512 and reports whenever two **different** inputs produce the **same** digest. It is built on Python's standard `hashlib` and has no third-party dependencies.

## What it does

- Hashes text typed by hand, passed on the command line, or loaded from a file.
- Runs one or several algorithms in a single scan.
- Compares every digest as it is produced and records each collision with both inputs.
- Prints a clear report: algorithm, inputs, hashes, collision verdict and statistics (total inputs, unique hashes, collisions).
- Saves the full report as text or JSON.
- Can compare only the first N bits of each digest, so collisions can be demonstrated in seconds.
- Ships with real MD5 collision test vectors.

## Project structure

```
hash-collision-detector/
├── main.py                 # CLI, interactive menu, demo
├── hash_generator.py       # hashlib wrapper, algorithm names, digest truncation
├── collision_detector.py   # detection engine, statistics, report rendering
├── utils.py                # colours, input parsing, file read/write
├── requirements.txt        # (standard library only)
├── README.md
├── samples/
│   ├── basic_inputs.txt        # clean example (includes one repeated line)
│   ├── many_inputs.txt         # 2,000 inputs for truncated-digest tests
│   └── md5_collision_pair.txt  # two different messages with the same MD5
└── tests/
    └── test_collision_detector.py
```

## Installation

Requirements: Python 3.8 or newer. Nothing else.

```bash
git clone <your-repository-url> hash-collision-detector
cd hash-collision-detector
python3 --version        # confirm 3.8+
```

`requirements.txt` exists for completeness; there are no packages to install.

## Usage

### Interactive menu

```bash
python3 main.py
```

The menu lets you enter inputs manually, scan a file, choose algorithms, set digest truncation, save the last report and run the demo.

### Command line

```bash
# Test typed inputs with SHA-256 (the default)
python3 main.py -t apple banana cherry

# Inputs with spaces need quotes
python3 main.py -t "hello world" "Hello World" -a sha1

# Scan a file with every algorithm and save a report
python3 main.py -f samples/basic_inputs.txt -a all -o report.txt

# JSON report (chosen by the .json extension)
python3 main.py -f samples/basic_inputs.txt -a md5 sha256 -o report.json

# A real MD5 collision (SHA-256 correctly shows no collision for the same data)
python3 main.py -f samples/md5_collision_pair.txt -a md5 sha256

# Find collisions in a 16-bit MD5 digest
python3 main.py -f samples/many_inputs.txt -a md5 --truncate 16

# Guided demonstration
python3 main.py --demo
```

### Options

| Option | Meaning |
|---|---|
| `-t, --text TEXT...` | One or more inputs to test |
| `-f, --file PATH` | Text file, one input per line |
| `-a, --algorithm ALG...` | `md5`, `sha1`, `sha256`, `sha512` or `all` (default `sha256`) |
| `--truncate BITS` | Compare only the first BITS bits of each digest |
| `-o, --output PATH` | Save the report (`.json` writes JSON, anything else text) |
| `--max-display N` | Entries shown on screen per algorithm (default 25; reports list all) |
| `-i, --interactive` | Open the interactive menu |
| `--demo` | Run the guided demonstration |
| `--no-color` | Disable coloured output |

### Input file format

- One input per line.
- Blank lines and lines starting with `#` are ignored.
- A line starting with `hex:` is decoded as raw bytes, for example `hex:00ff10`. This is how binary collision vectors are supplied.
- Other whitespace (including trailing spaces) is part of the input, so `hello` and `hello ` are different inputs.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Scan finished, no collision |
| 1 | At least one collision detected |
| 2 | Error (bad file, bad option, and so on) |

This makes the tool usable in scripts and CI jobs.

## Sample output

```
================================================================
 ALGORITHM: MD5
 Digest   : full 128-bit
================================================================

Inputs and hashes
----------------------------------------------------------------
[1] Input : hex:d131dd02c5e6eec4...  (128 bytes)
    Hash  : 79054025255fb1a26e4bc422aef54eb4
[2] Input : hex:d131dd02c5e6eec4...  (128 bytes)
    Hash  : 79054025255fb1a26e4bc422aef54eb4

Collision analysis
----------------------------------------------------------------
!! COLLISION DETECTED: 1 found !!

 Collision #1
   Algorithm : MD5
   Hash      : 79054025255fb1a26e4bc422aef54eb4
   Differ at : byte offset(s) 19, 45, 59, 83, 109, 123 (6 of 128 bytes differ)

Statistics
----------------------------------------------------------------
 Total inputs tested   : 2
 Distinct inputs       : 2
 Unique hashes         : 1
 Collisions detected   : 1 (YES)
```

## How detection works

1. Each input is hashed and its digest stored in a dictionary keyed by digest.
2. If the digest is new, the input is remembered.
3. If the digest was seen before and the earlier input has **different bytes**, a collision is recorded.
4. If the earlier input is **byte-for-byte identical**, it is counted as a duplicate and not reported, because identical inputs must always give identical hashes.

If three inputs share a digest, two collisions are reported (each against the first).

## Running the tests

```bash
python3 -m unittest discover -s tests -v
```

The tests cover hash correctness against known vectors, algorithm-name handling, truncation, duplicate handling, collision detection (truncated and the real MD5 pair), and file and hex parsing.

## Limitations

- **Accidental collisions are practically unfindable at full length.** For SHA-256 and SHA-512 no collision is known, and for random inputs the chance of finding one by testing inputs is negligible. Expect "no collision" for normal data. Use `--truncate` to see detection working.
- **The tool does not attack hashes.** It checks the inputs you give it. It does not generate collisions; the bundled MD5 vectors are published public test data.
- **SHA-1** has a known practical collision (the 2017 SHAttered attack). That PDF pair is not bundled because of its size; you can supply it as a file of `hex:` lines or use two PDFs converted to hex.
- **Memory use grows with input count.** All distinct inputs and digests are held in memory. Files over 100 MiB are refused.
- **Text is encoded as UTF-8.** The same visible text in a different encoding is a different input. Use `hex:` for exact bytes.
- Input files must be UTF-8 text. One input per line, so inputs containing newlines need the `hex:` form.
- MD5 and SHA-1 are cryptographically broken. They are supported here for analysis and education, not for protecting data.

## License

Provide your own license before publishing (MIT is a common choice for tools like this).
