# profanity2

Profanity is a high performance (probably the fastest!) vanity address generator for Ethereum. Create cool customized addresses that you never realized you needed! Recieve Ether in style! Wow!

![Screenshot](/img/screenshot.png?raw=true "Wow! That's a lot of zeros!")

This fork adds `--match-all` to stream every address matching a hex pattern, and `--checksum` to filter results by EIP-55 capitalization.

# Important to know

A previous version of this project has a known critical issue due to a bad source of randomness. The issue enables attackers to recover private key from public key: https://blog.1inch.io/a-vulnerability-disclosed-in-profanity-an-ethereum-vanity-address-tool

This project "profanity2" was forked from the original project and modified to guarantee **safety by design**. This means source code of this project do not require any audits, but still guarantee safe usage.

Project "profanity2" is not generating key anymore, instead it adjusts user-provided public key until desired vanity address will be discovered. Users provide seed public key in form of 128-symbol hex string with `-z` parameter flag. Resulting private key should be used to be added to seed private key to achieve final private key of the desired vanity address (private keys are just 256-bit numbers). Running "profanity2" can even be outsourced to someone completely unreliable - it is still safe by design.

## Getting public key for mandatory `-z` parameter

Generate private key and public key via openssl in terminal (remove prefix "04" from public key):
```bash
$ openssl ecparam -genkey -name secp256k1 -text -noout -outform DER | xxd -p -c 1000 | sed 's/41534e31204f49443a20736563703235366b310a30740201010420/Private Key: /' | sed 's/a00706052b8104000aa144034200/\'$'\nPublic Key: /'
```

Derive public key from existing private key via openssl in terminal (remove prefix "04" from public key):
```bash
$ openssl ec -inform DER -text -noout -in <(cat <(echo -n "302e0201010420") <(echo -n "PRIVATE_KEY_HEX") <(echo -n "a00706052b8104000a") | xxd -r -p) 2>/dev/null | tail -6 | head -5 | sed 's/[ :]//g' | tr -d '\n' && echo
```

## Adding private keys (never use online calculators!)

### add_keys.py (recommended)

Use the included `add_keys.py` script to generate the final private key and derive the Ethereum address:
```bash
python3 add_keys.py
```

Best run this on an air-gapped machine.

Requires Python 3.6+, no external dependencies.

### Terminal:

Use private keys as 64-symbol hexadecimal string WITHOUT `0x` prefix:
```bash
(echo 'ibase=16;obase=10' && (echo '(PRIVATE_KEY_A + PRIVATE_KEY_B) % FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F' | tr '[:lower:]' '[:upper:]')) | bc
```

### Python

Use private keys as 64-symbol hexadecimal string WITH `0x` prefix:
```bash
$ python3
>>> hex((PRIVATE_KEY_A + PRIVATE_KEY_B) % 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F)
```

# Usage
```
usage: ./profanity2 [OPTIONS]

  Mandatory args:
    -z                      Seed public key to start, add it's private key
                            to the "profanity2" resulting private key.
                            The 04 prefix is stripped automatically if present.

  Basic modes:
    --benchmark             Run without any scoring, a benchmark.
    --zeros                 Score on zeros anywhere in hash.
    --letters               Score on letters anywhere in hash.
    --numbers               Score on numbers anywhere in hash.
    --mirror                Score on mirroring from center.
    --leading-doubles       Score on hashes leading with hexadecimal pairs
    -b, --zero-bytes        Score on hashes containing the most zero bytes

  Modes with arguments:
    --leading <single hex>   Score on hashes leading with given hex character.
    --matching <hex string>  Score on hashes matching given hex string.
    --match-all <hex string> Output all addresses satisfying the given hex string.
    --checksum <N>           Requires --match-all. Filters results by EIP-55 checksum
                             capitalization. Targets at least N results (N >= 1).

  Advanced modes:
    --contract              Instead of account address, score the contract
                            address created by the account's zeroth transaction.
    --leading-range         Scores on hashes leading with characters within
                            given range.
    --range                 Scores on hashes having characters within given
                            range anywhere.

  Range:
    -m, --min <0-15>        Set range minimum (inclusive), 0 is '0' 15 is 'f'.
    -M, --max <0-15>        Set range maximum (inclusive), 0 is '0' 15 is 'f'.

  Device control:
    -s, --skip <index>      Skip device given by index.
    -n, --no-cache          Don't load cached pre-compiled version of kernel.

  Tweaking:
    -w, --work <size>       Set OpenCL local work size. [default = 64]
    -W, --work-max <size>   Set OpenCL maximum work size. [default = -i * -I]
    -i, --inverse-size      Set size of modular inverses to calculate in one
                            work item. [default = 255]
    -I, --inverse-multiple  Set how many above work items will run in
                            parallell. [default = 16384]
    -q, --quit-score <N>    In score modes: quit when score reaches N.
                            In --match-all: quit after N addresses found.
                            [default = 0 (off), ignored with --checksum]

  Examples:
    ./profanity2 --leading f -z HEX_PUBLIC_KEY_128_CHARS_LONG
    ./profanity2 --matching dead -z HEX_PUBLIC_KEY_128_CHARS_LONG
    ./profanity2 --matching badXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXbad -z HEX_PUBLIC_KEY_128_CHARS_LONG
    ./profanity2 --match-all 1337XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXC0DE -z HEX_PUBLIC_KEY_128_CHARS_LONG
    ./profanity2 --match-all 1337_C0DE -q 5 -z HEX_PUBLIC_KEY_128_CHARS_LONG
    ./profanity2 --match-all C0FFEE --checksum 10 -z HEX_PUBLIC_KEY_128_CHARS_LONG
    ./profanity2 --match-all _C0FFEE --checksum 3 -z HEX_PUBLIC_KEY_128_CHARS_LONG
    ./profanity2 --leading-range -m 0 -M 1 -z HEX_PUBLIC_KEY_128_CHARS_LONG
    ./profanity2 --leading-range -m 10 -M 12 -z HEX_PUBLIC_KEY_128_CHARS_LONG
    ./profanity2 --range -m 0 -M 1 -z HEX_PUBLIC_KEY_128_CHARS_LONG
    ./profanity2 --contract --leading 0 -z HEX_PUBLIC_KEY_128_CHARS_LONG
    ./profanity2 --contract --zero-bytes -z HEX_PUBLIC_KEY_128_CHARS_LONG

  About:
    profanity2 is a vanity address generator for Ethereum that utilizes
    computing power from GPUs using OpenCL.

  Forked "profanity2" (this fork):
    Author: borj404 <borj404@proton.me>
    Disclaimer:
      Added --match-all mode for streaming all matching addresses
      and --checksum for EIP-55 capitalization filtering.
      No cryptographic logic or safety mechanisms from profanity2 were modified.

  Forked "profanity2":
    Author: 1inch Network <info@1inch.io>
    Disclaimer:
      This project "profanity2" was forked from the original project and
      modified to guarantee "SAFETY BY DESIGN". This means source code of
      this project doesn't require any audits, but still guarantee safe usage.

  From original "profanity":
    Author: Johan Gustafsson <profanity@johgu.se>
    Beer donations: 0x000dead000ae1c8e8ac27103e4ff65f42a4e9203
    Disclaimer:
      Always verify that a private key generated by this program corresponds to
      the public key printed by importing it to a wallet of your choice. This
      program like any software might contain bugs and it does by design cut
      corners to improve overall performance.
```

## Pattern shorthand for `--matching` and `--match-all`

Instead of typing a full 40-char pattern, use `_` as a fill separator in both `--matching` and `--match-all`:

| Input | Equivalent |
|:------|:-----------|
| `C0FFEE` | `C0FFEEXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX` (prefix) |
| `_C0FFEE` | `XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXC0FFEE` (suffix) |
| `1337_C0DE` | `1337XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXC0DE` (prefix+suffix) |

Full 40-char patterns are passed through unchanged. Both `X` and `_` act as wildcards.

## EIP-55 checksum filtering (`--checksum`)

Each hex letter in the pattern has a 50% chance of matching its EIP-55 capitalization. For a pattern with N hex letters the probability per address is `(1/2)^N`.

The GPU collects raw matching addresses case-insensitively, then the CPU applies EIP-55 checksum to each candidate and keeps only those where the letter casing matches the pattern exactly.

| Hex letters | Probability | Internal target for `--checksum 1` |
|:-----------:|:-----------:|:----------------------------------:|
| 1 | 50% | 8 |
| 3 | 12.5% | 32 |
| 5 | ~3.1% | 128 |
| 6 | ~1.6% | 256 |
| 8 | ~0.4% | 1024 |
| 10 | ~0.1% | 4096 |

Pattern capitalization matters: `C0FFEE` finds addresses where those letters are uppercase in their EIP-55 checksum; `c0ffee` finds lowercase.

### Benchmarks - Current version
|Model|Clock Speed|Memory Speed|Modified straps|Speed|Time to match eight characters
|:-:|:-:|:-:|:-:|:-:|:-:|
|GTX 1070 OC|1950|4450|NO|179.0 MH/s| ~24s
|GTX 1070|1750|4000|NO|163.0 MH/s| ~26s
|RX 480|1328|2000|YES|120.0 MH/s| ~36s
|RTX 4090|-|-|-|1096 MH/s| ~3s
|Apple Silicon M1<br/>(8-core GPU)|-|-|-|45.0 MH/s| ~97s
|Apple Silicon M1 Max<br/>(32-core GPU)|-|-|-|172.0 MH/s| ~25s
|Apple Silicon M3 Pro<br/>(18-core GPU)|-|-|-|97 MH/s| ~45s
|Apple Silicon M4 Max<br/>(40-core GPU)|-|-|-|350 MH/s| ~12s

