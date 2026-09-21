# Library Lending Blockchain

A C command-line application that records library borrowing and returning events in a tamper-evident blockchain. Books and members are loaded from registries before the CLI starts. Each transaction is SHA-256 hashed, linked to the preceding block, digitally signed with an ECDSA P-256 private key, and persisted to `chain.dat`.

## Requirements

- C11 compiler
- OpenSSL 3.x development package (`libssl-dev` on Debian/Ubuntu, or the MSYS2 `mingw-w64-x86_64-openssl` package)

## Build and run

Linux/macOS:

```sh
make
./library_tracker
```

Windows with MSYS2 UCRT64:

```sh
pacman -S mingw-w64-ucrt-x86_64-gcc mingw-w64-ucrt-x86_64-openssl
make CC=/ucrt64/bin/gcc
env MSYSTEM=UCRT64 MSYSTEM_PREFIX=/ucrt64 PATH=/ucrt64/bin:/usr/bin:/bin ./library_tracker.exe
```

The Makefile supplies the UCRT64 environment automatically when `/ucrt64/bin/gcc` is used from an MSYS shell. The `env` prefix on the run command exposes the matching UCRT64 runtime DLLs as well.

The first run creates an ECDSA P-256 private key in `library_private.pem`, creates a genesis block, and saves the chain in `chain.dat`. Keep the key with the chain: signatures from a different key will not verify.

## CLI demonstration

```text
borrow BK001 ALU001
borrow BK001 ALU002        # rejected: already on loan
borrow BK999 ALU001        # rejected: invalid book
return BK001 ALU001
view
validate
tamper
exit
```

`tamper` changes a past block in memory, shows validation failure, then reloads the last persisted chain so the demonstration does not permanently corrupt the file.

## Persistence and validation

`books.txt` and `members.txt` are mandatory comma-separated registries. Empty or missing files stop startup. `chain.dat` stores the binary block array. Every block hash covers its index, timestamp, registry snapshots, action, and previous hash. Validation recomputes each hash and checks every link. Signatures are verified when records are viewed.

## Submission checklist

- Source: `library_tracker.c`
- Registry inputs: `books.txt`, `members.txt`
- Build instructions: this README
- System design: [DESIGN.md](DESIGN.md)
- Report outline: [REPORT.md](REPORT.md)
- Demo: record startup, valid and invalid commands, `view`, `validate`, and `tamper`
