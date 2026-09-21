# System Design

```mermaid
flowchart LR
    B[books.txt] --> BR[Book registry]
    M[members.txt] --> MR[Member registry]
    U[CLI borrow / return] --> V{Validate IDs and loan state}
    BR --> V
    MR --> V
    V -->|valid| S[Create transaction block]
    S --> G[SHA-256 hash]
    S --> E[ECDSA P-256 signature]
    G --> L[previous_hash links]
    L --> C[(chain.dat)]
    E --> C
    C --> Q[view records / validate chain]
```

## Block structure

```text
index | timestamp | book_id | book_title | member_id | member_name |
action | previous_hash | signature | hash
```

The genesis block has index `0` and a previous hash containing 64 zero characters. Each later block stores the previous block's hash. The hash is calculated over all block fields except the signature and final hash; the ECDSA signature authenticates the same canonical transaction payload. Registry values are copied into the block so later registry edits do not rewrite historical events.
