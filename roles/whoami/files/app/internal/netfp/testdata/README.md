`clienthellos.json` holds TLS ClientHello records extracted from the sample
captures in FoxIO's JA4 repository (https://github.com/FoxIO-LLC/ja4, `pcap/`).
Expected JA4 and JA4_r values are that project's own snapshot outputs
(`rust/ja4/src/snapshots`); expected JA3 values come from Wireshark's
implementation. JA4 (TLS client fingerprinting) is BSD 3-Clause, Copyright (c)
2026 FoxIO: see `LICENSE-JA4.txt`. This service implements only JA4, not the
separately licensed JA4+ methods.

One vector deliberately differs from FoxIO's tools: for a non-ASCII first ALPN
value, JA4.md specifies the first and last hex characters, which is what
Wireshark and this implementation output; FoxIO's tools still substitute `99`.
