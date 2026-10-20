# ADR-0005 — Crypto agility senza primitive custom

- Stato: accettato come design; provider di firma/cifratura/PQC non attivi nella prima slice.
- Data: 2026-10-04.

## Decisione

Definire confini futuri `CryptoProvider`, `KeyStore`, `Signer`, `Verifier`, `KeyAgreement`, `AEAD`, `Hash`. I formati firmati/cifrati includeranno versione protocollo, suite/algorithm ID, key ID, nonce e contesto autenticato, senza downgrade silenzioso. Nessuna private key hardcoded né algoritmo crittografico implementato in proprio.

ML-KEM, ML-DSA e SLH-DSA sono candidati per ruoli differenti, non sostituti universali di tutti gli algoritmi. Hybrid viene scelto soltanto dentro un protocollo qualificato; non si concatenano primitive per inventare un protocollo. Bulk encryption resta simmetrica moderna tramite librerie mantenute. [NIST: standard PQC finalizzati](https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards), verificato 2026-10-04.

## Conseguenze

Serve un piano di migrazione per chiavi, evidence capsules, policy, update e checkpoint longevi, oltre a interoperabilità e performance. CNG/TPM è preferito dove qualificato, ma nessuna disponibilità PQC hardware viene presunta. Il digest SHA-256 dello storage iniziale è integrità non autenticata, non firma e non rende piko “PQC protetto”. Il supporto reale resta una milestone da verificare.

