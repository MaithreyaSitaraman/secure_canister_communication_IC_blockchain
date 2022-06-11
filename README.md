# Secure Canister Communication on the IC Blockchain
Submitted to the Supernova Hackathon by Cramium Inc.

## Summary

We provide a framework where messages can be securely passed between canisters, i.e to avoid man-in-the-middle attacks. Our solution can allow secrets such as email addresses, passwords or device ids to be securely communicated between canisters without being compromised by evesdroppers. Such a solution does not yet exist as a project deployed on IC, and we therefore believe we are making important contribution towards the futures of the IC, opening up the possibilities to a wide range of business applications, which rely on secrets being securely transmitted.

Our solution in a nutshell comprises of a sender and a receiver. The sender and receiver perform a public key exchange to independently arrive at a secret AES key which cannot be known to an evesdropper. The sender then sends AES encrypted data to the receiver which is then decrypted on the receiver's side.

## Encryption Modules we built

We use the Diffie-Hellman key exchange together with AES-238, both for which we built original modules in motoko (see /encryption_modules/AES.mo and /encryption_modules/diffiehellman.mo). AES makes use of multiplication in polynomial rings, and we therefore wrote the mathematical module /encryption_modules/polynomial_handling.mo.

## How to run our solution



## 


