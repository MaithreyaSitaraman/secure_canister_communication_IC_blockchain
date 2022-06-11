# Secure Canister Communication on the IC Blockchain
Submitted to the Supernova Hackathon by Cramium Inc.

## Summary

We provide a framework where messages can be securely passed between canisters, i.e to avoid man-in-the-middle attacks. Our solution can allow secrets such as email addresses, passwords or device ids to be securely communicated between canisters without being compromised by evesdroppers. Such a solution does not yet exist as a project deployed on IC, and we therefore believe we are making important contribution towards the futures of the IC, opening up the possibilities to a wide range of business applications, which rely on secrets being securely transmitted.

Our solution in a nutshell comprises of a sender and a receiver. The sender and receiver perform a public key exchange to independently arrive at a secret AES key which cannot be known to an evesdropper. The sender then sends AES encrypted data to the receiver which is then decrypted on the receiver's side.

## Encryption Modules we built

We use the Diffie-Hellman key exchange together with AES-238, both for which we built original modules in motoko (see /encryption_modules/AES.mo and /encryption_modules/diffiehellman.mo). AES makes use of multiplication in polynomial rings, and we therefore wrote a mathematical module to handle this (see /encryption_modules/polynomial_handling.mo). We are the first to implement AES, Diffie-Hellman, and multiplication in polynomial rings in Motoko.

## How to run our solution

Choose your secret message that should be communicated securely. For this example, our message is "My secret password is FireWater45_1991". 

Now, run: dfx canister call sender send_secure_message '("My secret password is FireWater45_1991")'

Your debug output will look like this (i.e this will be printed out for demonstration purposes):

*[Canister rrkah-fqaaa-aaaaa-aaaaq-cai] Receiver: I have independently computed the AES secret key, and it is f882c3e88feeaad705db052c13cce66b
*[Canister ryjl3-tyaaa-aaaaa-aaaba-cai] Sender: I have independently computed the AES secret key, and it is f882c3e88feeaad705db052c13cce66b
*[Canister ryjl3-tyaaa-aaaaa-aaaba-cai] Sender: The raw hex data (before encryption) is 4d79207365637265742070617373776f72642069732046697265576174657234355f31393931
*[Canister ryjl3-tyaaa-aaaaa-aaaba-cai] Sender: The encrypted message we are sending to the Receiver is 481b2a540f7503a5aa12248c812060d873d0e888862a7c0dc8fee4fb3fed2e329189c1ab8bbbeb2d93e4e9b43de9f228
*[Canister rrkah-fqaaa-aaaaa-aaaaq-cai] Receiver: The encrypted message I have received is 481b2a540f7503a5aa12248c812060d873d0e888862a7c0dc8fee4fb3fed2e329189c1ab8bbbeb2d93e4e9b43de9f228
*[Canister rrkah-fqaaa-aaaaa-aaaaq-cai] Receiver: The decrypted message using my AES secret key is: My secret password is FireWater45_1991

Basically, the debug output is telling us that:
* both the Receiver and Sender have independently computed the AES secret key, their keys match.
* The Sender has converted the secret message into hex, encrypted it, and sent the encrypted data to the Receiver
* The Receiver has received the correct encrypted data, and has decrypted it correctly as the original message

To further demonstrate that the message has been received successfully, you can run: dfx canister call receiver view_decrypted_received_message

This will return: ("My secret password is FireWater45_1991")

That is, the Receiver has decrypted the message successfully and stored it in a variable on that canister (for demonstration purposes) which is then being accessed.

## Decentralization could, in the future, prove to be a better than Centralization from a security perspective


