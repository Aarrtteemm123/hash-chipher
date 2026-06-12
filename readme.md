The algorithm processes the message as a sequence of bytes. The current state of the key is used for each byte. A hash is computed from the key, and its first byte acts as an XOR mask. Before this, a 64-byte BLAKE3 hash of the input data is additionally computed: it is mixed with the initial key and participates in each encryption step as context. Next, a key step occurs, and the algorithm selects a salt value. The search continues until the first byte of the resulting hash matches the target value, which was calculated from the initial byte and the XOR mask. The found salt is stored in the ciphertext. After that, the key is updated (again via SHA-256), and the next byte is processed using the new key. Each step depends on the previous state. At the end, a BLAKE3 hash (as a number) is added to the ciphertext to verify the message’s integrity during decryption: if the hash does not match, the data is considered altered.

# Architecture Encryption Algorithm (HashCipherV2)

## Basic Components

* $H(x)$ — Cryptographic hash function SHA-256 (returns 32 bytes).
* $H_{fast}(x)$ — Fast extendable-output function (XOF) BLAKE3 (fixed output length set to 64 bytes).
* $S$ — Initial secret (password, passphrase).
* $D$ — Input data as an array of bytes ($D_0, D_1, \dots, D_n$) to be encrypted.
* $D_{hash}$ — Global fingerprint of the input data (message context).
* $K_i$ — Current working key state for processing the $i$-th data byte.
* $C$ — Output ciphertext array (sequence of found $salt$ values plus the checksum at the end).
* $\parallel$ — Concatenation operator (joining byte arrays together).

---

## Encryption Process

### Stage 1: State and Context Initialization
First, generate the base key $K_{base}$ from the secret $S$:
$$K_{base} = H(S)$$

Next, compute a 64-byte fingerprint of the entire input data array $D$. This establishes the unique message context:
$$D_{hash} = H_{fast}(D)$$

The initial working key $K_0$ is formed by irreversibly mixing the base key, the data fingerprint, and an initialization marker:
$$K_0 = H(K_{base} \parallel D_{hash} \parallel \text{"|init-key|"})$$

### Stage 2: Main Loop (for each byte $D_i$)
1. **Mask Calculation:** Hash the current key together with the context and the mask marker. Take the first byte of the result:
   $$Mask_i = \text{FirstByte}(H(K_i \parallel D_{hash} \parallel \text{"|mask|"}))$$
2. **Target Generation:** Mix the current data byte $D_i$ with the mask using a bitwise XOR:
   $$Target_i = D_i \oplus Mask_i$$
3. **Proof-of-Work (Brute-force):** Start iterating an integer $salt_i$ (from 0 upwards). Check the condition — whether the first byte of the new hash matches our target value:
   $$\text{FirstByte}(H(K_i \parallel D_{hash} \parallel salt_i \parallel \text{"|salt|"})) == Target_i$$
   As soon as the condition is met, the loop stops, and $salt_i$ is appended to the output array $C$.
4. **State Update:** The key is updated for the next iteration using a transition marker to ensure unique parameters for the subsequent byte:
   $$K_{i+1} = H(K_i \parallel D_{hash} \parallel \text{"|next-key|"})$$
   The algorithm proceeds to the next byte $D_{i+1}$.

### Stage 3: Finalization (Integrity Control)
After the loop completes, the fingerprint $D_{hash}$ is converted into a numeric value and appended to the very end of the ciphertext array $C$ as an authenticity marker.

---

## Decryption Process

### Stage 1: Context Extraction and Initialization
The array $C$ is provided as input. The last element is extracted — this is our $D_{hash}$. The remainder of the array ($salt_0, \dots, salt_n$) will be used to recover the data.

The base key is formed, and the identical initial working state is restored:
$$K_{base} = H(S)$$
$$K_0 = H(K_{base} \parallel D_{hash} \parallel \text{"|init-key|"})$$

### Stage 2: Main Loop (for each $salt_i$)
1. **Mask Restoration:** The mask is generated from the current key state using the same algorithm:
   $$Mask_i = \text{FirstByte}(H(K_i \parallel D_{hash} \parallel \text{"|mask|"}))$$
2. **Target Byte Calculation:** Using the known $salt_i$ value from the ciphertext, recreate the $Target_i$ value that the system originally searched for via brute-force:
   $$Target_i = \text{FirstByte}(H(K_i \parallel D_{hash} \parallel salt_i \parallel \text{"|salt|"}))$$
3. **Original Byte Restoration:** The original data byte $D_i$ is recovered via a reverse XOR operation:
   $$D_i = Target_i \oplus Mask_i$$
4. **State Update:** The key is updated to maintain perfect synchronization with the encryption process:
   $$K_{i+1} = H(K_i \parallel D_{hash} \parallel \text{"|next-key|"})$$

### Stage 3: Integrity Verification (Authentication)
All recovered bytes are sequentially combined into a new array $D_{recovered}$. To confirm that the ciphertext has not been modified or corrupted, compute a new hash:
$$Check_{hash} = H_{fast}(D_{recovered})$$

If $Check_{hash} \neq D_{hash}$, the system generates a critical error ("Integrity Violation / Corrupted Data"). If the values match perfectly, the algorithm successfully returns the original array $D$.