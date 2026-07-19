# AES
AES algorithm implementation using C.

## Disclaimer & Educational Purpose

This repository is a **Proof of Concept (PoC)** implemented for educational purposes. 
The primary goal of this project is to deeply understand the internal mechanics of the AES algorithm and to improve C programming skills (e.g., bitwise operations, memory management, and modularization).

Please **DO NOT** use this implementation in a production environment. 
To optimize execution speed, this code heavily relies on pre-computed Lookup Tables (such as the 1D S-box array). While efficient in software, this approach is vulnerable to **Side-Channel Attacks (specifically, Cache Timing Attacks)**. 

I am constantly learning, feedback is always welcome! If you find any logical bugs or have suggestions for improvement, please feel free to open an **Issue** or submit a **Pull Request**.

# Build and Run
This project uses **the GCC compiler**. Please open your terminal and run commands below in order.

1. Build the project
```
gcc main.c AES.c data.c -o aes_program
```

2. And run:
```
./aes_program
```

3. Expected Output
When you run the program, it will execute both AES-128 and AES-256 encryption tests using the official NIST test vectors.
```
=== AES-128 Encryption ===
Plaintext : 32 43 f6 a8 88 5a 30 8d 31 31 98 a2 e0 37 07 34 
Key (128) : 2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c 
Ciphertext: 39 25 84 1d 02 dc 09 fb dc 11 85 97 19 6a 0b 32 

=== AES-256 Encryption ===
Plaintext : 32 43 f6 a8 88 5a 30 8d 31 31 98 a2 e0 37 07 34 
Key (256) : 60 3d eb 10 15 ca 71 be 2b 73 ae f0 85 7d 77 81 1f 35 2c 07 3b 61 08 d7 2d 98 10 a3 09 14 df f4 
Ciphertext: 30 21 61 3a 97 3e 58 2f 4a 29 23 41 37 ae c4 94
```

## References
National Institute of Standards and Technology (2001) Advanced Encryption Standard (AES). (Department of Commerce, Washington, D.C.), Federal Information Processing Standards Publication (FIPS) NIST FIPS 197, updated May 9, 2023. https://doi.org/10.6028/NIST.FIPS.197-upd1