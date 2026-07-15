# AES
AES algorithm implementation using C.

## Disclaimer & Educational Purpose

This repository is a **Proof of Concept (PoC)** implemented for educational purposes. 
The primary goal of this project is to deeply understand the internal mechanics of the AES algorithm and to improve C programming skills (e.g., bitwise operations, memory management, and modularization).

Please **DO NOT** use this implementation in a production environment. 
To optimize execution speed, this code heavily relies on pre-computed Lookup Tables (such as the 1D S-box array). While efficient in software, this approach is vulnerable to **Side-Channel Attacks (specifically, Cache Timing Attacks)**. 

I am constantly learning, feedback is always welcome! If you find any logical bugs or have suggestions for improvement, please feel free to open an **Issue** or submit a **Pull Request**.

# Example
This project uses **the GCC compiler**. Please open your terminal and run commands below in order.

Build the project
```
gcc AES.c Data.c -o aes_program
```

And run:
```
./aes_program
```

### Current Progress: Key Expansion Phase
Currently, the **Key Expansion** module is successfully implemented and tested. The main encryption logic (`AddRoundKey`, `SubBytes`, etc.) is actively under development.

**Execution Output (Key Expansion):**
```text
--- AES-128 Key Expansion result ---
Round  0 Key: 2B7E1516 28AED2A6 ABF71588 09CF4F3C 
Round  1 Key: A0FAFE17 88542CB1 23A33939 2A6C7605 
Round  2 Key: F2C295F2 7A96B943 5935807A 7359F67F 
...      ...
Round  9 Key: AC7766F3 19FADC21 28D12941 575C006E 
Round 10 Key: D014F9A8 C9EE2589 E13F0CC8 B6630CA6
```