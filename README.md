# jubjub-vs-bandersnatch

![image](https://github.com/user-attachments/assets/cccbc840-bcce-40b0-ba7a-43c3c7835d5b)

## Benchmark

- R1CS

Curve | Generic | 2D hinted GLV | 4D hinted GLV (with `Mux`) | 4D Fake GLV (with `logup`)  |
------|---------|------|----------------------|--------------------------------------------|
Jubjub          |  3314  |  2401   | - | - |
Bandersnatch    |  3314  |  2420   | 4552 | 2692 |


- SCS

Curve | Generic | 2D hinted GLV | 4D hinted GLV (with `Mux`) | 4D Fake GLV (with `logup`)  |
------|---------|------|----------------------|--------------------------------------------|
Jubjub          |  5863  |  4549   | - | - |
Bandersnatch    |  5863  |  4712   | 11027 | 6721 |

