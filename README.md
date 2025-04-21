# Identity-Based Encryption

**Course:** Cryptography and Security Protocols  
**University:** Instituto Superior Técnico  
**Academic year:** 2019-20

### Team

- 73891 — David Gonçalves  ([david.s.goncalves@tecnico.ulisboa.pt](mailto:david.s.goncalves@tecnico.ulisboa.pt))
- 94112 — Gonçalo Pires ([goncalo.estevinho.pires@tecnico.ulisboa.pt](mailto:goncalo.estevinho.pires@tecnico.ulisboa.pt))

## Assignment

- 1st option of [Project List](documentation/ProjectList.pdf).
- [BF01](documentation/Identity-Based_Encryption_from_the_Weil_Pairing.pdf)
- [BLS01](documentation/Short_Signatures_from_the_Weil_Pairing.pdf)

The goal of this project is to implement the Identity-based Encryption scheme of [BF01] based on pairings and discuss
similarities with BLS signature scheme [BLS01].

## Testing

```sh
git clone --recursive -j4 https://gitlab.com/MangaD/cps-project
cd cps-project/src/ecpy
# We use Python 3, so make sure python3 is being used below.
python3 -m pip install --upgrade .
cd ..
python3 test.py
```

## Discussion

Boneh–Lynn–Shacham (BLS) is a signature scheme that allows its users to verify if a signature is authentic. BLS and IBE both use as their base pairing cryptography. Both schemes use bilinear pairing, BLS for verifying signatures and IBE for encrypting and decrypting messages. In both systems security is based on the variant of Computational Diffie–Hellman Assumption (CDH), in our case it is based on Weil Diffie-Hellman Assumption (WDH) as our IBE uses weil pairing.

## Problems

- We could have implemented the `weil_pairing` function ourselves.
- We should have used `symmetric_weil_pairing` function instead of `weil_pairing`, because the later is degenerate. `symmetric_weil_pairing` is only defined for `extendedFInitieFields` in the `ecpy` library.

## Dependencies

- [Elliptic-Curve Cryptography Library](https://github.com/elliptic-shiho/ecpy)