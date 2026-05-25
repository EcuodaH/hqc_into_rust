# Architecture du projet HQC — Documentation détaillée

**Version :** HQC-256
**Langage :** Rust 2024 

---

## Table des matières

1. [Vue d'ensemble](#1-vue-densemble)
2. [Paramètres cryptographiques](#2-paramètres-cryptographiques)
3. [Structure des fichiers](#3-structure-des-fichiers)
4. [Couche KEM — interface publique](#4-couche-kem--interface-publique)
5. [Couche PKE — chiffrement sous-jacent](#5-couche-pke--chiffrement-sous-jacent)
6. [Arithmétique polynomiale GF(2)[X]](#6-arithmétique-polynomiale-gf2x)
7. [Vecteurs épars et échantillonnage](#7-vecteurs-épars-et-échantillonnage)
8. [Code correcteur d'erreurs](#8-code-correcteur-derreurs)
9. [Primitives symétriques](#9-primitives-symétriques)
10. [Structures de données](#10-structures-de-données)
11. [Sérialisation](#11-sérialisation)
12. [Flot d'exécution complet](#12-flot-dexécution-complet)
13. [Choix d'implémentation Rust](#13-choix-dimplémentation-rust)

---

## 1. Vue d'ensemble

HQC est un **KEM post-quantique** basé sur la difficulté de décoder des codes linéaires aléatoires
dans un anneau quasi-cyclique. La structure est en deux couches :

```
┌──────────────────────────────────────────────┐
│  KEM (kem.rs)                                │
│  crypto_kem_keypair / _enc / _dec            │
│  Transform Fujisaki-Okamoto                  │
├──────────────────────────────────────────────┤
│  PKE (hqc.rs)                                │
│  hqc_pke_keygen / _encrypt / _decrypt        │
│  Chiffrement LWE quasi-cyclique + codage     │
├────────────────┬────────────────┬────────────┤
│  gf2x          │  code          │ symmetric  │
│  Multiplication│  RS + RM       │ SHA3/SHAKE │
│  GF(2)[X]      │  correcteurs   │            │
├────────────────┼────────────────┼────────────┤
│  vector        │  reed_solomon  │  parsing   │
│  Vect épars    │  reed_muller   │  sérialisa.│
│  échantillon.  │  fft / gf      │            │
└────────────────┴────────────────┴────────────┘
```

La sécurité repose sur deux problèmes difficiles :
- **Syndrome Decoding Problem (SDP)** : trouver un vecteur d'erreur `e` connaissant `H·eᵀ = s`
- **Quasi-Cyclic version** : la structure quasi-cyclique compresse les clés d'un facteur N

---

## 2. Paramètres cryptographiques

Définis dans `src/parameters.rs` — tout le code y fait référence via des constantes.

| Constante | Valeur | Signification |
|-----------|--------|---------------|
| `PARAM_N` | 17 669 | Longueur des vecteurs dans GF(2)^N (dimension de l'anneau) |
| `PARAM_N1` | 46 | Longueur du code Reed-Solomon (en symboles GF(2^8)) |
| `PARAM_N2` | 384 | Longueur d'un mot de code Reed-Muller (en bits) |
| `PARAM_N1N2` | 17 664 | Longueur totale du code (N1 × N2 = 46 × 384) |
| `PARAM_OMEGA` | 66 | Poids de Hamming des clés secrètes x, y |
| `PARAM_OMEGA_R` | 75 | Poids de Hamming des vecteurs aléatoires r1, r2 |
| `PARAM_OMEGA_E` | 75 | Poids de Hamming du bruit e |
| `PARAM_DELTA` | 15 | Capacité de correction Reed-Solomon (corrige ≤ 15 erreurs) |
| `PARAM_M` | 8 | Degré de l'extension GF(2^8) |
| `PARAM_K` | 16 | Dimension du message (en octets) |
| `PARAM_SECURITY_BYTES` | 16 | Taille du secret interne m (128 bits) |

### Tailles des objets

| Objet | Calcul | Taille |
|-------|--------|--------|
| Clé publique `ek` | seed (32) + s en octets (2210) | **2 241 B** |
| Clé secrète `dk` | ek + seed_dk (32) + σ (16) + seed_kem (32) | **2 321 B** |
| Chiffré `ct` | u (2210) + v (2208) + salt (16) | **4 433 B** |
| Secret partagé | — | **32 B** |

---

## 3. Structure des fichiers

```
hqc/
├── src/
│   ├── lib.rs            — exports publics de la bibliothèque
│   ├── main.rs           — binaire minimal (run_kat)
│   ├── parameters.rs     — toutes les constantes cryptographiques
│   ├── data_structures.rs— types: CiphertextPke, CiphertextKem, RmCodeword
│   │
│   ├── kem.rs            — KEM public : keypair, enc, dec
│   ├── hqc.rs            — PKE : keygen, encrypt, decrypt
│   │
│   ├── gf2x.rs           — multiplication GF(2)[X] / (X^N − 1)
│   ├── vector.rs         — vecteurs sur GF(2)^N, échantillonnage épars
│   │
│   ├── code.rs           — encode/decode (orchestration RS + RM)
│   ├── reed_solomon.rs   — code RS(46,16,15)
│   ├── reed_muller.rs    — code RM(1,7) × MULTIPLICITY
│   ├── fft.rs            — FFT additive sur GF(2^8)
│   ├── gf.rs             — arithmétique GF(2^8) : mul, square, inverse
│   ├── tables.rs         — tables de log/antilog GF(2^8)
│   │
│   ├── symmetric.rs      — SHA3-256/512, SHAKE256, fonctions de domaine
│   └── parsing.rs        — sérialisation/désérialisation clés et chiffrés
│
├── tests/
│   ├── kats.rs - Test des Kats
│   ├── prng_tests.rs - Test unitaire de prng
│   ├── PQCkemKAT_2321.req (ASK)
│   └── PQCkemKAT_2321.rsp — 100 vecteurs KAT (Avec réponses, seul utile dans le projet)
└── Cargo.toml
```

---

## 4. Couche KEM — interface publique

**Fichier :** `src/kem.rs`

C'est la seule interface que les utilisateurs finaux appellent. Elle élève le PKE sous-jacent en KEM.

### 4.1 `crypto_kem_keypair(ek_kem, dk_kem, ctx)`

```
ctx (PRNG) → seed_kem (32 B)
              │
              └─ SHAKE256(seed_kem) → seed_pke (32 B), σ (16 B)
                                        │
                                        └─ hqc_pke_keygen(seed_pke) → ek_pke, dk_pke

dk_kem = ek_pke ‖ dk_pke ‖ σ ‖ seed_kem   (concatenation)
ek_kem = ek_pke
```

La clé secrète KEM contient `seed_kem` pour régénérer aléatoirement σ en cas d'échec de décryption.

### 4.2 `crypto_kem_enc(ct, ss, ek, ctx)`

```
ctx → m (16 B aléatoires), salt (16 B)
H = SHA3-256(ek)
(K ‖ θ) = SHA3-512(H ‖ m ‖ salt)        ← K : secret partagé, θ : graine d'enc
c = hqc_pke_encrypt(ek, m, θ)
ct = c ‖ salt
ss = K
```

### 4.3 `crypto_kem_dec(ss, ct, dk)`

```
Extraire ek, dk_pke, σ depuis dk
Extraire c, salt depuis ct
m' = hqc_pke_decrypt(dk_pke, c)
H  = SHA3-256(ek)
(K' ‖ θ') = SHA3-512(H ‖ m' ‖ salt)
c'  = hqc_pke_encrypt(ek, m', θ')       ← ré-encryption
K̄  = SHA3-256(H ‖ σ ‖ c ‖ salt)        ← valeur de repli

ss = K'  si c == c'                      ← comparaison temps-constant
     K̄   sinon
```

La ré-encryption est la clé de la sécurité : si l'attaquant modifie `c`,
la comparaison échoue et il reçoit une valeur aléatoire `K̄` sans information.

---

## 5. Couche PKE — chiffrement sous-jacent

**Fichier :** `src/hqc.rs`

Le PKE HQC est un chiffrement de type **McEliece-like** dans l'anneau quasi-cyclique.

### 5.1 Génération de clés `hqc_pke_keygen(ek, dk, seed)`

```
(seed_dk ‖ seed_ek) = SHA3-512(seed)      ← déterminisme depuis une graine

dk = seed_dk                               ← clé secrète = graine pour régénérer y
ek = seed_ek ‖ s

Génération interne :
  SHAKE256(seed_dk) → y (poids OMEGA), x (poids OMEGA)   ← vecteurs épars secrets
  SHAKE256(seed_ek) → h (vecteur aléatoire)               ← vecteur public
  s = y·h + x   (dans GF(2)[X]/(X^N − 1))                ← clé publique partielle
```

La clé secrète est simplement une **graine de 32 octets** : `y` et `x` sont régénérés à la demande.
La clé publique expose `h` (déterministe depuis seed_ek) et `s = y·h + x` (problème SDP).

### 5.2 Chiffrement `hqc_pke_encrypt(c, ek, m, θ)`

```
Décodage de ek → h, s

SHAKE256(θ) → r2 (poids OMEGA_R), e (poids OMEGA_E), r1 (poids OMEGA_R)

u = r2·h + r1                             ← première composante du chiffré
v = encode(m) + trunc(r2·s + e)           ← deuxième composante du chiffré
c = (u, v)
```

`encode(m)` transforme les 16 octets de message en un vecteur de 17664 bits via RS + RM.
`trunc` tronque à N1×N2 = 17664 bits (le résultat de la multiplication est de longueur N).

### 5.3 Déchiffrement `hqc_pke_decrypt(m, dk, c)`

```
Régénérer y depuis dk (seed)

tmp = y·u                                 ← exploit de la structure quasi-cyclique
v' = v + trunc(y·u)                       ← enlever le bruit
     = encode(m) + trunc(r2·s + e) + trunc(y·(r2·h + r1))
     = encode(m) + trunc(r2·(y·h) + e + y·r1)
     = encode(m) + BRUIT

m = decode(v')                            ← correction d'erreurs
```

Le bruit résiduel `r2·(y·h - s) + e + y·r1 = r2·(-x) + e + y·r1` est de poids
borné — les paramètres garantissent que le décodage réussit avec probabilité `1 - 2^{-128}`.

---

## 6. Arithmétique polynomiale GF(2)[X]

**Fichier :** `src/gf2x.rs`

C'est le **goulot d'étranglement** : ~98 % du temps CPU.

### 6.1 L'anneau de travail

On travaille dans `GF(2)[X] / (X^N − 1)` avec N = 17 669 (premier, garantissant une structure simple).
Les polynômes sont représentés comme des tableaux de `u64` (17669 bits → 277 mots de 64 bits).

### 6.2 `vect_mul(o, a1, a2)`

1. **Multiplication non réduite** via `karatsuba_mul` : résultat de longueur 2N
2. **Réduction modulo X^N − 1** via `reduce` : ramène à longueur N

### 6.3 Algorithme de Karatsuba

L'algorithme divise le polynôme en deux moitiés `A = A_lo + X^m·A_hi` :

```
A × B = A_lo·B_lo  +  X^{2m}·(A_hi·B_hi)  +  X^m·[(A_lo+A_hi)·(B_lo+B_hi) - A_lo·B_lo - A_hi·B_hi]
```

3 récursions au lieu de 4 → complexité `O(n^{log₂3}) ≈ O(n^{1.585})` vs `O(n²)` naïf.

La récursion s'arrête quand `n ≤ 16` (seuil `KARATSUBA_THRESHOLD`) et bascule sur `schoolbook_mul`.

```
karatsuba_mul(n=277)
  ├─ karatsuba_mul(n=139)
  │    ├─ karatsuba_mul(n=70)
  │    │    └─ ... jusqu'à n≤16 → schoolbook_mul
  │    └─ ...
  └─ ...
```

### 6.4 `schoolbook_mul`

Boucle double sur les mots de 64 bits avec shift bit-à-bit. Pour chaque bit de `a[i]`,
applique `b` décalé via `(b[j] << bit) | (b[j] >> (64-bit))`.

### 6.5 Réduction `reduce`

Exploite `X^N ≡ 1 (mod X^N − 1)` : les coefficients de degré ≥ N se "replient" sur les degrés bas.

```rust
o[i] = a[i] ^ (a[i + N_64 - 1] >> (N % 64)) ^ (a[i + N_64] << (64 - N % 64))
```

---

## 7. Vecteurs épars et échantillonnage

**Fichier :** `src/vector.rs`

Les vecteurs secrets (x, y, r1, r2, e) sont **épars** : seulement 66 ou 75 bits à 1 sur 17 669.
Ils sont représentés comme des tableaux de `u64` (format dense) mais générés via leur **support**
(liste des positions des bits à 1).

### 7.1 `vect_generate_random_support1` — méthode par rejet

```
Lire 3 octets aléatoires → entier 24 bits
Si > seuil de rejet (16 767 881) : recommencer   ← évite le biais
Réduire mod N par Barrett                          ← pas de division coûteuse
Vérifier l'absence de doublon                      ← unicité du support
```

La borne de rejet `UTILS_REJECTION_THRESHOLD = 16 767 881` est calculée pour que le résidu
modulo N soit uniformément distribué sur [0, N-1].

### 7.2 `vect_generate_random_support2` — méthode Fisher-Yates

Génère directement un échantillon sans rejet (plus rapide, utilisée pour r1, r2, e) :

```
Pour i = 0..weight :
  buf = rand_u32[i]
  support[i] = i + (buf × (N - i)) >> 32

Puis dé-duplication en temps constant (compare_u32 via masques).
```

### 7.3 `vect_write_support_to_vector`

Convertit le support (positions) en vecteur dense de façon **temps-constant** :

```rust
index_tab[i] = support[i] >> 6          // quel mot u64
bit_tab[i] = 1u64 << (support[i] & 63)  // quel bit dans ce mot

Pour chaque mot v[i] :
  val1 = (i == index_tab[j]) ? 1 : 0    // branchless via wrapping_sub/neg
  v[i] |= bit_tab[j] & mask(val1)
```

### 7.4 `barrett_reduce(x) → x mod N`

Division modulaire sans division matérielle, par approximation :

```
q = (x × μ) >> 32   avec μ = ⌊2^32 / N⌋ = 243 079
r = x - q × N
Si r ≥ N : r -= N
```

### 7.5 `vect_set_random` — vecteur aléatoire dense

Remplit tous les bits aléatoirement via SHAKE256, puis masque le dernier mot
pour que seuls les N bits significatifs soient non-nuls.

### 7.6 `vect_add`, `vect_compare`, `vect_truncate`

- `vect_add` : XOR mot par mot (addition dans GF(2))
- `vect_compare` : comparaison temps-constant (accumulateur OR, retourne 0x01 si égaux, 0x00 sinon)
- `vect_truncate` : masque les bits au-delà de N1×N2 = 17 664

---

## 8. Code correcteur d'erreurs

**Fichiers :** `src/code.rs`, `src/reed_solomon.rs`, `src/reed_muller.rs`, `src/fft.rs`, `src/gf.rs`

### 8.1 Vue d'ensemble du code concaténé

```
Message : 16 octets (PARAM_K = 16)
    ↓  Reed-Solomon RS(46, 16, 15)  — distance minimale 31, corrige ≤ 15 symboles (octets)
Codeword RS : 46 octets (PARAM_N1 = 46)
    ↓  Reed-Muller RM(1, 7) × 3    — chaque octet → 128 bits, MULTIPLICITY = 3 copies
Codeword final : 46 × 384 = 17 664 bits (PARAM_N1N2)
```

Le bruit ajouté par HQC a un poids de Hamming borné. Le décodage concaténé proceed en sens inverse :
Reed-Muller corrige d'abord les erreurs bit à bit, Reed-Solomon corrige les symboles résiduels.

### 8.2 Reed-Muller `src/reed_muller.rs`

**Code RM(1,7)** : code linéaire de longueur 128, dimension 8, distance minimale 64.
Encode un octet (8 bits) en 128 bits. Peut corriger jusqu'à 31 erreurs sur 128 bits.

#### Encodage (`encode`)

Utilise une construction par masques de bits :

```rust
first_word ^= bit0mask(message >> 0) & 0xaaaaaaaa  // bit 0 : pattern alternant 10101...
first_word ^= bit0mask(message >> 1) & 0xcccccccc  // bit 1 : pattern 11001100...
// ... jusqu'au bit 6
// bits 5, 6, 7 contrôlent les 4 mots de 32 bits
```

`MULTIPLICITY = ⌈N2/128⌉ = 3` : chaque codeword est copié 3 fois pour renforcer la correction.

#### Décodage

1. `expand_and_sum` : sommer les MULTIPLICITY copies → tableau de 128 entiers i16 (comptage de votes)
2. `hadamard` : Transformée de Walsh-Hadamard (WHT) — 7 passes de papillons sur 128 éléments
3. `find_peaks` : chercher le maximum en valeur absolue → sa position encode le message

La WHT transforme le problème de décodage en un problème de recherche de maximum, soluble en O(N log N).

### 8.3 Reed-Solomon `src/reed_solomon.rs`

**Code RS(46, 16, 15)** sur GF(2^8). Distance minimale = 31, corrige ≤ 15 symboles en erreur.

#### Encodage

Multiplie le message par le polynôme générateur `G(X)` = produit des racines `α^i` pour i=1..30.
Utilise `gf_mul` pour l'arithmétique dans GF(2^8).

#### Décodage (pipeline de 6 étapes)

```
1. compute_syndromes    : S_i = c(α^i), i=1..2δ  — détecter les erreurs
2. compute_elp          : Berlekamp-Massey        — trouver le polynôme localisateur d'erreurs Λ(X)
3. compute_roots        : FFT de Chien Search     — trouver les positions d'erreurs (racines de Λ)
4. compute_z_poly       : polynôme évaluateur Z(X)
5. compute_error_values : formule de Forney        — calculer les valeurs des erreurs
6. correct_errors       : corriger le codeword reçu
```

### 8.4 FFT additive sur GF(2^8) `src/fft.rs`

Utilisée par Reed-Solomon pour évaluer des polynômes en tous les éléments de GF(2^8) efficacement.

L'algorithme est une **FFT additive** (Lin-Chung-Han) adaptée à GF(2^8) :

- `compute_fft_betas` : calcul de la base `{β_i}` de GF(2^8) sur GF(2)
- `compute_subset_sums` : sommes de sous-ensembles de la base (toutes les 2^7 = 128 valeurs)
- `fft_rec` : FFT récursive — divise le polynôme en deux moitiés avec `radix`, récurse
- `radix` / `radix_big` : décomposition Taylor d'un polynôme `f(X) = f_0(X²+X) + X·f_1(X²+X)`

### 8.5 Arithmétique GF(2^8) `src/gf.rs`, `src/tables.rs`

- **Polynôme irréductible** : `X^8 + X^4 + X^3 + X + 1` (standard AES/RS)
- `gf_mul(a, b)` : multiplication via tables de log/antilog (O(1) avec table)
- `gf_square(a)` : carré via table (optimisé)
- `gf_inverse(a)` : inverse via algorithme Itoh-Tsujii (enchaîne squarings et multiplications)

---

## 9. Primitives symétriques

**Fichier :** `src/symmetric.rs`

Toutes les fonctions cryptographiques utilisent **SHA3** (bibliothèque `sha3` crate).

| Fonction | Algorithme | Usage |
|----------|-----------|-------|
| `prng_init(seed, pers)` | SHAKE256 | Initialise le PRNG de génération de clés |
| `prng_get_bytes(ctx, buf)` | XofReader::read | Tire des octets pseudo-aléatoires |
| `xof_init(seed)` | SHAKE256 | Initialise un XOF pour échantillonnage |
| `xof_get_bytes(ctx, buf)` | XofReader::read | Tire des octets |
| `hash_h(out, ek)` | SHA3-256 | Hache la clé publique |
| `hash_g(out, H, m, salt)` | SHA3-512 | Dérive K et θ (KDF) |
| `hash_i(out, seed)` | SHA3-512 | Dérive les graines dk/ek depuis seed_pke |
| `hash_j(out, H, σ, c)` | SHA3-256 | Dérive K̄ (valeur de repli FO) |

Chaque fonction utilise un **octet de domaine** différent (0–3) pour la séparation de domaine,
évitant toute confusion entre les différentes utilisations de SHAKE256/SHA3.

---

## 10. Structures de données

**Fichier :** `src/data_structures.rs`

```rust
struct CiphertextPke {
    u: [u64; VEC_N_SIZE_64],        // 277 mots × 64 = 17 728 bits ⊇ N bits
    v: [u64; VEC_N1N2_SIZE_64],     // 276 mots × 64 = 17 664 bits = N1×N2
}

struct CiphertextKem {
    c_pke: CiphertextPke,
    salt:  [u8; 16],                // sel pour la sécurité multi-utilisateurs
}

struct RmCodeword {
    u32: [u32; 4],                  // 128 bits = 1 mot de code Reed-Muller
}
```

Les vecteurs de longueur N sont stockés en `u64` avec quelques bits superflus
masqués explicitement (voir `bitmask` dans `parameters.rs`).

---

## 11. Sérialisation

**Fichier :** `src/parsing.rs`

Les clés et chiffrés sont sérialisés en tableaux d'octets contigus (format "flat") :

```
ek_pke = seed_ek (32 B) ‖ s en octets (VEC_N_SIZE_BYTES = 2209 B)
dk_pke = seed_dk (32 B)

dk_kem = ek_pke ‖ dk_pke ‖ σ (16 B) ‖ seed_kem (32 B)

ct = u en octets (2209 B) ‖ v en octets (2208 B) ‖ salt (16 B)
```

La désérialisation utilise `std::slice::from_raw_parts` pour reinterpréter les octets
en mots `u64` directement (zero-copy sur architectures little-endian x86-64).

---

## 12. Flot d'exécution complet

### keypair

```
crypto_kem_keypair
  ├─ prng_get_bytes         → seed_kem
  ├─ xof_init(seed_kem)     → SHAKE256 context
  ├─ xof_get_bytes ×2       → seed_pke, σ
  └─ hqc_pke_keygen(seed_pke)
       ├─ hash_i            → seed_dk, seed_ek
       ├─ xof_init(seed_dk) + vect_sample_fixed_weight1 ×2  → y, x
       ├─ xof_init(seed_ek) + vect_set_random              → h
       ├─ vect_mul(y, h)    → y·h   [Karatsuba ← 98% du temps]
       └─ vect_add          → s = y·h + x
```

### enc

```
crypto_kem_enc
  ├─ prng_get_bytes ×2       → m, salt
  ├─ hash_h(ek)              → H
  ├─ hash_g(H, m, salt)      → K, θ
  └─ hqc_pke_encrypt(ek, m, θ)
       ├─ xof_init(θ) + vect_sample_fixed_weight2 ×3  → r2, e, r1
       ├─ vect_mul(r2, h)    → r2·h
       ├─ vect_add           → u = r2·h + r1
       ├─ code_encode(m)     → encode(m)  [RS + RM]
       ├─ vect_mul(r2, s)    → r2·s
       ├─ vect_add           → r2·s + e
       ├─ vect_truncate
       └─ vect_add           → v = encode(m) + trunc(r2·s + e)
```

### dec

```
crypto_kem_dec
  ├─ hqc_pke_decrypt
  │    ├─ (regen y depuis seed_dk)
  │    ├─ vect_mul(y, u)     → y·u
  │    ├─ vect_truncate
  │    ├─ vect_add           → v + trunc(y·u) = encode(m) + bruit
  │    └─ code_decode        [RM decode → RS decode]
  ├─ hash_h, hash_g          → K', θ'
  ├─ hqc_pke_encrypt(ek, m', θ')  ← ré-encryption complète !
  ├─ hash_j                  → K̄ (repli)
  ├─ vect_compare ×3         → ct == ct' ? (temps-constant)
  └─ sélection K' ou K̄       (branchless)
```

---

## 13. Choix d'implémentation Rust

### `inline-threshold = 0` dans Cargo.toml

Désactive l'inlining automatique du compilateur. Effet : chaque appel de fonction reste
visible dans les outils de profiling (callgrind, perf). En production, supprimer cette option
pour laisser LLVM optimiser.

### `unsafe` et zero-copy

Le code utilise `std::slice::from_raw_parts` pour interpréter des `[u8]` en `[u64]` et vice-versa.
C'est sûr sur x86-64 (little-endian, alignement relaxé en Rust), mais **non portable** sur
des architectures big-endian.

### `zeroize`

Les données secrètes (clés, seeds, messages) sont effacées de la mémoire après usage via
la crate `zeroize`. Sans ça, les valeurs resteraient dans la mémoire de processus et pourraient
être récupérées par un attaquant qui a accès à la mémoire (heap spray, core dump, etc.).

### Temps-constant

Les comparaisons critiques (`vect_compare`, la sélection finale dans `dec`) utilisent
des masques et opérations arithmétiques au lieu de branchements `if`. Cela évite les
attaques par canal auxiliaire (timing attacks) où un attaquant mesure le temps d'exécution
pour deviner des bits secrets.

### Tests

Chaque module contient des tests unitaires (`#[cfg(test)]`) :
- Propriétés algébriques : `X × X^{N-1} = 1` dans l'anneau
- Round-trip : `decode(encode(m)) = m` pour RM et RS
- Poids de Hamming exact des vecteurs épars générés
- Réduction Barrett correcte sur toutes valeurs 24 bits
