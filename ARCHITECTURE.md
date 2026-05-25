# Architecture du projet HQC

**Version :** HQC-128\
**Langage :** Rust 2024
---

## Table des matières

1. [Présentation de HQC](#1-presentation-de-hqc)
2. [Les paramètres importants](#2-les-paramètres-importants)
3. [Structure des fichiers](#3-structure-des-fichiers)
4. [Le KEM — ce que l'utilisateur appelle](#4-le-kem--ce-que-lutilisateur-appelle)
5. [Le PKE — le chiffrement interne](#5-le-pke--le-chiffrement-interne)
6. [La multiplication de polynômes](#6-la-multiplication-de-polynômes)
7. [Les vecteurs épars](#7-les-vecteurs-épars)
8. [Le code correcteur d'erreurs](#8-le-code-correcteur-derreurs)
9. [Les fonctions de hachage](#9-les-fonctions-de-hachage)
10. [Les structures de données](#10-les-structures-de-données)
11. [La sérialisation](#11-la-sérialisation)
12. [Ce qui se passe étape par étape](#12-ce-qui-se-passe-étape-par-étape)
13. [Choix techniques Rust](#13-choix-techniques-rust)

---

## 1. Présentation de HQC

HQC est un **KEM post-quantique** — un algorithme qui permet à deux personnes d'établir un secret partagé sur un réseau public, même face à un ordinateur quantique.   

> **KEM (Key Encapsulation Mechanism)** : Alice génère une paire de clés (publique/privée). Bob utilise la clé publique d'Alice pour "encapsuler" un secret et lui envoyer. Alice "décapsule" avec sa clé privée. À la fin, ils partagent le même secret sans jamais l'avoir envoyé en clair.

Le projet est organisé en deux couches :

```
┌──────────────────────────────────────────────┐
│  KEM (kem.rs)         ← interface publique   │
│  keypair / enc / dec                         │
│  + protection anti-attaques actives (FO)     │
├──────────────────────────────────────────────┤
│  PKE (hqc.rs)         ← chiffrement de base  │
│  keygen / encrypt / decrypt                  │
├────────────────┬────────────────┬────────────┤
│  gf2x          │  code          │ symmetric  │
│  Multiplication│  correcteur    │ SHA3/SHAKE │
│  polynomiale   │  d'erreurs     │            │
├────────────────┼────────────────┼────────────┤
│  vector        │  reed_solomon  │  parsing   │
│  Vecteurs épars│  reed_muller   │  sérialisa.│
└────────────────┴────────────────┴────────────┘
```

La sécurité repose sur le fait qu'il est très difficile (même pour un ordinateur quantique) de décoder un code linéaire aléatoire — c'est le problème QCSD.

---

## 2. Les paramètres importants

Tous définis dans `src/parameters.rs`. Le code entier y fait référence.

| Constante | Valeur | Ce que c'est |
|-----------|--------|--------------|
| `PARAM_N` | 17 669 | Taille des vecteurs (nombre de bits) dans l'anneau GF(2)[X]/(X^N-1) |
| `PARAM_N1` | 46 | Nombre de symboles (octets) après encodage Reed-Solomon |
| `PARAM_N2` | 384 | Taille d'un mot de code Reed-Muller (en bits) |
| `PARAM_N1N2` | 17 664 | Taille totale du message encodé (N1 × N2) |
| `PARAM_OMEGA` | 66 | Nombre de bits à 1 dans les clés secrètes x et y |
| `PARAM_OMEGA_R` | 75 | Nombre de bits à 1 dans les vecteurs aléatoires r1, r2 |
| `PARAM_OMEGA_E` | 75 | Nombre de bits à 1 dans le bruit e |
| `PARAM_DELTA` | 15 | Nombre d'erreurs que Reed-Solomon peut corriger |
| `PARAM_K` | 16 | Taille du message interne (en octets) |

### Tailles des objets échangés

| Objet | Taille |
|-------|--------|
| Clé publique | 2 241 octets |
| Clé secrète | 2 321 octets |
| Message chiffré | 4 433 octets |
| Secret partagé | 32 octets |

---

## 3. Structure des fichiers

```
hqc/
├── src/
│   ├── lib.rs             — point d'entrée de la bibliothèque
│   ├── main.rs            — binaire (lance les KATs)
│   ├── parameters.rs      — toutes les constantes
│   ├── data_structures.rs — types : CiphertextPke, CiphertextKem, RmCodeword
│   │
│   ├── kem.rs             — KEM : keypair, enc, dec (interface publique)
│   ├── hqc.rs             — PKE : keygen, encrypt, decrypt (couche interne)
│   │
│   ├── gf2x.rs            — multiplication de polynômes dans GF(2)[X]/(X^N-1)
│   ├── vector.rs          — vecteurs sur GF(2)^N, génération de vecteurs épars
│   │
│   ├── code.rs            — encode/decode (orchestre RS + RM)
│   ├── reed_solomon.rs    — code Reed-Solomon RS(46,16,15)
│   ├── reed_muller.rs     — code Reed-Muller RM(1,7)
│   ├── fft.rs             — FFT additive sur GF(2^8) (utilisée par RS)
│   ├── gf.rs              — arithmétique dans GF(2^8) : mul, carré, inverse
│   ├── tables.rs          — tables précalculées pour GF(2^8)
│   │
│   ├── symmetric.rs       — SHA3-256/512, SHAKE256
│   └── parsing.rs         — sérialisation / désérialisation
│
├── tests/
│   └── PQCkemKAT_2321.rsp — 100 vecteurs de test officiels NIST
├── benches/
│   └── hqc_bench.rs       — benchmarks Criterion
└── Cargo.toml
```

---

## 4. Le KEM — ce que l'utilisateur appelle

**Fichier :** `src/kem.rs`

C'est l'unique interface publique du projet. Un utilisateur n'a besoin de connaître que trois fonctions : générer ses clés, encapsuler un secret, décapsuler un secret.

En dessous, le KEM s'appuie sur le PKE (section 5) pour faire le vrai travail cryptographique. Son rôle propre est d'ajouter la **transformation Fujisaki-Okamoto (FO)**, qui rend le schéma résistant aux attaques actives.

> **Pourquoi FO ?** Le PKE seul est vulnérable : un attaquant pourrait modifier le message chiffré et observer comment la décapsulation réagit pour en déduire des informations sur la clé secrète. FO coupe ça net : à la décapsulation, on re-chiffre le résultat obtenu et on vérifie que ça correspond au chiffré reçu. Si quelqu'un a tripatouillé le chiffré, la vérification échoue et l'attaquant reçoit une valeur aléatoire qui ne lui apprend rien.

### `crypto_kem_keypair` — génération de clés

Cette fonction génère la paire de clés publique/secrète. Elle ne fait pas le travail cryptographique elle-même : elle délègue au PKE (`hqc_pke_keygen`).

Son rôle propre est de dériver depuis une graine aléatoire toutes les valeurs nécessaires : la graine pour le PKE, et une valeur secrète supplémentaire σ (sigma) qui sert uniquement de valeur de repli en cas d'attaque lors de la décapsulation.

La clé secrète KEM est simplement la concaténation de tout ce qu'on aura besoin pour décapsuler : la clé publique PKE, la clé secrète PKE, σ, et la graine d'origine. La clé publique KEM est directement la clé publique PKE.

### `crypto_kem_enc` — encapsulation

Cette fonction est appelée par quelqu'un qui possède la clé publique d'un destinataire et veut lui transmettre un secret partagé.

Elle commence par générer un message aléatoire interne `m` (16 octets) et un sel aléatoire. Ce `m` n'est pas le message de l'utilisateur — c'est une valeur temporaire dont le hash va devenir le secret partagé final. Elle hache ensuite la clé publique, puis dérive à la fois le secret partagé `K` et une graine de chiffrement `θ` (thêta) depuis un seul appel SHA3-512. Enfin, elle chiffre `m` avec le PKE en utilisant `θ` comme source d'aléa.

Le résultat retourné est le message chiffré (qui permet au destinataire de retrouver `m`) et le secret partagé `K`. L'expéditeur conserve `K`, que le destinataire retrouvera de son côté.

### `crypto_kem_dec` — décapsulation

Cette fonction est appelée par le détenteur de la clé secrète pour retrouver le secret partagé depuis un message chiffré reçu.

Elle commence par extraire les différentes parties stockées dans la clé secrète, puis déchiffre le message chiffré avec le PKE pour obtenir un candidat `m'`. Elle recalcule ensuite `K'` et `θ'` exactement comme l'expéditeur l'aurait fait, puis **re-chiffre `m'` avec `θ'`** pour obtenir un chiffré `c'`.

C'est là que FO entre en jeu : si le chiffré reçu et `c'` sont identiques, tout s'est bien passé et `K'` est retourné comme secret partagé. S'ils diffèrent (signe qu'une attaque ou une corruption a eu lieu), une valeur de repli `K̄` est retournée à la place — calculée depuis σ, ce qui garantit qu'elle a l'air aléatoire pour l'attaquant.

La comparaison entre les deux chiffrés est faite en **temps constant** pour éviter qu'un attaquant puisse deviner le résultat en mesurant le temps d'exécution. Conférez-vous au README.md pour plus d'info sur le temps constant.

---

## 5. Le PKE — le chiffrement interne

**Fichier :** `src/hqc.rs`

### Génération de clés

```
(seed_dk ‖ seed_ek) = SHA3-512(seed)

Depuis seed_dk : générer y (épars, poids 66) et x (épars, poids 66)
Depuis seed_ek : générer h (aléatoire dense)
s = y·h + x   (multiplication dans GF(2)[X]/(X^N-1))

clé secrète = seed_dk        ← juste 32 octets, y et x sont régénérés à la demande
clé publique = seed_ek ‖ s
```

La clé secrète ne stocke qu'une graine — les vecteurs secrets y et x sont recalculés au besoin.

### Chiffrement

```
Depuis ek, récupérer h et s
Depuis θ : générer r1, r2, e  (tous épars)

u = r2·h + r1             ← première partie du chiffré
v = encode(m) + trunc(r2·s + e)   ← deuxième partie
```

`encode(m)` transforme les 16 octets du message en 17 664 bits via Reed-Solomon puis Reed-Muller.

### Déchiffrement

```
Régénérer y depuis la clé secrète (seed_dk)

tmp = trunc(y·u)
v' = v + tmp = encode(m) + bruit résiduel

m = decode(v')    ← le code correcteur retire le bruit
```

Le bruit résiduel est de poids borné — les paramètres garantissent que le décodage réussit avec probabilité 1 - 2^{-128}.

---

## 6. La multiplication de polynômes

**Fichier :** `src/gf2x.rs`

C'est le **goulot d'étranglement** du projet : environ 98% du temps CPU.

On travaille dans l'anneau `GF(2)[X] / (X^N − 1)` avec N = 17 669. Les polynômes sont stockés comme des tableaux de 277 mots de 64 bits (277 × 64 = 17 728 bits ⊇ 17 669 bits).

### `vect_mul(résultat, a, b)`

1. **Multiplication** via l'algorithme de Karatsuba → résultat de longueur 2N
2. **Réduction modulo X^N − 1** : les coefficients de degré ≥ N se "replient" sur les degrés bas (car X^N ≡ 1)

### Algorithme de Karatsuba

Au lieu de faire une multiplication naïve en O(n²), Karatsuba divise chaque polynôme en deux moitiés et ne fait que 3 multiplications récursives au lieu de 4.

```
A × B = A_bas·B_bas  +  X^{2m}·(A_haut·B_haut)  +  X^m·[...]
```

Complexité : O(n^1.585) au lieu de O(n²). La récursion s'arrête quand n ≤ 16 et bascule sur la multiplication naïve (`schoolbook_mul`).

---

## 7. Les vecteurs épars

**Fichier :** `src/vector.rs`

Les vecteurs secrets (x, y, r1, r2, e) ont très peu de bits à 1 : par exemple, 66 bits à 1 sur 17 669. C'est ce qui rend le problème QCSD difficile.

Ils sont stockés en format dense (tableaux de u64), mais générés via leur **support** (la liste des positions des bits à 1).

### Génération par rejet (`vect_generate_random_support1`)

```
Tirer 3 octets aléatoires → entier 24 bits
Si la valeur dépasse le seuil (16 767 881) : recommencer
Sinon : réduire modulo N via Barrett → position valide
Vérifier qu'elle n'est pas déjà prise
```

### Génération Fisher-Yates (`vect_generate_random_support2`)

Méthode plus rapide utilisée pour r1, r2, e :

```
Pour i de 0 à poids :
    support[i] = i + (aléatoire × (N - i)) >> 32
```

### `barrett_reduce` — réduction modulaire rapide

Division par N sans instruction de division, par approximation entière :

```
q = (x × 243079) >> 32
r = x - q × N
Si r ≥ N : r -= N
```

### Autres opérations sur les vecteurs

- `vect_add` : XOR mot par mot (addition dans GF(2))
- `vect_compare` : comparaison en temps constant
- `vect_truncate` : efface les bits au-delà de N1×N2 = 17 664

---

## 8. Le code correcteur d'erreurs

**Fichiers :** `src/code.rs`, `src/reed_solomon.rs`, `src/reed_muller.rs`, `src/fft.rs`, `src/gf.rs`

HQC ajoute intentionnellement du bruit lors du chiffrement. Le code correcteur d'erreurs est là pour le retirer lors du déchiffrement.

### Schéma général (code concaténé)

```
Message : 16 octets
    ↓  Reed-Solomon RS(46, 16, 15)  — ajoute de la redondance au niveau octet
Mot de code : 46 octets
    ↓  Reed-Muller RM(1, 7) × 3    — chaque octet devient 384 bits (3 copies de 128 bits)
Vecteur final : 46 × 384 = 17 664 bits
```

Au déchiffrement, on fait l'inverse : Reed-Muller corrige les erreurs bit à bit, Reed-Solomon corrige les erreurs résiduelles octet par octet.

### Reed-Muller `src/reed_muller.rs`

Encode un octet (8 bits) en 128 bits. Peut corriger jusqu'à 31 erreurs sur ces 128 bits. Chaque mot de code est répété 3 fois (`MULTIPLICITY = 3`) pour renforcer la robustesse.

Décodage en 3 étapes :
1. Additionner les 3 copies pour cumuler les "votes"
2. Appliquer la Transformée de Walsh-Hadamard (WHT)
3. Chercher le maximum → c'est l'octet décodé

### Reed-Solomon `src/reed_solomon.rs`

Code RS(46, 16, 15) sur GF(2^8). Corrige jusqu'à 15 octets erronés sur 46.

Décodage en 6 étapes :
1. Calculer les syndromes (détecter les erreurs)
2. Algorithme de Berlekamp-Massey (trouver les positions d'erreurs)
3. FFT de Chien Search (trouver les racines)
4. Calculer le polynôme évaluateur
5. Formule de Forney (valeurs des erreurs)
6. Corriger le mot de code

### FFT additive `src/fft.rs`

Utilisée par Reed-Solomon pour évaluer des polynômes efficacement sur tout GF(2^8). C'est une FFT adaptée aux corps de caractéristique 2.

### Arithmétique GF(2^8) `src/gf.rs`

- Polynôme irréductible : X^8 + X^4 + X^3 + X + 1
- Multiplication et inverse via tables de logarithmes précalculées (O(1))

---

## 9. Les fonctions de hachage

**Fichier :** `src/symmetric.rs`

Tout le code cryptographique utilise la famille **SHA3** (crate `sha3`).

| Fonction | Algorithme | Rôle |
|----------|-----------|------|
| `prng_init` / `prng_get_bytes` | SHAKE256 | Générateur pseudo-aléatoire pour les KATs |
| `xof_init` / `xof_get_bytes` | SHAKE256 | Génère les vecteurs épars (r1, r2, e, h, x, y) |
| `hash_h` | SHA3-256 | Hache la clé publique |
| `hash_g` | SHA3-512 | Dérive le secret partagé K et la graine de chiffrement θ |
| `hash_i` | SHA3-512 | Dérive les graines de clé privée/publique PKE |
| `hash_j` | SHA3-256 | Calcule la valeur de repli K̄ (cas d'attaque) |

Chaque fonction utilise un **octet de domaine** différent (0–3) pour éviter qu'un hash calculé dans un contexte soit réutilisable dans un autre.

---

## 10. Les structures de données

**Fichier :** `src/data_structures.rs`

```rust
// Le chiffré PKE = (u, v)
struct CiphertextPke {
    u: [u64; 277],   // vecteur de N bits (partie "clé publique du chiffré")
    v: [u64; 276],   // vecteur de N1×N2 bits (message encodé + bruit)
}

// Le chiffré KEM = chiffré PKE + sel
struct CiphertextKem {
    c_pke: CiphertextPke,
    salt: [u8; 16],  // sel pour la sécurité multi-utilisateurs
}

// Un mot de code Reed-Muller = 128 bits
struct RmCodeword {
    u32: [u32; 4],
}
```

Les vecteurs de taille N sont stockés en mots de 64 bits. Les quelques bits superflus (277×64 - 17669 = 59 bits) sont masqués explicitement.

---

## 11. La sérialisation

**Fichier :** `src/parsing.rs`

Les clés et chiffrés sont convertis en tableaux d'octets pour être stockés ou échangés :

```
clé_publique_PKE  = seed_ek (32 o) ‖ s en octets (2209 o)
clé_privée_PKE    = seed_dk (32 o)

clé_secrète_KEM   = clé_pub_PKE ‖ clé_priv_PKE ‖ σ (16 o) ‖ seed_kem (32 o)

chiffré           = u (2209 o) ‖ v (2208 o) ‖ salt (16 o)
```

La conversion octets ↔ mots u64 se fait via `std::slice::from_raw_parts` (zero-copy sur x86-64 little-endian).

---

## 12. Ce qui se passe étape par étape

### Génération de clés (`keypair`)

```
crypto_kem_keypair
  ├─ PRNG → seed_kem
  ├─ SHAKE256(seed_kem) → seed_pke, σ
  └─ hqc_pke_keygen(seed_pke)
       ├─ SHA3-512 → seed_dk, seed_ek
       ├─ SHAKE256(seed_dk) → y, x  (vecteurs épars secrets)
       ├─ SHAKE256(seed_ek) → h     (vecteur dense public)
       ├─ vect_mul(y, h)            ← ~98% du temps CPU (Karatsuba)
       └─ s = y·h + x
```

### Encapsulation (`enc`)

```
crypto_kem_enc
  ├─ PRNG → m, salt
  ├─ SHA3-256(ek) → H
  ├─ SHA3-512(H, m, salt) → K, θ
  └─ hqc_pke_encrypt(ek, m, θ)
       ├─ SHAKE256(θ) → r2, e, r1  (vecteurs épars)
       ├─ u = r2·h + r1
       ├─ code_encode(m)            (RS + RM : 16 o → 17664 bits)
       └─ v = encode(m) + trunc(r2·s + e)
```

### Décapsulation (`dec`)

```
crypto_kem_dec
  ├─ hqc_pke_decrypt
  │    ├─ régénérer y depuis seed_dk
  │    ├─ tmp = trunc(y·u)
  │    ├─ v' = v + tmp  (= encode(m) + bruit)
  │    └─ code_decode(v') → m'   (RM puis RS)
  ├─ re-chiffrer m' pour obtenir c'
  ├─ comparer c == c' en temps constant
  └─ retourner K' (succès) ou K̄ (échec)
```

---

## 13. Choix techniques Rust

### `inline-threshold = 0` dans Cargo.toml

Désactive l'inlining automatique. Chaque appel de fonction reste visible dans les outils de profiling (callgrind, perf). À supprimer en production pour laisser LLVM optimiser.

### `unsafe` et zero-copy

`std::slice::from_raw_parts` est utilisé pour interpréter des `[u8]` en `[u64]` sans copie. C'est valide sur x86-64 (little-endian), mais non portable sur les architectures big-endian.

### `zeroize`

Les données secrètes (clés, seeds, messages) sont effacées de la mémoire après usage. Sans ça, les valeurs pourraient être récupérées depuis un dump mémoire.

### Temps-constant

Les comparaisons critiques utilisent des masques binaires au lieu de branchements `if`. Cela évite les attaques par timing, où un attaquant mesurerait le temps d'exécution pour deviner des bits secrets.

### `wrapping_sub`

Les soustractions qui "wrappent" (0 - 1 = 255 sur u8) sont explicites en Rust avec `wrapping_sub()`, contrairement au C où c'est silencieux. Cela rend l'intention claire et évite les panics en mode debug.

### Tests

Chaque module contient des tests unitaires (`#[cfg(test)]`) :
- Propriétés algébriques : `X × X^{N-1} = 1` dans l'anneau
- Aller-retour : `decode(encode(m)) = m` pour RM et RS
- Poids de Hamming exact des vecteurs épars générés
- Réduction Barrett correcte
- 100 vecteurs KAT officiels NIST (tests d'intégration complets)
