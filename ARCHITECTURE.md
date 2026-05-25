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

La sécurité repose sur le fait qu'il est très difficile (même pour un ordinateur quantique) de décoder un code linéaire aléatoire — c'est le problème Quasi Cyclic Syndorme Decoding problem.

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

C'est la couche cryptographique réelle, appelée par le KEM. Elle implémente un chiffrement de type "Learning With Errors" adapté aux corps binaires et aux anneaux quasi-cycliques. Elle expose trois fonctions.

### `hqc_pke_keygen` — génération de clés

À partir d'une graine de 32 octets, cette fonction dérive tout ce dont on a besoin. Elle commence par hacher la graine pour obtenir deux sous-graines indépendantes : une pour la clé privée, une pour la clé publique. Depuis la graine privée, elle génère deux vecteurs épars secrets `x` et `y` (66 bits à 1 chacun sur 17 669). Depuis la graine publique, elle génère un vecteur dense aléatoire `h`. Elle calcule ensuite `s = y·h + x` dans l'anneau GF(2)[X]/(X^N-1).

La clé secrète est simplement la graine privée — 32 octets. `x` et `y` ne sont jamais stockés : ils sont régénérés à la demande depuis cette graine. La clé publique expose `h` et `s`. Retrouver `x` et `y` depuis `(h, s)` est le problème QCSD, supposé infaisable.

### `hqc_pke_encrypt` — chiffrement

À partir de la clé publique et d'un message de 16 octets, cette fonction produit un chiffré en deux parties `(u, v)`. Elle commence par récupérer `h` et `s` depuis la clé publique, puis génère trois vecteurs épars aléatoires `r1`, `r2`, `e` depuis une graine fournie en paramètre (c'est le `θ` du KEM, ce qui rend le chiffrement déterministe).

La première partie du chiffré est `u = r2·h + r1` — ça ressemble à une clé publique PKE et c'est intentionnel. La deuxième partie est `v = encode(m) + trunc(r2·s + e)` : le message est d'abord encodé avec le code correcteur d'erreurs (Reed-Solomon puis Reed-Muller, 16 octets → 17 664 bits), puis "bruité" en lui ajoutant `r2·s + e`. C'est ce bruit qui sera retiré au déchiffrement.

### `hqc_pke_decrypt` — déchiffrement

À partir de la clé secrète et du chiffré `(u, v)`, cette fonction retrouve le message. Elle commence par régénérer `y` depuis la graine secrète, puis calcule `y·u`. En développant les termes, on peut montrer que `v + trunc(y·u)` est égal à `encode(m)` plus un vecteur d'erreur de poids borné — parce que tous les vecteurs impliqués (x, y, r1, r2, e) sont épars. Le code correcteur d'erreurs retire ce bruit résiduel et retrouve le message original. Les paramètres garantissent que ça fonctionne avec probabilité 1 - 2^{-128}.

---

## 6. La multiplication de polynômes

**Fichier :** `src/gf2x.rs`

Module le plus critique en performance : **~98% du temps CPU**. Toutes les multiplications de vecteurs (y·h, r2·s, y·u…) passent par lui.

### Objectif

Multiplier deux polynômes dans GF(2)[X]/(X^N-1) avec N = 17 669. C'est une multiplication classique de polynômes binaires, suivie d'un "repliement" des coefficients de degré ≥ N vers les degrés bas (puisque X^N ≡ 1). Les polynômes sont stockés en 277 mots de 64 bits.

### L'algorithme de Karatsuba

Une multiplication naïve coûterait ~312 millions d'opérations — trop lent. Karatsuba divise chaque polynôme en deux moitiés et n'effectue que **3 multiplications récursives au lieu de 4** :

```
            A  =  A_haut · X^m  +  A_bas         (chaque moitié = m mots)
            B  =  B_haut · X^m  +  B_bas

  A × B  =  P1 · X^(2m)  +  P3 · X^m  +  P2

  avec :  P1 = A_haut × B_haut       
          P2 = A_bas  × B_bas        
          P3 = (A_haut + A_bas) × (B_haut + B_bas)  −  P1  −  P2
```

Le "+ P1 + P2" final permet de récupérer le terme croisé sans le calculer directement — c'est l'astuce de Karatsuba. Complexité : **O(n^1.585) au lieu de O(n²)**.

La récursion s'arrête quand les blocs font ≤ 16 mots, et bascule sur `schoolbook_mul` (multiplication naïve, plus rapide à cette taille) :

```
karatsuba_mul(277)
  ├─ karatsuba_mul(139)
  │    ├─ karatsuba_mul(70)
  │    │    ├─ karatsuba_mul(35)
  │    │    │    └─ ... → schoolbook_mul (≤16)
  │    │    └─ ...
  │    └─ ...
  └─ ...
```


---
## 7. Les vecteurs épars

**Fichier :** `src/vector.rs`

Les vecteurs secrets et de bruit (x, y, r1, r2, e) ont **très peu de bits à 1** :

```
x, y         →  66 bits à 1 sur 17 669  (poids OMEGA)
r1, r2, e    →  75 bits à 1 sur 17 669  (poids OMEGA_R / OMEGA_E)
```

C'est ce faible poids de Hamming qui rend le problème QCSD difficile.

### Comment ils sont générés

On génère d'abord le **support** (liste des positions des bits à 1), puis on construit le vecteur dense. Deux méthodes selon l'usage :

| Fonction | Utilisée pour | Méthode |
|----------|--------------|---------|
| `vect_generate_random_support1` | clés secrètes x, y | Tirage + rejet (évite le biais statistique) |
| `vect_generate_random_support2` | r1, r2, e | Fisher-Yates (unicité par construction, plus rapide) |

### Barrett reduce

Pour ramener une position aléatoire dans [0, N-1], il faut calculer `x mod N`. L'instruction matérielle de division est lente, donc on utilise Barrett : une multiplication + un décalage de bits avec une constante précalculée (243 079 = ⌊2³²/N⌋). C'est une optimisation classique en crypto embarquée.

### Autres opérations

- `vect_add` — addition dans GF(2) = XOR bit à bit
- `vect_compare` — comparaison en temps constant (anti-timing-attack)
- `vect_truncate` — efface les bits au-delà de N1×N2 = 17 664

---

## 8. Le code correcteur d'erreurs

**Fichiers :** `src/code.rs`, `src/reed_solomon.rs`, `src/reed_muller.rs`, `src/fft.rs`, `src/gf.rs`

HQC ajoute intentionnellement du bruit au chiffrement (r1, r2, e) pour la sécurité. Le code correcteur d'erreurs sert à éliminer ce bruit au déchiffrement.

### Vue d'ensemble : code concaténé

```
Message       :  16 octets
    │
    │  Reed-Solomon  RS(46, 16)
    ↓  (ajoute redondance octet par octet)
RS codeword   :  46 octets
    │
    │  Reed-Muller   RM(1,7) × 3 copies
    ↓  (1 octet → 128 bits, répété 3 fois = 384 bits)
Vecteur final :  46 × 384 = 17 664 bits
```

**Au déchiffrement** : RM corrige d'abord les erreurs bit à bit, puis RS rattrape les octets que RM n'a pas réussi à décoder.

### Reed-Muller `src/reed_muller.rs`

Encode 1 octet (8 bits) → 128 bits, répété 3 fois (`MULTIPLICITY = 3`). Corrige jusqu'à 31 erreurs sur 128 bits.

Décodage en 3 étapes :

```
3 copies bruitées  ──> somme des votes  ──> Hadamard  ──>  argmax  =  octet décodé
   (3×128 bits)         (128 valeurs)         (128 valeurs)
```

L'astuce : la Hadamard transforme le problème de décodage en une simple recherche du maximum.

### Reed-Solomon `src/reed_solomon.rs`

Code RS(46, 16) sur GF(2⁸). Corrige jusqu'à **15 octets erronés sur 46**.

Pipeline de décodage en 6 étapes :

```
1. compute_syndromes      → détecte qu'il y a des erreurs
2. compute_elp            → polynôme localisateur Λ(X)
3. compute_roots          → racines de Λ = positions des erreurs
4. compute_z_poly         → polynôme évaluateur Z(X)
5. compute_error_values   → valeurs des erreurs
6. correct_errors         → XOR les corrections au codeword
```

### FFT additive `src/fft.rs`

Évalue un polynôme en tous les éléments de GF(2⁸) en O(n log n) au lieu de O(n²). C'est une FFT adaptée aux corps de caractéristique 2 (contrairement à la FFT classique).

### Arithmétique GF(2⁸) `src/gf.rs` et `src/tables.rs`

GF(2⁸) = les 256 valeurs possibles d'un octet, avec :
- **Addition** : XOR
- **Multiplication** : modulo le polynôme irréductible `X⁸ + X⁴ + X³ + X + 1`
- **Inverse** : via tables de log/antilog précalculées → opération en O(1)

---

## 9. Les fonctions de hachage

**Fichier :** `src/symmetric.rs`

Tout le projet utilise la famille **SHA3** (norme NIST post-quantique). Deux usages :
- **Sortie fixe** : SHA3-256 (32 o), SHA3-512 (64 o)
- **Sortie extensible** (XOF) : SHAKE256, produit autant d'octets qu'on veut — pratique pour générer des vecteurs de taille arbitraire

| Fonction | Algorithme | Rôle |
|----------|-----------|------|
| `prng_init` / `prng_get_bytes` | SHAKE256 | PRNG déterministe pour les KATs |
| `xof_init` / `xof_get_bytes` | SHAKE256 | Génère les vecteurs (x, y, h, r1, r2, e) depuis leurs graines |
| `hash_h` | SHA3-256 | Hache la clé publique (utilisé partout ensuite) |
| `hash_g` | SHA3-512 | Dérive K + θ en un seul appel (les 64 octets coupés en deux) |
| `hash_i` | SHA3-512 | Dérive seed_dk + seed_ek depuis seed_pke |
| `hash_j` | SHA3-256 | Calcule la valeur de repli K̄ (FO) |

**Séparation de domaine** : chaque fonction ajoute un octet de domaine différent (0–3) à son entrée. Un hash calculé dans un contexte ne peut donc pas être réutilisé dans un autre, même à entrées identiques.

---

## 10. Les structures de données

**Fichier :** `src/data_structures.rs`

```rust
struct CiphertextPke {
    u: [u64; 277],   // N bits (la "partie publique" du chiffré)
    v: [u64; 276],   // N1×N2 bits (message encodé + bruit)
}

struct CiphertextKem {
    c_pke: CiphertextPke,
    salt: [u8; 16],  // sel anti-collision multi-utilisateurs
}

struct RmCodeword {
    u32: [u32; 4],   // 128 bits = 1 mot de code Reed-Muller
}
```

Les vecteurs de taille N occupent 277 mots de 64 bits (= 17 728 bits), soit 59 bits de trop. Ces bits superflus sont toujours masqués à zéro — un oubli produit des multiplications fausses.

---

## 11. La sérialisation

**Fichier :** `src/parsing.rs`

Conversion des structures Rust vers/depuis des tableaux d'octets pour stockage et transmission :

```
ek_pke      =  seed_ek (32 o)  ‖  s en octets (2209 o)             →  2241 o
dk_pke      =  seed_dk (32 o)                                       →    32 o
dk_kem      =  ek_pke  ‖  dk_pke  ‖  σ (16 o)  ‖  seed_kem (32 o)  →  2321 o
ct          =  u (2209 o)  ‖  v (2208 o)  ‖  salt (16 o)            →  4433 o
```

La conversion octets ↔ u64 utilise `std::slice::from_raw_parts` — pas de copie, on réinterprète directement la mémoire. Valide sur x86-64 (little-endian), non portable sur big-endian.

---

## 12. Ce qui se passe étape par étape

Enchaînement complet des appels, de l'interface publique aux opérations bas niveau.

### Génération de clés

```
crypto_kem_keypair
  ├─ PRNG → seed_kem
  ├─ SHAKE256(seed_kem) → seed_pke, σ
  └─ hqc_pke_keygen(seed_pke)
       ├─ SHA3-512 → seed_dk, seed_ek
       ├─ SHAKE256(seed_dk) → y, x  (épars)
       ├─ SHAKE256(seed_ek) → h     (dense)
       ├─ vect_mul(y, h)            ← ~98% du temps CPU
       └─ s = y·h + x
```

### Encapsulation

```
crypto_kem_enc
  ├─ PRNG → m, salt
  ├─ SHA3-256(ek)             → H
  ├─ SHA3-512(H, m, salt)     → K, θ
  └─ hqc_pke_encrypt(ek, m, θ)
       ├─ SHAKE256(θ)         → r2, e, r1
       ├─ u = r2·h + r1
       ├─ code_encode(m)      (RS + RM : 16 o → 17664 bits)
       └─ v = encode(m) + trunc(r2·s + e)
```

### Décapsulation

```
crypto_kem_dec
  ├─ hqc_pke_decrypt(c, dk_pke)
  │    ├─ régénérer y depuis seed_dk
  │    ├─ tmp = trunc(y·u)
  │    ├─ v' = v + tmp        (= encode(m) + bruit borné)
  │    └─ code_decode(v')     → m'  (RM puis RS)
  ├─ recalculer H, K', θ'
  ├─ hqc_pke_encrypt(ek, m', θ')  → c'    ← re-chiffrement (FO)
  ├─ compare(c, c') en temps constant
  └─ retourne K' si c==c', sinon K̄
```

---

## 13. Choix techniques Rust

### `[inline(never)]` pour les fonctions

En temps normal, le compilateur Rust (LLVM) copie le code des petites fonctions directement à leurs sites d'appel pour éviter le coût du `call`. C'est efficace, mais ça rend le profiling illisible : les outils comme callgrind voient un gros bloc de code sans pouvoir distinguer quelle fonction fait quoi. Désactiver l'inlining sacrifie un peu de performance mais rend le profiling précis. Cette option doit être retirée pour une version de production.

### `unsafe` et zero-copy

Rust interdit normalement de réinterpréter un tableau d'octets comme un tableau de u64 — les types sont différents. Il faut utiliser `std::slice::from_raw_parts`, marqué `unsafe`, pour dire au compilateur qu'on sait ce qu'on fait. C'est correct sur x86-64 parce que cette architecture est little-endian et tolère les accès non-alignés, mais ce serait un comportement indéfini sur certaines architectures embarquées.

### `zeroize`

Après usage, les données secrètes (graines, clés, message interne `m`) sont explicitement écrasées en mémoire via la crate `zeroize`. Sans ça, ces valeurs restent dans la mémoire du processus et pourraient être lues depuis un fichier de dump ou via une attaque heap spray. C'est une précaution standard en cryptographie.

### Temps-constant

En Rust (comme en C), un `if` peut s'exécuter plus ou moins vite selon la branche prise. Un attaquant qui mesure le temps d'exécution peut parfois en déduire le résultat d'une comparaison — c'est une attaque par timing. Pour y résister, les comparaisons critiques utilisent des masques binaires et des opérations arithmétiques qui prennent toujours le même temps, quelle que soit la valeur des données.
Pour plus d'information sur le temps constant dans HQC voir la section concernée dans le README.md

### `wrapping_sub`

En C, `0 - 1` sur un entier non signé vaut 255 (le comportement wrap est défini). En Rust, la même opération provoque un panic en mode debug. Pour reproduire fidèlement le comportement C (voulu ici, car c'est un masque cryptographique), on utilise `wrapping_sub(1)`. Ça rend l'intention explicite et évite les surprises lors du portage.

### Tests

Chaque module contient ses propres tests unitaires vérifiés à chaque compilation. Les tests algébriques vérifient que les propriétés mathématiques tiennent (par exemple que multiplier X^{N-1} par X donne bien 1 dans l'anneau). Les tests de round-trip vérifient que `decode(encode(m)) = m` pour Reed-Muller et Reed-Solomon. Des tests de distribution vérifient que les vecteurs épars générés ont exactement le bon poids. Et les 100 vecteurs KAT servent de test d'intégration complet — si une seule valeur diverge du fichier de référence, le test échoue.
