# Rapport de Profiling — HQC-128

**KATs :** 100 vecteurs de test (`PQCkemKAT_2321.rsp`)

---

## 1. Quelques rappels sur HQC

HQC (Hamming Quasi-Cyclic) est un algorithme de **chiffrement post-quantique**. L'idée : même un ordinateur quantique ne peut pas casser ce chiffrement.

Il fonctionne comme un KEM (Key Encapsulation Mechanism) : au lieu de chiffrer directement un message, on s'en sert pour que deux personnes se mettent d'accord sur une clé secrète partagée de 32 octets, sans jamais se la transmettre directement.

### Les trois opérations

| Opération | Rôle | Qui l'exécute |
|-----------|------|---------------|
| **keypair** | Générer une paire clé publique / clé secrète | Le serveur |
| **enc** | Encapsuler une clé secrète dans un chiffré | Le client |
| **dec** | Décapsuler : retrouver la clé secrète depuis le chiffré | Le serveur |


### Tailles des objets cryptographiques

| Objet | Taille |
|-------|--------|
| Clé publique | 2 241 octets |
| Clé secrète | 2 321 octets |
| Chiffré | 4 433 octets |
| Secret partagé | 32 octets |

---

## 2. Méthode de mesure

### Ce qui est mesuré

Pour chaque KAT, on mesure le temps de chacune des trois opérations séparément, ainsi que la variation de mémoire RSS avant/après chaque appel. On reproduit cette mesure sur les 100 seeds pour obtenir une distribution représentative.

### Implémentation Rust

Le binaire de profiling se trouve dans `src/bin/profile_kats.rs`.
Il lit les 100 seeds du fichier `tests/PQCkemKAT_2321.rsp`, exécute les trois opérations sur chaque seed, et mesure le temps avec `std::time::Instant`.

**Compilation et exécution :**

```bash
cargo build --release --bin profile_kats
./target/release/profile_kats raw 100
```

**Format de sortie :**

```
keypair_ns enc_ns dec_ns keypair_rss_kb enc_rss_kb dec_rss_kb
3784282 8948723 12510230 212 8 8
3733708 7919928 17027776 0 0 0
...
peak_hwm_kb 4076
```

### Implémentation C

Le fichier de profiling se mets dans `tests/bench/benchmark_kats.c` du dépôt C. (Fichier benchmark sur [Ce Lien](https://github.com/EcuodaH/hqc_into_rust/tree/main/benches/bench_c)\
Il utilise la même approche : `clock_gettime(CLOCK_MONOTONIC)` et lecture de`/proc/self/status` pour la mémoire.

**Compilation et exécution :**

```bash
# Depuis hqc-next-release/
cmake -S . -B build -DHQC_ARCH=ref -DCMAKE_BUILD_TYPE=Release -DVARIANTS=hqc-1
cmake --build build --target benchmark_kats_hqc_1
./build/tests/bench/benchmark_kats_hqc_1
```

**Format de sortie :** identique au Rust, une ligne par KAT.

---
## 3. Résultats

### 3.1 Rust — `inline-threshold=0` (profiling)

Inlining désactivé pour permettre l'analyse callgrind.  
Mesures sur 100 KATs, `cargo build --release`.

| Opération | Min | Médiane | Moyenne | P95 | Max |
|-----------|-----|---------|---------|-----|-----|
| keypair | 2,93 ms | 3,63 ms | 3,66 ms | 3,84 ms | 4,01 ms |
| enc | 4,36 ms | 7,25 ms | 7,25 ms | 7,59 ms | 7,81 ms |
| dec | 6,56 ms | 10,99 ms | 10,99 ms | 11,34 ms | 12,08 ms |

**Pic mémoire (VmHWM) : 4 076 Ko (~4 Mo)**

### 3.2 Rust — `release-opt` (inlining LLVM par défaut)

Inlining réactivé (seuil LLVM par défaut : 275).  
Mesures sur 100 KATs, `cargo build --profile release-opt`.

| Opération | Min | Médiane | Moyenne | P95 | Max |
|-----------|-----|---------|---------|-----|-----|
| keypair | 3,61 ms | 3,63 ms | 3,64 ms | 3,69 ms | 4,07 ms |
| enc | 6,00 ms | 7,24 ms | 7,27 ms | 7,48 ms | 7,55 ms |
| dec | 10,89 ms | 10,97 ms | 11,01 ms | 11,16 ms | 11,36 ms |

**Pic mémoire (VmHWM) : 4 072 Ko (~4 Mo)**

Les médianes sont quasi identiques entre les deux configurations Rust.
La différence visible est la **variance** : `release-opt` est nettement plus régulier (écart min/max réduit de moitié). Cela s'explique par le fait que `karatsuba_mul` domine à ~98 % du temps total — c'est une grande fonction récursive que l'inlining ne peut pas réduire, donc le gain médian est faible. En revanche, les petites fonctions auxiliaires inlinées rendent le comportement de cache plus prévisible.

### 3.3 Implémentation C (référence)

Mesures sur 100 KATs, `cmake -DCMAKE_BUILD_TYPE=Release -DHQC_ARCH=ref`.

| Opération | Min | Médiane | Moyenne | P95 | Max |
|-----------|-----|---------|---------|-----|-----|
| keypair | 2,95 ms | 2,97 ms | 3,00 ms | 3,11 ms | 3,14 ms |
| enc | 5,91 ms | 5,96 ms | 6,00 ms | 6,28 ms | 6,47 ms |
| dec | 9,10 ms | 9,18 ms | 9,27 ms | 9,53 ms | 12,86 ms |

**Pic mémoire (VmHWM) : 1 768 Ko (~1,7 Mo)**

Variance très faible : les temps sont quasi-constants d'un KAT à l'autre.

---

## 4. Comparatif

### Temps d'exécution (médiane)

| Opération | Rust (no-inline) | Rust (release-opt) | C (ref) |
|-----------|------------------|--------------------|---------|
| keypair | 3,63 ms | 3,63 ms | **2,97 ms** |
| enc | 7,25 ms | 7,24 ms | **5,96 ms** |
| dec | 10,99 ms | 10,97 ms | **9,18 ms** |

Le C de référence est environ **20 % plus rapide** que le Rust sur toutes les opérations, indépendamment de l'inlining.

### Variance (écart min→max)

| Opération | Rust (no-inline) | Rust (release-opt) | C (ref) |
|-----------|------------------|--------------------|---------|
| keypair | 1,08 ms | 0,46 ms | 0,19 ms |
| enc | 3,45 ms | 1,55 ms | 0,56 ms |
| dec | 5,52 ms | 0,47 ms | 3,76 ms |

L'inlining réduit significativement la variance Rust, la rapprochant du comportement C.

### Mémoire

| | Rust | C (ref) |
|-|------|---------|
| Pic VmHWM | ~4 076 Ko | 1 768 Ko |
| Ratio | **×2,3** | — |

Le Rust consomme environ **2,3× plus de mémoire** au pic, principalement à cause des allocations heap (`Vec`) pour les clés et chiffrés, contre des variables de pile en C.

### Analyse des écarts de performance

**Pourquoi le C est plus rapide :** GCC et Clang compilent le C avec un des optimisations très agressives par défaut et une gestion de pile optimisée. 
La version Rust utilise des traits (`XofReader`, etc.) qui introduisent un niveau d'indirection supplémentaire, et les allocations `Vec` ont un coût par rapport aux tableaux de pile C.

**Pourquoi l'inlining Rust n'aide pas la médiane :** `karatsuba_mul` représente ~98 % des instructions exécutées. C'est une fonction large et récursive — l'inlining ne s'y applique pas. Les fonctions que l'inlining améliore (helpers GF, vecteurs) représentent collectivement ~2 % du temps, d'où un impact quasi nul sur la médiane.

---

## 5. Axes d'amélioration

### 5.1 Inlining — impact mesuré et nul sur la médiane

Trois configurations ont été testées et mesurées :

| Configuration | Effet | Médiane keypair |
|---|---|---|
| `--release --features profiling` | `inline(never)` sur fonctions clés + `threshold=0` | 3,79 ms |
| `--release` | `threshold=0` uniquement | 3,78 ms |
| `--profile release-opt` | inlining LLVM par défaut (seuil 275) | 3,85 ms |

Les trois donnent des résultats identiques. La raison : `karatsuba_mul` consomme ~98 % du temps total. C'est une grande fonction récursive que l'inlining ne peut pas absorber.
Les fonctions auxiliaires qui bénéficieraient de l'inlining (`bit0mask`, `compare_u32`,`barrett_reduce`...) représentent collectivement ~2 % du temps — leur inlining est donc invisible sur la médiane.

**Conclusion : l'inlining n'est pas un levier d'optimisation pour HQC.** La variance est légèrement réduite avec `release-opt` (comportement de cache plus régulier), mais la performance médiane ne bouge pas.

### 5.2 Utiliser l'implémentation AVX2

Le dépôt C dispose d'une implémentation `x86_64` avec AVX2 (`-DHQC_ARCH=x86_64`).
Elle vectorise notamment `schoolbook_mul` sur 256 bits. Côté Rust, une implémentation équivalente avec `std::arch` ou la crate `packed_simd` permettrait un gain similaire.
Gain typique sur `vect_mul` : **×2–4**.

### 5.3 Paralléliser les multiplications indépendantes

Dans `enc`, les deux multiplications `r2·h` et `r2·s` sont indépendantes.
Dans `dec`, `y·u` pourrait être lancé en parallèle du rechiffrement.
L'utilisation de threads (Rayon) ou d'`async` permettrait de les exécuter simultanément sur des cœurs différents. Gain potentiel : **25–40 %** sur `enc` et `dec`.

