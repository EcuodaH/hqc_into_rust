# Rapport de Profiling — HQC-128

**Environnement :** Linux x86-64, mode release  
**KATs :** 100 vecteurs de test (`PQCkemKAT_2321.rsp`)

---

## 1. Quelques rappels sur HQC

HQC (Hamming Quasi-Cyclic) est un algorithme de **chiffrement post-quantique**. L'idée : même un ordinateur quantique ne peut pas casser ce chiffrement.

Il fonctionne comme un KEM (Key Encapsulation Mechanism) : au lieu de chiffrer directement un message,
on s'en sert pour que deux personnes se mettent d'accord sur une clé secrète partagée de 32 octets,
sans jamais se la transmettre directement.

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

Pour chaque KAT, on mesure le temps de chacune des trois opérations séparément, ainsi que la variation de mémoire RSS avant/après chaque appel. On reproduit cette mesure sur les 100 seeds pour obtenir une distribution
représentative.

### Implémentation Rust

Le binaire de profiling se trouve dans `src/bin/profile_kats.rs`.
Il lit les 100 seeds du fichier `tests/PQCkemKAT_2321.rsp`, exécute les trois opérations
sur chaque seed, et mesure le temps avec `std::time::Instant`.

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

Le fichier de profiling se mets dans `tests/bench/benchmark_kats.c` du dépôt C. (Fichier donné dans le dossier implem_bench du répo rust)
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

### 3.1 Implémentation Rust

Mesures sur 100 KATs, mode release (`-O2`, `inline-threshold=0`).

| Opération | Min | Médiane | Moyenne | P95 | Max |
|-----------|-----|---------|---------|-----|-----|
| keypair | 2,40 ms | 3,67 ms | 3,69 ms | 3,92 ms | 4,97 ms |
| enc | 4,48 ms | 7,32 ms | 7,34 ms | 7,92 ms | 9,58 ms |
| dec | 7,38 ms | 11,07 ms | 11,20 ms | 12,16 ms | 17,03 ms |

**Pic mémoire (VmHWM) : 4 076 Ko (~4 Mo)**

La variance est notable (écart min/max d'un facteur ~2) car les premières itérations
profitent de caches CPU froids, et le scheduler OS introduit du bruit.
La médiane est la valeur la plus représentative du comportement en régime établi.

### 3.2 Implémentation C (référence)

Mesures sur 100 KATs, mode release (`-O2`, architecture `ref`).

| Opération | Min | Médiane | Moyenne | P95 | Max |
|-----------|-----|---------|---------|-----|-----|
| keypair | 2,95 ms | 2,97 ms | 3,00 ms | 3,11 ms | 3,14 ms |
| enc | 5,91 ms | 5,96 ms | 6,00 ms | 6,28 ms | 6,47 ms |
| dec | 9,10 ms | 9,18 ms | 9,27 ms | 9,53 ms | 12,86 ms |

**Pic mémoire (VmHWM) : 1 768 Ko (~1,7 Mo)**

La variance est très faible : les temps sont quasi-constants d'un KAT à l'autre,
signe que la compilation C produit un code plus prévisible en termes de cache.

---
