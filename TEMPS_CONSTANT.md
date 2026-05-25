# Code en temps constant — HQC

Le temps constant signifie que le temps d'exécution d'une fonction **ne dépend pas des données secrètes**.
Sans ça, un attaquant qui mesure précisément le temps d'exécution peut retrouver des bits de clé (*timing attack*).

---

## `src/kem.rs`

### Sélection finale de la clé partagée

```rust
result = result.wrapping_sub(1);
for i in 0..SHARED_SECRET_BYTES {
    k_prime[i] = (k_prime[i] & result) ^ (k_bar[i] & !result);
}
```

Point le plus critique du projet. Si le chiffré reçu ne correspond pas au chiffré recalculé,
il faut retourner `K̄` (valeur de repli) au lieu de `K'`. Un simple `if ct == ct'` fuiterait
**combien d'octets correspondent** avant la divergence. Ici : on compare tout, on calcule les deux
valeurs, on sélectionne avec un masque en une seule passe.

---

## `src/vector.rs`

### `compare_u32`

```rust
fn compare_u32(v1: u32, v2: u32) -> u32 {
    1 ^ (((v1.wrapping_sub(v2)) | (v2.wrapping_sub(v1))) >> 31)
}
```

Égalité sans branchement : si `v1 != v2`, au moins un des deux `wrapping_sub` a son bit 31 à 1.
Utilisée pour la dé-duplication du support dans `vect_generate_random_support2`.

### `barrett_reduce`

```rust
let reduce_flag = (r.wrapping_sub(PARAM_N as u32) >> 31) ^ 1;
let mask = reduce_flag.wrapping_neg();
r.wrapping_sub(mask & (PARAM_N as u32))
```

Correction finale `if r >= N then r -= N` sans branchement : le masque vaut `0xFFFFFFFF`
si la soustraction est nécessaire, `0x00000000` sinon.

### Dé-duplication dans `vect_generate_random_support2`

```rust
found |= compare_u32(support[i], support[j]);
let mask = found.wrapping_neg();
support[i] = (mask & i as u32) ^ (!mask & support[i]);
```

Si un doublon est détecté, on remplace par `i` (index courant) — sans jamais brancher sur le résultat.

### `vect_write_support_to_vector`

```rust
let tmp: u32 = (i as u32).wrapping_sub(index_tab[j]);
let val1: u32 = 1 ^ ((tmp | tmp.wrapping_neg()) >> 31);
let mask: u64 = (val1 as u64).wrapping_neg();
val |= bit_tab[j] & mask;
```

Pour chaque mot du vecteur, on vérifie si `i == index_tab[j]` sans `if` :
le masque est `0xFFFFFFFFFFFFFFFF` si oui, `0` sinon.

### `vect_compare`

```rust
let mut r: u16 = 0x0100;
for i in 0..size {
    r |= (v1[i] ^ v2[i]) as u16;
}
((r - 1) >> 8) as u8
```

Comparaison sans `return false` anticipé : on parcourt **toujours** tous les octets.
Retourne `1` si égaux, `0` sinon — en temps constant quelle que soit la position de la première différence.

---

## `src/reed_muller.rs`

### `bit0mask`

```rust
fn bit0mask(x: i32) -> i32 {
    -((x) & 1)
}
```

Produit `0xFFFFFFFF` si le bit 0 de `x` est 1, `0x00000000` sinon.
Utilisée dans tout `encode` pour construire les mots du codeword sans branchement sur les bits du message.

### `find_peaks`

```rust
let pos_mask: i32 = -((t > 0) as i32);
let absolute = (pos_mask & (t as i32)) | (!pos_mask & -(t as i32));
```

Valeur absolue sans `if t < 0` : `pos_mask` vaut `-1` si `t > 0`, `0` sinon,
ce qui sélectionne `t` ou `-t` par masque.

---

## `src/reed_solomon.rs`

### Berlekamp-Massey (`compute_elp`)

```rust
let mask1 = (d.wrapping_neg() >> 15).wrapping_neg();
let mask2 = (deg_sigma.wrapping_sub(deg_x_sigma_p) >> 15).wrapping_neg();
let mask12__ = std::hint::black_box(mask1 & mask2);
```

Les deux conditions du BM (`d != 0` et `deg_sigma <= deg_x_sigma_p`) sont évaluées
en masques. `std::hint::black_box` empêche le compilateur d'optimiser et de réintroduire un branchement.

### Calcul des polynômes

```rust
let mask = ((i as u16).wrapping_sub(degree).wrapping_sub(1) >> 15).wrapping_neg();
```

Conditionne les écritures dans les tableaux de polynômes sans boucle conditionnelle.

### `compute_roots` / `compute_error_values`

```rust
let mask1: u16 = ((error[i] as i32).wrapping_neg() >> 31) as u16;
let mask2: u16 = !((((j as i32) ^ (delta_counter as i32)).wrapping_neg() >> 31) as u16);
beta_j[j] += mask1 & mask2 & GF_EXP[i];
```

Accumulation conditionnelle des positions et valeurs d'erreur sans branchement sur les données.

### Réduction d'index cyclique

```rust
let tmp = i.wrapping_sub(modulus);
```

Évite un `if i >= modulus` qui fuiterait la valeur de `i`.

---

## `src/gf2x.rs`

### `schoolbook_mul`

```rust
let mask = ((ai >> bit) & 1u64).wrapping_neg();
r[i + j] ^= b[j] & mask;
```

Chaque bit de `a[i]` est transformé en masque 64 bits (`0` ou `0xFFFFFFFFFFFFFFFF`)
pour conditionner l'XOR avec `b[j]` — sans `if bit_est_a_1`.

---

## `src/fft.rs`

### `fft_retrieve_error_poly`

```rust
error[0] ^= (1 ^ (((w[0]).wrapping_neg() as u16) >> 15)) as u8;
```

Sélection des positions d'erreur sans branchement sur les valeurs du spectre.

---

## Zeroize — effacement mémoire

Bien que ce ne soit pas du temps constant à proprement parler, `zeroize()` fait partie
des mêmes protections contre les attaques par canal auxiliaire.
Les données suivantes sont effacées de la RAM après usage :

| Fichier | Variables effacées |
|---------|-------------------|
| `kem.rs` | `seed_kem`, `sigma`, `seed_pke`, `dk_pke`, `m`, `k_theta`, `theta`, `m_prime`, `k_theta_prime`, `k_bar`, `theta_prime` |
| `hqc.rs` | `keypair_seed`, `x`, `y`, `r1`, `r2`, `e`, `tmp`, `tmp1`, `tmp2` |
| `code.rs` | `tmp` (buffer intermédiaire RS→RM) |
| `reed_solomon.rs` | `cdw_bytes` |

Sans `zeroize`, ces valeurs resteraient en mémoire et pourraient être récupérées
via un core dump, un heap spray, ou une attaque cold-boot.
