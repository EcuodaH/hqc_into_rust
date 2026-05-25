# Rapport de Profiling — HQC-256

**Données :** 100 KATs (Known Answer Tests)

---

## 1. Quelques rappels sur HQC

HQC (Hamming Quasi-Cyclic) est un algorithme de **chiffrement post-quantique** sélectionné par le NIST en 2024.
L'idée : même un ordinateur quantique ne peut pas casser ce chiffrement.

Il fonctionne comme un KEM (Key Encapsulation Mechanism) : au lieu de chiffrer directement un message,
on s'en sert pour que deux personnes se mettent d'accord sur une clé secrète partagée de 32 octets,
sans jamais se la transmettre directement.

### Les trois opérations

| Opération | Rôle | Qui l'exécute |
|-----------|------|---------------|
| **keypair** | Générer une paire clé publique / clé secrète | Le serveur |
| **enc** | Encapsuler une clé secrète dans un chiffré | Le client |
| **dec** | Décapsuler : retrouver la clé secrète depuis le chiffré | Le serveur |

---

## 2. Résultats de performance

Ces mesures ont été effectuées sur **100 KATs** (100 exécutions complètes avec des données officielles).

### 2.1 Temps d'exécution (wall-clock)

| Opération | Minimum | Médiane | Moyenne | Maximum |
|-----------|---------|---------|---------|---------|
| keypair   | 1,12 ms | 3,62 ms | 2,63 ms | 5,16 ms |
| enc       | 2,21 ms | 7,26 ms | 5,24 ms | 11,61 ms |
| dec       | 3,32 ms | 11,01 ms | 7,87 ms | 14,88 ms |

> **Pourquoi la médiane est-elle plus haute que la moyenne ?**
> Les premières exécutions bénéficient du cache CPU chaud (temps courts), tirant la moyenne vers le bas.
> La médiane reflète mieux le comportement "normal".

#### Ce que ça veut dire concrètement

- **keypair** en ~3,6 ms : générer ses clés est rapide. On le fait rarement (une fois par session).
- **enc** en ~7,3 ms : le client encapsule la clé. Acceptable pour établir une connexion TLS.
- **dec** en ~11 ms : le serveur décapsule. C'est l'opération la plus coûteuse car elle fait une **ré-encryption complète** pour vérifier le chiffré (protection contre les attaques actives).

> **Comparaison :** RSA-2048 keygen prend ~50 ms, enc/dec ~1 ms. HQC est plus lent sur le chiffrement
> mais offre une sécurité post-quantique. Les tailles de clés (ci-dessous) sont le vrai défi.

### 2.2 Mémoire utilisée

| Métrique | Valeur |
|----------|--------|
| Pic mémoire (VmHWM) | **~4 Mo** |

La mémoire utilisée est raisonnable. La plupart du stack est consommé par les buffers temporaires
de la multiplication de polynômes (Karatsuba).

### 2.3 Tailles des objets cryptographiques

| Objet | Taille |
|-------|--------|
| Clé publique (`ek`) | 2 241 octets (~2,2 Ko) |
| Clé secrète (`dk`) | 2 321 octets (~2,3 Ko) |
| Chiffré (`ct`) | 4 433 octets (~4,3 Ko) |
| Secret partagé (`ss`) | 32 octets |

> **Comparaison RSA-2048 :** clé publique ~256 octets, chiffré ~256 octets.
> HQC paie sa sécurité post-quantique avec des objets **~10–17× plus grands**.
> C'est le compromis fondamental de la crypto post-quantique basée sur les codes.

---

## 3. Où passe le temps ? (analyse du call graph)

### 3.1 La fonction dominante : `karatsuba_mul`

Quand on profile avec callgrind (comptage d'instructions CPU), **~98 % des instructions** sont
exécutées dans `gf2x::karatsuba_mul` et `gf2x::schoolbook_mul`.
Cela vient du fait que HQC repose sur des multiplications de polynômes dans l'anneau GF(2)[X]/(X^N − 1)
avec N = 17 669. Multiplier deux polynômes de degré ~17 000 est intrinsèquement coûteux.

L'algorithme de Karatsuba divise le problème en 3 sous-problèmes de taille moitié au lieu de 4
(multiplication naïve). Sur de grands polynômes, c'est un gain majeur.

```
vect_mul (1 appel)
  └─ karatsuba_mul          ← diviser pour régner, récursif
       ├─ karatsuba_mul (×3 récursif jusqu'à n ≤ 16)
       └─ schoolbook_mul    ← cas de base : boucle simple sur 64-bit words
```

Chaque appel à `enc` ou `dec` fait **2 multiplications** (`r2·h` et `r2·s`),
et `dec` en fait **3** (+ `y·u` pour déchiffrer).

### 3.2 Arbre d'appels complet

Les call graphs SVG sont disponibles dans `profiling_results/` :

| Fichier | Contenu |
|---------|---------|
| `graph_static_global.svg` | Toutes les fonctions HQC (59 nœuds) |
| `graph_static_keypair.svg` | Uniquement les appels de keypair |
| `graph_static_enc.svg` | Uniquement les appels de enc |
| `graph_static_dec.svg` | Uniquement les appels de dec |

Ouvrir `rapport_profiling.html` pour naviguer entre les graphes dans le navigateur.

### 3.3 Résumé des modules et leur rôle

| Module | Rôle | Poids |
|--------|------|-------|
| `kem` | Interface publique KEM (3 fonctions) | ~0 % |
| `hqc` | Couche PKE sous-jacente | ~0 % |
| `gf2x` | Multiplication polynômes GF(2)[X] | **~98 %** |
| `vector` | Vecteurs épars, échantillonnage aléatoire | ~1 % |
| `code` | Encodage/décodage correcteur d'erreurs | ~1 % |
| `reed_solomon` | Code RS(46,16,15) | ~0,5 % |
| `reed_muller` | Code RM(1,7)×3 | ~0,3 % |
| `fft` | FFT sur GF(2^8) pour Reed-Solomon | ~0,2 % |
| `gf` | Arithmétique GF(2^8) | ~0,1 % |
| `symmetric` | SHA3-256/512, SHAKE256 | ~0,1 % |
| `parsing` | Sérialisation des clés et chiffrés | ~0 % |

---

## 4. Comprendre les composants cryptographiques

### 4.1 Le code correcteur d'erreurs : pourquoi c'est là ?

HQC chiffre en **ajoutant intentionnellement du bruit** (des erreurs aléatoires) au message.
Seul le détenteur de la clé secrète peut enlever ce bruit. Pour être sûr de récupérer le message
exact malgré ce bruit, on utilise un **code correcteur d'erreurs** à deux niveaux :

```
Message (16 octets)
  ↓ Reed-Solomon RS(46,16,15) — corrige jusqu'à 15 erreurs de symboles
Codeword RS (46 octets)
  ↓ Reed-Muller RM(1,7)×3 — chaque octet → 128 bits, répété 3 fois
Codeword final (17664 bits = 2208 octets)
```

**Reed-Solomon** : code très utilisé (CD, DVD, QR codes). Robuste sur des erreurs par paquets.  
**Reed-Muller** : code simple et très décodable via la transformée de Walsh-Hadamard.

### 4.2 La sécurité : le problème difficile

La sécurité de HQC repose sur la **difficulté de décoder un code linéaire aléatoire**.
Intuition : si on vous donne un vecteur bruité `v = m·G + e` où `e` est une erreur aléatoire
de poids de Hamming `w`, retrouver `m` ou `e` sans connaître la structure secrète est
aussi dur que de trouver une aiguille dans une botte de foin — même pour un ordinateur quantique.

### 4.3 La transformation Fujisaki-Okamoto (FO)

La décrpytion fait une **ré-encryption** puis compare les chiffrés :

```
dec:
  1. Décrypter m' = PKE.Dec(dk, c)
  2. Ré-encrypter c' = PKE.Enc(ek, m', θ')
  3. Si c == c' : retourner K = H_G(m')
     Sinon      : retourner K = H_J(σ)   ← valeur aléatoire indiscernable
```

Cette étape (transform FO) rend le KEM **IND-CCA2 sécurisé** : un attaquant qui modifie
le chiffré ne peut pas en tirer d'information sur la clé secrète. C'est pour ça que `dec`
est plus lent que `enc` : il fait en interne deux fois plus de travail.

---

## 5. Pistes d'optimisation

| Piste | Gain potentiel | Complexité |
|-------|---------------|------------|
| SIMD / AVX2 pour `schoolbook_mul` | ×2–4 sur la mul | Élevée |
| Réduire `MULTIPLICITY` dans RM | Moins de copies | Vérifier DFR |
| Paralléliser les 2 `vect_mul` de `enc` | ×1,5 sur enc | Moyenne |
| Batch decapsulation | Amortir le coût | Faible |

> **Note :** L'implémentation actuelle désactive l'inlining (`inline-threshold=0`) pour la lisibilité
> du profiling. En production, l'activer ferait gagner ~10–20 % sur les petites fonctions.

---

## 6. Glossaire pour débutants

| Terme | Définition |
|-------|-----------|
| **KEM** | Key Encapsulation Mechanism — protocole pour établir une clé secrète partagée |
| **PKE** | Public Key Encryption — chiffrement à clé publique sous-jacent |
| **GF(2)** | Corps à 2 éléments {0, 1} — l'addition est un XOR, la multiplication un AND |
| **Poids de Hamming** | Nombre de bits à 1 dans un vecteur |
| **Vecteur épars** | Vecteur avec très peu de bits à 1 (ici : 66 sur 17 669) |
| **Code correcteur** | Technique d'ajout de redondance pour corriger des erreurs |
| **KAT** | Known Answer Test — vecteur de test officiel NIST pour valider l'implémentation |
| **Callgrind** | Outil Valgrind qui compte les instructions CPU et les appels de fonctions |
| **Wall-clock** | Temps réel écoulé (horloge murale), par opposition au temps CPU |
| **VmHWM** | Virtual Memory High Water Mark — pic de mémoire RAM utilisé |
| **IND-CCA2** | Niveau de sécurité standard : indiscernabilité sous attaque à chiffrés choisis |
