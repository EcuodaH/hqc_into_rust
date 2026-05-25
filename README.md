
# HQC en Rust

L'objectif de ce projet a été d'implémenter l'algorithme hqc en langage Rust


## Présentation de l'archive

L'archive se décompose en différents modules s'occupant chacune d'une partie de l'algorithme.

### Descriptions des modules
#### Le module hqc.rs
Base de l'algorithme, il permet de générer les clés publiques et privées et de chiffrer/déchiffrer un message.

#### le module vector.rs
Gère les opérations classiques sur les vecteurs.

#### le module gf2x.rs
Gère les opérations classiques dans GF(2)[X^n - 1].

#### le module code.rs
Encode et décode les messages en utilisant les modules reed_solomon et reed_muller. Encapsulation de reed_muller et reed_solomon.

#### le module parsing.rs
S'occupe de la traduction des bytes en vecteurs u64.

#### le module reed_solomon.rs
Ajoute le code correcteur reed_solomon et de décode les messages. Il travaille ici sur des symboles en bytes.

#### le module reed_muller.rs
Encode 1 byte ( =8 bits ) en 128 bits en ajoutant une forte redondance.

#### le module symmetric.rs
Permet d'utiliser simplement les hash et shake256.

## Running Tests

Pour pouvoir lancer les tests (kats) il faut avoir le compilateur cargo et lancer dans le dossier racine hqc_rust

```bash
  cargo test test_kat
```


## Adaptations nécessaires


```

```
## Réflexion sur les résultats


## Auteurs

- Haddouche Mathis, mail : mathis.haddouche@alumni.enac.fr
- Béguet Mathis
- Ledrappier Abel
- Leroux Arthur, [arthur](https://github.com/EcuodaH/hqc_into_rust/blob/main)


## Documentation

[Pour plus de détails sur l'architecture](https://github.com/EcuodaH/hqc_into_rust/tree/main/ARCHITECTURE.md)


