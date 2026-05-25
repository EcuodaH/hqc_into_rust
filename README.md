
# HQC en Rust

L'objectif de ce projet a été d'implémenter l'algorithme hqc en langage Rust


## Présentation de l'archive

l'archive se décompose en différents modules s'occupant chacune d'une partie de l'algorithme.

#### le module hqc.rs
ce module est le coeur de l'algorithme, il permet de générer les clés publiques et privées et de chiffrer/déchiffrer un message.

#### le module vector.rs
ce module gère les opérations classiques sur les vecteurs.

#### le module gf2x.rs
ce module gère les opérations classiques dans GF(2)[X].

#### le module code.rs
ce module encode et décode les messages en utilisant les modules reed_solomon et reed_muller.

#### le module parsing.rs
ce module s'occupe de la traduction des bytesen vecteurs u64.

#### le module reed_solomon.rs
ce module ajoute le code correcteur reed_solomon et de décoder les messages. Il travaille ici sur des symboles en bytes.

#### le module reed_muller.rs
ce module encode 1 byte ( =8 bits ) en 128 bits en ajoutant une forte redondance.

#### le module symmetric.rs
ce module permet d'utiliser simplement les hash et shake256.
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


