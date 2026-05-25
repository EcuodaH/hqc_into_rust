
# HQC en Rust

L'objectif de ce projet a été d'implémenter l'algorithme hqc en langage Rust


## Présentation de l'archive

L'archive se décompose en différents modules s'occupant chacune d'une partie de l'algorithme.\
Pour plus d'information sur l'architecture : [ARCHITECTURE.md](https://github.com/EcuodaH/hqc_into_rust/tree/main/ARCHITECTURE.md)

En voici un résumé très concis :

### Descriptions des modules
#### Le module hqc.rs
Base de l'algorithme, il permet de générer les clés publiques et privées et de chiffrer/déchiffrer un message.

#### Le module vector.rs
Gère les opérations classiques sur les vecteurs.

#### Le module gf2x.rs
Gère les opérations classiques dans GF(2)[X^n - 1].

#### Le module code.rs
Encode et décode les messages en utilisant les modules reed_solomon et reed_muller. Encapsulation de reed_muller et reed_solomon.

#### Le module parsing.rs
S'occupe de la traduction des bytes en vecteurs u64.

#### Le module reed_solomon.rs
Ajoute le code correcteur reed_solomon et de décode les messages. Il travaille ici sur des symboles en bytes.

#### Le module reed_muller.rs
Encode 1 byte ( =8 bits ) en 128 bits en ajoutant une forte redondance.

#### Le module symmetric.rs
Permet d'utiliser simplement les hash et shake256.

## Running Tests

Pour pouvoir lancer les tests (kats) il faut avoir le compilateur cargo et lancer dans le dossier racine hqc_rust

```bash
  cargo test test_kat
```
## Profiling

Pour le profiling nous avons utilisé les outils valgrind et samply afin de générer les données nécessaires à l'analyse. Nous avons fait nos recherches nous mêmes afin de trouver les moyennes de temps de calcul et d'espace. Nos résultats sont contenus dans ce document : 

Afin d'automatiser tout ça, un script de profiling à été généré via Claude. Celui-ci nous permet notemment de générer les graphiques d'appels de fonctions, ainsi que de réunir les données sous un format JSON.

```python
  python3 profile.py
```


Il est possible sous linux que les privilèges soient trop bas. Cela vous sera indiqué si vous essayez de lancer le profile.py. Dans ce cas tapez la commande suivante : 
```bash
  sudo sysctl kernel.perf_event_paranoid=1
```


## Adaptations nécessaires

Le portage de C vers Rust a nécessité plusieurs ajustements liés aux différences fondamentales entre les deux langages. Toutes ces adaptations viennent de la différence entre les 2 langages et de la sécurité sur les types imposée par Rust.

-Les accès mémoire non alignés, courants en C, provoquent des panics en Rust debug — notamment pour lire v depuis le ciphertext à l'offset 2209 qui n'est pas aligné sur 8 octets, ce qui a imposé de passer par un buffer intermédiaire aligné.\
-Les soustractions entières qui wrappent silencieusement en C (comme 0 - 1 = 255 sur un u8) déclenchent un panic en Rust debug, résolu avec wrapping_sub.\
-Les pointeurs et casts unsafe omniprésents en C — notamment pour lire des tableaux u64 comme des slices d'octets — ont dû être explicitement marqués unsafe en Rust via std::slice::from_raw_parts.\

## Réflexion sur les résultats
Temps constant : se référer au fichier [TEMPS_CONSTANT.md](https://github.com/EcuodaH/hqc_into_rust/tree/main/TEMPS_CONSTANT.md)

## Auteurs

- Haddouche Mathis, mail : mathis.haddouche@alumni.enac.fr
- Béguet Mathis
- Ledrappier Abel
- Leroux Arthur, [arthur](https://github.com/EcuodaH/hqc_into_rust/blob/main)


## Documentation

[Pour plus de détails sur l'architecture](https://github.com/EcuodaH/hqc_into_rust/tree/main/ARCHITECTURE.md)


