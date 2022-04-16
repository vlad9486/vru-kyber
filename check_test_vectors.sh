#!/usr/bin/env bash

set e

[[ $(shasum -a256 target/test_vectors512.txt) == "6730bb552c22d9d2176ffb5568e48eb30952cf1f065073ec5f9724f6a3c6ea85"* ]]
[[ $(shasum -a256 target/test_vectors768.txt) == "667c8ca2ca93729c0df6ff24588460bad1bbdbfb64ece0fe8563852a7ff348c6"* ]]
[[ $(shasum -a256 target/test_vectors1024.txt) == "ff1a854b9b6761a70c65ccae85246fe0596a949e72eae0866a8a2a2d4ea54b10"* ]]
