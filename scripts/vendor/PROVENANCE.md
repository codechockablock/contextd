# Vendored third-party code — provenance

These files exist so that `scripts/verify_format_independent.mjs` can verify
ML-DSA (FIPS 204) checkpoint signatures on any Node runtime, including ones
whose OpenSSL predates ML-DSA support (Node < 24 / OpenSSL < 3.5). They are
**verify-only in use**: the vendored modules expose signing and keygen, but
the verifier never calls anything except `ml_dsa44/65/87.verify`. There is no
`package.json`, no npm install step, and no network access at verify time —
the verifier plus this directory is a self-contained artifact.

## Upstream sources

| Package | Version | Upstream repo | Upstream commit (npm `gitHead`) | npm tarball SHA-256 |
|---|---|---|---|---|
| `@noble/post-quantum` | 0.4.1 | https://github.com/paulmillr/noble-post-quantum | `17834f542f8f6f8e60f5ae0b9718f404ea95c5d5` | `3858ef059d4b3fceca7f179e7470883bd5eb9eaf74457c1d00ec1746e5a90f3d` |
| `@noble/hashes` | 1.8.0 | https://github.com/paulmillr/noble-hashes | `32f700f38ec49d7e6b2ab687904d6b2d7d60d80a` | `e8a765d92c04faaccba8776411c5038cb195f812ee629fce07e1d2e6aec80ea0` |

Tarballs were fetched from `registry.npmjs.org` on 2026-08-18. Registry
integrity strings: post-quantum `sha512-TRXjvnY9jAFNWbxOx+pKt21BNsCEWKFjMbIK
wdx9CQXBudDanpY20EfOcooV7DIsRS/+Mf8D8utpUPjfGrQ8fA==`, hashes `sha512-jCs9ld
d7NwzpgXDIf6P3+NrHh9/sD6CQdxHyjQI+h/6rDNo88ypBxxz45UDuZHz9r3tNz7N/VInSVoVdtX
EI4A==`.

`@noble/post-quantum` 0.4.1 is pinned deliberately: it is the newest release
whose dependency graph is exactly ML-DSA + `@noble/hashes`. Every release from
0.5.0 on additionally depends on `@noble/curves` (NTT via `abstract/fft.js`),
which would widen this directory beyond ML-DSA verification + SHA-3/SHAKE.

Files are the `esm/` builds from the npm tarballs. `noble-hashes/sha2.js` and
`noble-hashes/_md.js` are present only because `noble-post-quantum/utils.js`
statically imports SHA-2 for ML-DSA *pre-hash* variants; the verifier uses
pure ML-DSA only and never executes them.

## Per-file hashes

`upstream sha256` is the file exactly as extracted from the npm tarball;
`vendored sha256` is the file as committed here. Where they differ, the ONLY
change is the import-specifier rewrite listed in the next section.

| File | Upstream path | Upstream SHA-256 | Vendored SHA-256 |
|---|---|---|---|
| `noble-hashes/_md.js` | `package/esm/_md.js` | `cefb1557e7715cb2117c83f82ef3e3175c7e0391c80bd5795b2d4effc45fc582` | (identical) |
| `noble-hashes/_u64.js` | `package/esm/_u64.js` | `e48c0cfc10810439a4807b46db136ce603a3fa09b62584f513ef2f3ca496af54` | (identical) |
| `noble-hashes/crypto.js` | `package/esm/crypto.js` | `9211d026c5d21e60e0126dd6f01150d87da5ba7261b8f468215c1264372ff5a5` | (identical) |
| `noble-hashes/sha2.js` | `package/esm/sha2.js` | `e729088b82e5450bff54c3a0013582aa42e1fe8f58dd31f5967f6ebe34c52299` | (identical) |
| `noble-hashes/sha3.js` | `package/esm/sha3.js` | `0260b46f92a3a94c7179958600d7f92469ef2c8f5d2e966bd9a838ff815713e9` | (identical) |
| `noble-hashes/utils.js` | `package/esm/utils.js` | `4cf4c1e05affedcb4fd584a43d76ae1a3711e34a36e2251b90c27e33ecc74fad` | `6939d5778fbd4a10feb224e1b9158ea59fb160b59dcaa43ea2ebb49f85c3b4ce` |
| `noble-post-quantum/_crystals.js` | `package/esm/_crystals.js` | `b36ec0d1a8f27c5c1d8eb8ffc9a0f04af2675952b48b9ee66000b9def03f9c09` | `76ea8780911d316c41f65d4e2a163add0d725196fb64533ddbf55bd7b7f8bb17` |
| `noble-post-quantum/ml-dsa.js` | `package/esm/ml-dsa.js` | `aac8f853f1e8e646587477f7fb4d94fbea083208a4c0c75876d5e9a26deffc51` | `82cdd530308f9188efec95514d478810d7569a1e74d3c3d484e30f3e438a96b7` |
| `noble-post-quantum/utils.js` | `package/esm/utils.js` | `75937e5ea90893b1817105cdd8de30676cebc19c34478ba6120d11b5e1f58930` | `06e497db5d028ae88aba593035ccb2f71afc836186e9623366e09e7c66de0b6f` |

## Modifications

Six `import` lines rewritten from bare package specifiers to relative paths,
so the files resolve with no `node_modules` and no `package.json`. Nothing
else was changed — no code, no logic, no whitespace.

| File | Original specifier | Rewritten to |
|---|---|---|
| `noble-hashes/utils.js` | `'@noble/hashes/crypto'` | `'./crypto.js'` |
| `noble-post-quantum/ml-dsa.js` | `'@noble/hashes/sha3'` | `'../noble-hashes/sha3.js'` |
| `noble-post-quantum/_crystals.js` | `'@noble/hashes/sha3'` | `'../noble-hashes/sha3.js'` |
| `noble-post-quantum/utils.js` | `'@noble/hashes/sha2'` | `'../noble-hashes/sha2.js'` |
| `noble-post-quantum/utils.js` | `'@noble/hashes/sha3'` | `'../noble-hashes/sha3.js'` |
| `noble-post-quantum/utils.js` | `'@noble/hashes/utils'` | `'../noble-hashes/utils.js'` |

## License

Both packages are MIT, © Paul Miller (https://paulmillr.com). The full
license text ships beside the code: `noble-hashes/LICENSE` and
`noble-post-quantum/LICENSE`.

## Known cosmetic wart

Node prints a one-line `MODULE_TYPELESS_PACKAGE_JSON` warning to stderr when
loading these `.js` files, because there is deliberately no `package.json` to
declare `"type": "module"`; node detects ESM syntax and reparses. Harmless,
and the price of keeping this directory free of package machinery.
