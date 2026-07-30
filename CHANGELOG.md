# Changelog

## [0.1.2](https://github.com/ridi-oss/proxy-monster/compare/server-v0.1.1...server-v0.1.2) (2026-07-30)


### Bug Fixes

* **ci:** let a published tag settle before calling it divergent ([#50](https://github.com/ridi-oss/proxy-monster/issues/50)) ([6538a33](https://github.com/ridi-oss/proxy-monster/commit/6538a33114d86ca766e300197720059bd7c49566))
* **cp:** compare only the host on the /mcp authority gate ([#48](https://github.com/ridi-oss/proxy-monster/issues/48)) ([7aa3bb2](https://github.com/ridi-oss/proxy-monster/commit/7aa3bb23505ab38d8b1fac380fdd691a2dee835f))
* **cp:** return the principal's resolved roles from /auth/me ([#49](https://github.com/ridi-oss/proxy-monster/issues/49)) ([f3401e1](https://github.com/ridi-oss/proxy-monster/commit/f3401e179b2b56f3947e1cc136f9205483573535))


### Performance

* **cp:** open a session from the catalog already held ([#51](https://github.com/ridi-oss/proxy-monster/issues/51)) ([b57a1ea](https://github.com/ridi-oss/proxy-monster/commit/b57a1ead9f467f9f9f045f0340b0c5967961eb6a))


### Documentation

* point at the published server images, and verify a partial push ([#43](https://github.com/ridi-oss/proxy-monster/issues/43)) ([f4cfd5b](https://github.com/ridi-oss/proxy-monster/commit/f4cfd5bc8447bd912485fb22ffbec852e949d7b4))

## [0.1.1](https://github.com/ridi-oss/proxy-monster/compare/server-v0.1.0...server-v0.1.1) (2026-07-30)


### Bug Fixes

* **proxy:** bound the events stream so a dead one cannot persist ([#42](https://github.com/ridi-oss/proxy-monster/issues/42)) ([4ff1c23](https://github.com/ridi-oss/proxy-monster/commit/4ff1c2359615fd082390e2b3423504e0379d0238))

## 0.1.0 (2026-07-30)


### Bug Fixes

* **auditmon:** boot on the environment alone ([c46b0ee](https://github.com/ridi-oss/proxy-monster/commit/c46b0eefc80e5a858b358ded0f69d3aff292d9d9))
* **auditmon:** let the bucket's Object-Lock policy govern retention ([80f1d35](https://github.com/ridi-oss/proxy-monster/commit/80f1d35d49d685688648a7de7339b21fc15614af))
* **cp:** tell a wedged proxy stream apart from an absent one ([e819cf0](https://github.com/ridi-oss/proxy-monster/commit/e819cf048b2e2664309a59690e2cae59062cec48))


### Performance

* **db:** memoize per-table MySQL normalization, batch column folding ([#5](https://github.com/ridi-oss/proxy-monster/issues/5)) ([ff35f4e](https://github.com/ridi-oss/proxy-monster/commit/ff35f4e7f24de092c67054339b15b842674bfeb0))


### Build & Dependencies

* **deps:** depend on the published mysqlwire, not the sibling directory ([#11](https://github.com/ridi-oss/proxy-monster/issues/11)) ([63c9603](https://github.com/ridi-oss/proxy-monster/commit/63c9603ff28a6224102ed3923430b3f18a101f3f))
* hold dependency updates for a cooldown, and accept Dependabot's subject case ([121d8c0](https://github.com/ridi-oss/proxy-monster/commit/121d8c0a0bf9d02bfe4edf491d01df89e2530132))
* keep the release trains below 1.0.0 ([#19](https://github.com/ridi-oss/proxy-monster/issues/19)) ([45ecde9](https://github.com/ridi-oss/proxy-monster/commit/45ecde9ed7a89ddbe72f8cabe424f2c27d3236b5))
* move the Go toolchain to 1.26 ([f4f62e1](https://github.com/ridi-oss/proxy-monster/commit/f4f62e1196f76367aa08bf41608f5a6080557da5))
* pin @types/node to the Node major the toolchain runs ([0e83120](https://github.com/ridi-oss/proxy-monster/commit/0e83120b8c649f08a86e59d36328b44dffbf7a7b))
* register the native-lib tasks the way Gradle 9 requires ([056fc73](https://github.com/ridi-oss/proxy-monster/commit/056fc73c93e25d468501574742abca6abd188591))
* release trains for the server, the client, and mysqlwire ([#12](https://github.com/ridi-oss/proxy-monster/issues/12)) ([f6c95f1](https://github.com/ridi-oss/proxy-monster/commit/f6c95f120685e052c576465c8e9ec00d4d5ce0be))


### Documentation

* **pmon:** install from the Homebrew tap ([#38](https://github.com/ridi-oss/proxy-monster/issues/38)) ([8d99938](https://github.com/ridi-oss/proxy-monster/commit/8d9993832a0e80bf81a2072e7413d8269abb94e1))
