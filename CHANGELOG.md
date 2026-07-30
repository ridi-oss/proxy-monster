# Changelog

## 0.1.0 (2026-07-30)


### Bug Fixes

* **auditmon:** boot on the environment alone ([c46b0ee](https://github.com/ridi-oss/proxy-monster/commit/c46b0eefc80e5a858b358ded0f69d3aff292d9d9))
* **auditmon:** let the bucket's Object-Lock policy govern retention ([80f1d35](https://github.com/ridi-oss/proxy-monster/commit/80f1d35d49d685688648a7de7339b21fc15614af))


### Performance

* **db:** memoize per-table MySQL normalization, batch column folding ([#5](https://github.com/ridi-oss/proxy-monster/issues/5)) ([ff35f4e](https://github.com/ridi-oss/proxy-monster/commit/ff35f4e7f24de092c67054339b15b842674bfeb0))


### Build & Dependencies

* **deps:** depend on the published mysqlwire, not the sibling directory ([#11](https://github.com/ridi-oss/proxy-monster/issues/11)) ([63c9603](https://github.com/ridi-oss/proxy-monster/commit/63c9603ff28a6224102ed3923430b3f18a101f3f))
* hold dependency updates for a cooldown, and accept Dependabot's subject case ([121d8c0](https://github.com/ridi-oss/proxy-monster/commit/121d8c0a0bf9d02bfe4edf491d01df89e2530132))
* keep the release trains below 1.0.0 ([#19](https://github.com/ridi-oss/proxy-monster/issues/19)) ([45ecde9](https://github.com/ridi-oss/proxy-monster/commit/45ecde9ed7a89ddbe72f8cabe424f2c27d3236b5))
* release trains for the server, the client, and mysqlwire ([#12](https://github.com/ridi-oss/proxy-monster/issues/12)) ([f6c95f1](https://github.com/ridi-oss/proxy-monster/commit/f6c95f120685e052c576465c8e9ec00d4d5ce0be))
