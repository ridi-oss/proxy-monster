# Changelog

## [0.1.6](https://github.com/ridi-oss/proxy-monster/compare/server-v0.1.5...server-v0.1.6) (2026-08-03)


### Features

* **control-plane:** add a batch column-tagging MCP tool ([#75](https://github.com/ridi-oss/proxy-monster/issues/75)) ([44c5764](https://github.com/ridi-oss/proxy-monster/commit/44c5764e42e6d202cb4b62a5b84830cbf9eedd12))
* **pmon:** check the local password before brokering a connection ([#67](https://github.com/ridi-oss/proxy-monster/issues/67)) ([87d3156](https://github.com/ridi-oss/proxy-monster/commit/87d3156f2cb73d86cb64b99c7ffbaa99c962a8e0))
* **web:** rename and delete a group from its detail page ([#76](https://github.com/ridi-oss/proxy-monster/issues/76)) ([115b2ac](https://github.com/ridi-oss/proxy-monster/commit/115b2accde8688659f94be299088e9e20af2aa6a))


### Bug Fixes

* **cp:** serve the derived context.tag actions with the policy schema ([#77](https://github.com/ridi-oss/proxy-monster/issues/77)) ([b3aed73](https://github.com/ridi-oss/proxy-monster/commit/b3aed73ffa60937ba9f78649f5cf3a28758dd470))
* **pmon:** open the browser from the CLI, and surface a daemon that is not this build ([#70](https://github.com/ridi-oss/proxy-monster/issues/70)) ([17ac5bb](https://github.com/ridi-oss/proxy-monster/commit/17ac5bb590f83fc2691131e16dbb052e9d632880))
* **web:** give each action-reference group a unique resource key ([#74](https://github.com/ridi-oss/proxy-monster/issues/74)) ([3082599](https://github.com/ridi-oss/proxy-monster/commit/3082599abf08b2573b790627a834246415d31ce8))


### Build & Dependencies

* require mysqlwire v0.1.1 ([#80](https://github.com/ridi-oss/proxy-monster/issues/80)) ([e64bebf](https://github.com/ridi-oss/proxy-monster/commit/e64bebf4c89e5e44ec6d76ade8b2c104a585a85c))


### Documentation

* forbid narrating history in comments and docs ([#71](https://github.com/ridi-oss/proxy-monster/issues/71)) ([ae77de2](https://github.com/ridi-oss/proxy-monster/commit/ae77de2355cc4fd0fc595a42fe4f4fb26dcecc9c))

## [0.1.5](https://github.com/ridi-oss/proxy-monster/compare/server-v0.1.4...server-v0.1.5) (2026-07-31)


### Features

* **control-plane:** send a PKCE S256 challenge when the IdP advertises it ([#64](https://github.com/ridi-oss/proxy-monster/issues/64)) ([bfce32d](https://github.com/ridi-oss/proxy-monster/commit/bfce32dec4c137b9e20d58d838c3874ea668d5d1))


### Bug Fixes

* **cp:** discover roles at the context an approved query executes in ([#63](https://github.com/ridi-oss/proxy-monster/issues/63)) ([a9d825c](https://github.com/ridi-oss/proxy-monster/commit/a9d825c2498a73d92b89db20f1bb4712c118a29b))
* **cp:** surface an editor denial as a decision, not a failure ([#62](https://github.com/ridi-oss/proxy-monster/issues/62)) ([b7fdcb2](https://github.com/ridi-oss/proxy-monster/commit/b7fdcb2332d3f24d896bd07ee93851027f905c36))

## [0.1.4](https://github.com/ridi-oss/proxy-monster/compare/server-v0.1.3...server-v0.1.4) (2026-07-31)


### Bug Fixes

* **cp:** end a task-event stream quietly when its client is gone ([#59](https://github.com/ridi-oss/proxy-monster/issues/59)) ([8cb617c](https://github.com/ridi-oss/proxy-monster/commit/8cb617c712415fff08214aa9f4e3b493a45782d2))
* **web:** label an editor result with the decision that released it ([#56](https://github.com/ridi-oss/proxy-monster/issues/56)) ([0d906c7](https://github.com/ridi-oss/proxy-monster/commit/0d906c7c1726959d7406769268a6baaf86d4c7cc))
* **web:** show the role's name, not its id, in the approval role picker ([#58](https://github.com/ridi-oss/proxy-monster/issues/58)) ([2df4294](https://github.com/ridi-oss/proxy-monster/commit/2df42944c133eee669eaf0f8ac30ffd828b55908))

## [0.1.3](https://github.com/ridi-oss/proxy-monster/compare/server-v0.1.2...server-v0.1.3) (2026-07-31)


### Features

* **cp:** let a debug login simulate the source address it decides under ([#54](https://github.com/ridi-oss/proxy-monster/issues/54)) ([3e5f374](https://github.com/ridi-oss/proxy-monster/commit/3e5f3742fdfb7787d179de5983b4d2cea2a6e154))

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
