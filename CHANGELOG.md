# Changelog

## [0.1.12](https://github.com/ridi-oss/proxy-monster/compare/server-v0.1.11...server-v0.1.12) (2026-08-11)


### Features

* **control-plane:** notification foundations (Cedar satisfiability + message catalog) ([#152](https://github.com/ridi-oss/proxy-monster/issues/152)) ([98a5d8c](https://github.com/ridi-oss/proxy-monster/commit/98a5d8c8ea48536d141c5ea1013742f342982b61))
* **control-plane:** re-home the console on shutdown via an SSE drain ([#149](https://github.com/ridi-oss/proxy-monster/issues/149)) ([a1e817f](https://github.com/ridi-oss/proxy-monster/commit/a1e817f34d6722c0a1b893f969e431c071108e1c))
* **control-plane:** the task-notification outbox and model ([#156](https://github.com/ridi-oss/proxy-monster/issues/156)) ([84d63d1](https://github.com/ridi-oss/proxy-monster/commit/84d63d1dada0352141fd7714fe48c4760d7e1a2a))
* **control-plane:** version-gate the Events stream, not just Register ([#164](https://github.com/ridi-oss/proxy-monster/issues/164)) ([8627c1f](https://github.com/ridi-oss/proxy-monster/commit/8627c1ff1b57d6eb1de34ec7a3e49574fe94cdcd)), closes [#158](https://github.com/ridi-oss/proxy-monster/issues/158)
* editor queries survive a proxy redeploy — drain in-flight + fail a cut/stalled run fast ([#160](https://github.com/ridi-oss/proxy-monster/issues/160)) ([a1054d2](https://github.com/ridi-oss/proxy-monster/commit/a1054d2f2792f46258fec6d8f5620668e3fdddb9))
* gate every statement by category (control-plane + console) ([#136](https://github.com/ridi-oss/proxy-monster/issues/136)) ([f2aaa3a](https://github.com/ridi-oss/proxy-monster/commit/f2aaa3a506f855ab646d6d149245d5e49bd0c80e))
* **goproxy:** abort the target-DB open when a run is closed or drained during it ([#162](https://github.com/ridi-oss/proxy-monster/issues/162)) ([9870599](https://github.com/ridi-oss/proxy-monster/commit/9870599e147f1a935890540c3af45ea2ad5a2ea2)), closes [#159](https://github.com/ridi-oss/proxy-monster/issues/159)
* **goproxy:** graceful drain of client connections on shutdown ([#148](https://github.com/ridi-oss/proxy-monster/issues/148)) ([a7addc4](https://github.com/ridi-oss/proxy-monster/commit/a7addc42f022d86a5b9f673943d89134f18c2468))
* Slack task-approval notifications (service → transport → wire → language) ([#155](https://github.com/ridi-oss/proxy-monster/issues/155)) ([cfca3b3](https://github.com/ridi-oss/proxy-monster/commit/cfca3b352d5cf7d789108724d15fa38db3253765))


### Bug Fixes

* **control-plane:** reject a missing proxy secret in production (GHSA-52x6-28h6-9pjw) ([#167](https://github.com/ridi-oss/proxy-monster/issues/167)) ([39ceb99](https://github.com/ridi-oss/proxy-monster/commit/39ceb99e27bd2b54700384bfad35a06220613e34))


### Refactoring

* **goproxy:** extract the shared wire-server core, dedup the MySQL/PostgreSQL brokers ([#151](https://github.com/ridi-oss/proxy-monster/issues/151)) ([24d1df2](https://github.com/ridi-oss/proxy-monster/commit/24d1df24d582e8d6d950ca1482392aaf6bb5bfba))
* rename the "backend" target-DB vocabulary to target-DB ([#165](https://github.com/ridi-oss/proxy-monster/issues/165)) ([690953c](https://github.com/ridi-oss/proxy-monster/commit/690953cac6fc0463c96750bb646d356d916d9a8c))

## [0.1.11](https://github.com/ridi-oss/proxy-monster/compare/server-v0.1.10...server-v0.1.11) (2026-08-07)


### Bug Fixes

* **goproxy:** repin sqlglot-go to v0.23.0 to match analyzer ([#144](https://github.com/ridi-oss/proxy-monster/issues/144)) ([fbdc8ce](https://github.com/ridi-oss/proxy-monster/commit/fbdc8cead1a4b25ab8cd85584063362a70940809))

## [0.1.10](https://github.com/ridi-oss/proxy-monster/compare/server-v0.1.9...server-v0.1.10) (2026-08-07)


### Features

* **analyzer:** classify every statement into a StatementKind ([#138](https://github.com/ridi-oss/proxy-monster/issues/138)) ([0821b87](https://github.com/ridi-oss/proxy-monster/commit/0821b878ddfb5056508a29ee170d4136160a40ef))
* **control-plane:** graceful drain of proxy Events streams on shutdown ([#140](https://github.com/ridi-oss/proxy-monster/issues/140)) ([9e7a73d](https://github.com/ridi-oss/proxy-monster/commit/9e7a73d20d8c75794ccda812efc56c5b33cf62e8))


### Bug Fixes

* **control-plane:** soft-delete Cedar policies ([#137](https://github.com/ridi-oss/proxy-monster/issues/137)) ([c4f8658](https://github.com/ridi-oss/proxy-monster/commit/c4f86589e9d027d9055125b7a033e7d7998b0bd2))
* **control-plane:** soft-delete groups ([#132](https://github.com/ridi-oss/proxy-monster/issues/132)) ([3368968](https://github.com/ridi-oss/proxy-monster/commit/3368968fe8d4be286e57171d6d3cc0c6d3d5e2c6))
* **web:** return to the intended page after login ([#133](https://github.com/ridi-oss/proxy-monster/issues/133)) ([e25ec4a](https://github.com/ridi-oss/proxy-monster/commit/e25ec4a7e85323842754c2b477a87478ec9b68b7))

## [0.1.9](https://github.com/ridi-oss/proxy-monster/compare/server-v0.1.8...server-v0.1.9) (2026-08-06)


### Features

* **auditmon:** detect off-hours admin changes and auth-failure bursts ([#126](https://github.com/ridi-oss/proxy-monster/issues/126)) ([d225cab](https://github.com/ridi-oss/proxy-monster/commit/d225cabe7518609ee5e091a8ba6517b281b41588))
* **auditmon:** render Slack alerts as Block Kit with per-decision console links ([#124](https://github.com/ridi-oss/proxy-monster/issues/124)) ([70096f3](https://github.com/ridi-oss/proxy-monster/commit/70096f32227ff41db4a3c190385c8c5945cbf0c8))
* carry the client address on ValidateToken for wire-rejection audits ([#125](https://github.com/ridi-oss/proxy-monster/issues/125)) ([37f3d71](https://github.com/ridi-oss/proxy-monster/commit/37f3d71e450104974b39af67fe1d8214c85d9d73))
* **control-plane:** audit authentication and session events ([#116](https://github.com/ridi-oss/proxy-monster/issues/116)) ([728682d](https://github.com/ridi-oss/proxy-monster/commit/728682d105909fe517d3ba9ed088f1d2aee2182c))
* **control-plane:** audit JIT elevation and approval decisions ([#121](https://github.com/ridi-oss/proxy-monster/issues/121)) ([4a1cf15](https://github.com/ridi-oss/proxy-monster/commit/4a1cf15b7a783db11cc62593558383e21bdcc592))
* **control-plane:** audit SCIM provisioning events ([#123](https://github.com/ridi-oss/proxy-monster/issues/123)) ([60d78f7](https://github.com/ridi-oss/proxy-monster/commit/60d78f702c8fb85f2b7a973eeb589efc3b1feafe))


### Bug Fixes

* **auth:** authenticate before device confirmation ([#122](https://github.com/ridi-oss/proxy-monster/issues/122)) ([2a12760](https://github.com/ridi-oss/proxy-monster/commit/2a12760d397742b79fead50e36b81b1968cdc16b))
* **control-plane:** soft-delete datasources instead of a blocked hard delete ([#120](https://github.com/ridi-oss/proxy-monster/issues/120)) ([f4f1118](https://github.com/ridi-oss/proxy-monster/commit/f4f1118aac1a8e7742fe2e4d25d7c7f64cf124ae))
* **control-plane:** soft-delete roles and mask functions ([#127](https://github.com/ridi-oss/proxy-monster/issues/127)) ([b175483](https://github.com/ridi-oss/proxy-monster/commit/b175483f9ba7f4791aa202a7526fa63fc536eced))
* **web:** hide debug login until config loads ([#118](https://github.com/ridi-oss/proxy-monster/issues/118)) ([fd2b72a](https://github.com/ridi-oss/proxy-monster/commit/fd2b72a32fd09fd5d19f6f64c4df9bc6dab42cac))

## [0.1.8](https://github.com/ridi-oss/proxy-monster/compare/server-v0.1.7...server-v0.1.8) (2026-08-05)


### Features

* **control-plane:** audit config-change admin actions ([#115](https://github.com/ridi-oss/proxy-monster/issues/115)) ([2f259f9](https://github.com/ridi-oss/proxy-monster/commit/2f259f94d02b7870f0d7bcf4bd204d64a5eb5149))


### Bug Fixes

* **control-plane:** view an authorized passthrough result instead of denying it ([#112](https://github.com/ridi-oss/proxy-monster/issues/112)) ([fd467e7](https://github.com/ridi-oss/proxy-monster/commit/fd467e7608c01b16e652a04255bc2c26aea326a1))

## [0.1.7](https://github.com/ridi-oss/proxy-monster/compare/server-v0.1.6...server-v0.1.7) (2026-08-05)


### Features

* **analyzer:** resolve catalog-changing DDL, gated by sql.ddl ([f8abb46](https://github.com/ridi-oss/proxy-monster/commit/f8abb46ac6df68a9e843046f4887bb654918dae6))
* **web:** show each Cedar policy's source, collapsed behind a row toggle ([#86](https://github.com/ridi-oss/proxy-monster/issues/86)) ([168684a](https://github.com/ridi-oss/proxy-monster/commit/168684a4fbdf7045860fe1b6d0f39ab4ce4e93ff))


### Bug Fixes

* **analyzer:** adopt sqlglot-go v0.21.0 + harden the MySQL statement-coverage audit ([#89](https://github.com/ridi-oss/proxy-monster/issues/89)) ([9b8b02b](https://github.com/ridi-oss/proxy-monster/commit/9b8b02baf80affb4bed8d166882f9c0cb303d071))
* **analyzer:** pin character_set_results = NULL to utf8mb4 for JDBC clients ([#94](https://github.com/ridi-oss/proxy-monster/issues/94)) ([6dcf0b5](https://github.com/ridi-oss/proxy-monster/commit/6dcf0b50d418325fe2539ccad40f03b95874dfec)), closes [#81](https://github.com/ridi-oss/proxy-monster/issues/81)
* **control-plane:** a tag is a tag ([#78](https://github.com/ridi-oss/proxy-monster/issues/78)) ([61cf6fd](https://github.com/ridi-oss/proxy-monster/commit/61cf6fd9ab1845e71c404dbad0eed559278cc9fa))
* **cp:** reprint the seeded Cedar policy source ([#84](https://github.com/ridi-oss/proxy-monster/issues/84)) ([27cab70](https://github.com/ridi-oss/proxy-monster/commit/27cab70579989e34c30c15c6d15df399ad6ef8ba))
* **goproxy:** pin mysqlwire v0.1.2 so the release image builds ([#111](https://github.com/ridi-oss/proxy-monster/issues/111)) ([c90a87e](https://github.com/ridi-oss/proxy-monster/commit/c90a87e5a3a7a4281d2bf7e5e1b6e8600aea5801))
* **goproxy:** use the shared printable scramble for the frontend greeting ([5f307b3](https://github.com/ridi-oss/proxy-monster/commit/5f307b3f3ef877d790cd0224af6cce0d149e4503))


### Build & Dependencies

* **analyzer:** adopt sqlglot-go v0.22.0 ([#97](https://github.com/ridi-oss/proxy-monster/issues/97)) ([82f2d66](https://github.com/ridi-oss/proxy-monster/commit/82f2d66a0cd4782014da0efd850f436fb23a72b8))
* **proto:** pin Go protobuf generators ([#102](https://github.com/ridi-oss/proxy-monster/issues/102)) ([7cf31d4](https://github.com/ridi-oss/proxy-monster/commit/7cf31d4806318341a6aca40b11f91f1bdae76ef4))


### Documentation

* add statement-classification design proposal ([#96](https://github.com/ridi-oss/proxy-monster/issues/96)) ([ed29774](https://github.com/ridi-oss/proxy-monster/commit/ed297742473d196ae23d9f4067b9002a42bdab27))

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
