# Changelog

## [0.1.8](https://github.com/ridi-oss/proxy-monster/compare/pmon-v0.1.7...pmon-v0.1.8) (2026-10-07)


### Features

* end a pmon login on the server at logout and at re-login ([91c14d8](https://github.com/ridi-oss/proxy-monster/commit/91c14d8a5a756ac2832e261ecb58085339e7eaad))
* get_pmon_guide and the connect page's pmon block ([3057674](https://github.com/ridi-oss/proxy-monster/commit/3057674dde6cef4231f277511ba7cf19a948e400))
* **pmon:** `pmon login --scopes` and granted scopes in `pmon status` ([2a8b467](https://github.com/ridi-oss/proxy-monster/commit/2a8b4676963aba7730e9f885f96894bd1b8202f2))
* **pmon:** `pmon mcp`, a stdio MCP bridge over the pmon login ([ec17a79](https://github.com/ridi-oss/proxy-monster/commit/ec17a798a3bb874865704aa9e33cf9db46b12aa6))
* **tray:** a menu per server, every copy format, state icons, native notifications ([2a7cb3f](https://github.com/ridi-oss/proxy-monster/commit/2a7cb3f1a7b5e9f38ecff9a70d5f84575de1a2f9))
* **tray:** a Settings window for servers, AI apps and login ([8dbc837](https://github.com/ridi-oss/proxy-monster/commit/8dbc837b1225e7925ebc90f12f8515cc783c42bf))
* **tray:** connect Claude Desktop, Claude Code and Codex to a server ([460db91](https://github.com/ridi-oss/proxy-monster/commit/460db91fa16edd79dafb3634f5c7704658f3c653))
* **tray:** English and Korean, with language and theme settings ([bb394d6](https://github.com/ridi-oss/proxy-monster/commit/bb394d659405f2bc5f28dddcfc59d3c840fc552b))
* **tray:** open pmon://connect links from the console ([6f1e5aa](https://github.com/ridi-oss/proxy-monster/commit/6f1e5aa26048d0d1e2e00d37036b5bd10ea564d3))


### Bug Fixes

* **pmon:** say when the daemon or the server is older than pmon mcp ([37da5a5](https://github.com/ridi-oss/proxy-monster/commit/37da5a5e001fa8914f1a84a2ba993faa16b68842))
* **tray:** name local builds after the pmon tag ([cad3037](https://github.com/ridi-oss/proxy-monster/commit/cad303702b84fb0d65d550d94326631ada741fe5))
* **tray:** review fixes for Settings, AI apps, connect links and notices ([2fe5a3c](https://github.com/ridi-oss/proxy-monster/commit/2fe5a3c222889aa07de16ad91539496260a93bf4))


### Refactoring

* **pmon:** move the CLI and other pmon-only packages under internal/ ([4e82d86](https://github.com/ridi-oss/proxy-monster/commit/4e82d86ca2e51a6221f20be3bc911f629ce459b8))
* **pmon:** move the menu-bar app into pmon/tray ([427357f](https://github.com/ridi-oss/proxy-monster/commit/427357f8003b62c65be6d998ea7337c6185aef1f))

## [0.1.7](https://github.com/ridi-oss/proxy-monster/compare/pmon-v0.1.6...pmon-v0.1.7) (2026-10-01)


### Features

* **pmon:** broker a local Athena endpoint ([120228e](https://github.com/ridi-oss/proxy-monster/commit/120228eb1fff45477f5eedd01915f318693e4d85))
* **pmon:** format Athena client configuration with local SigV4 credentials ([9f75ae6](https://github.com/ridi-oss/proxy-monster/commit/9f75ae6ff30ef499b110a79594f05f1539dcf748))

## [0.1.6](https://github.com/ridi-oss/proxy-monster/compare/pmon-v0.1.5...pmon-v0.1.6) (2026-09-30)


### ⚠ BREAKING CHANGES

* **pmon:** require a control-plane URL on the first login

### Features

* **pmon:** add server commands and a server argument to the CLI ([145c0c3](https://github.com/ridi-oss/proxy-monster/commit/145c0c38b46c37ae92bea33aa17f32869c9a5f5d))
* **pmon:** broker PostgreSQL connections ([d9303df](https://github.com/ridi-oss/proxy-monster/commit/d9303df11e8d4101d0e1368a860ae532a6f0fd23))
* **pmon:** keep a named set of servers in the daemon ([b80935a](https://github.com/ridi-oss/proxy-monster/commit/b80935a9fbaee28d392d3a973ec3dede0f929022))
* **pmon:** render PostgreSQL connection strings ([3127ea8](https://github.com/ridi-oss/proxy-monster/commit/3127ea8657478376070431d1a44a3b0a677dacb2))
* **pmon:** require a control-plane URL on the first login ([755dc55](https://github.com/ridi-oss/proxy-monster/commit/755dc550e1892a586a26f07f7ec5b11db434f9d7))
* **pmontray:** show every server's datasources ([94117b6](https://github.com/ridi-oss/proxy-monster/commit/94117b6d92a5296fdf5a342c6c862a55eed2405f))


### Bug Fixes

* **pmon:** refuse to act on a daemon from before multi-server support ([c7168ca](https://github.com/ridi-oss/proxy-monster/commit/c7168caabc949b0970c55d70a5102be76d0c82b1))
* **pmon:** stabilize daemon control sockets ([#262](https://github.com/ridi-oss/proxy-monster/issues/262)) ([be370d3](https://github.com/ridi-oss/proxy-monster/commit/be370d346fe4cc5cbd6acf4149890145651f4195))
* **pmon:** use moby/moby HostConfig in client interop test ([#281](https://github.com/ridi-oss/proxy-monster/issues/281)) ([b1de20a](https://github.com/ridi-oss/proxy-monster/commit/b1de20a7e4a9949abc25429d22f26a83cd7a7f95))


### Refactoring

* **pmon:** declare provider connection formats and carry connection metadata ([3dcc427](https://github.com/ridi-oss/proxy-monster/commit/3dcc4270e4b97a1e10743fb13cac6c79b77779ee))
* **pmon:** format connection strings through a provider registry ([83092bb](https://github.com/ridi-oss/proxy-monster/commit/83092bbed49d63ed2b00b0b6b3f09573557451f2))
* **pmon:** serve local listeners through the provider ([2622810](https://github.com/ridi-oss/proxy-monster/commit/2622810f17c81820f970512b0dd5f349863614ee))


### Build & Dependencies

* **deps:** bump github.com/docker/docker in /pmon ([#216](https://github.com/ridi-oss/proxy-monster/issues/216)) ([ee1babd](https://github.com/ridi-oss/proxy-monster/commit/ee1babd8d3487fda7eaf7ba99d8c37c3a1d29823))
* **deps:** bump the go group across 4 directories with 8 updates ([#256](https://github.com/ridi-oss/proxy-monster/issues/256)) ([d431547](https://github.com/ridi-oss/proxy-monster/commit/d431547ff28646ad24ec82226b8387510ba3ce5a))


### Chores

* cut server 0.1.21 for the [#202](https://github.com/ridi-oss/proxy-monster/issues/202) revert ([#230](https://github.com/ridi-oss/proxy-monster/issues/230)) ([5001b8c](https://github.com/ridi-oss/proxy-monster/commit/5001b8ccd91a3a9f9ef47f5fc6efe50f0a86f715))
* **pmon:** release pmon 0.1.6 ([74e74b8](https://github.com/ridi-oss/proxy-monster/commit/74e74b819050f5a44ca07f7c0198af9be6f9cb9e))

## [0.1.5](https://github.com/ridi-oss/proxy-monster/compare/pmon-v0.1.4...pmon-v0.1.5) (2026-08-20)


### Build & Dependencies

* bump mysqlwire to v0.1.4 in goproxy and pmon ([#220](https://github.com/ridi-oss/proxy-monster/issues/220)) ([d45f214](https://github.com/ridi-oss/proxy-monster/commit/d45f214010ac98df0ae9b4ae8e27ce23fe8dc6f9))

## [0.1.4](https://github.com/ridi-oss/proxy-monster/compare/pmon-v0.1.3...pmon-v0.1.4) (2026-08-13)


### Features

* **pmon:** add JDBC truncation diagnostics opt-in ([#129](https://github.com/ridi-oss/proxy-monster/issues/129)) ([6160315](https://github.com/ridi-oss/proxy-monster/commit/61603152491aa1babc5cea80b72f6690bb06f292))


### Build & Dependencies

* **deps:** bump mysqlwire to v0.1.3 in goproxy and pmon ([#196](https://github.com/ridi-oss/proxy-monster/issues/196)) ([54d0491](https://github.com/ridi-oss/proxy-monster/commit/54d049160706fd8c99683aa5caa97c4d29b76e44))
* **deps:** bump the go group across 4 directories with 14 updates ([#181](https://github.com/ridi-oss/proxy-monster/issues/181)) ([47f3f3c](https://github.com/ridi-oss/proxy-monster/commit/47f3f3c57c7d2ceba31e201c3e2e7187ea28015f))

## [0.1.3](https://github.com/ridi-oss/proxy-monster/compare/pmon-v0.1.2...pmon-v0.1.3) (2026-08-05)


### Bug Fixes

* **pmon:** advertise CONNECT_WITH_DB so JDBC/DBeaver clients connect ([4f08d55](https://github.com/ridi-oss/proxy-monster/commit/4f08d556e76e037d1e81ac94fdae6003fb757a7b))


### Build & Dependencies

* **pmon:** pin mysqlwire v0.1.2 for the auth-scramble fix ([#110](https://github.com/ridi-oss/proxy-monster/issues/110)) ([bc9f265](https://github.com/ridi-oss/proxy-monster/commit/bc9f265254d1a125b8a93a5908492fde2c0e5301))

## [0.1.2](https://github.com/ridi-oss/proxy-monster/compare/pmon-v0.1.1...pmon-v0.1.2) (2026-08-03)


### Features

* **pmon:** check the local password before brokering a connection ([#67](https://github.com/ridi-oss/proxy-monster/issues/67)) ([87d3156](https://github.com/ridi-oss/proxy-monster/commit/87d3156f2cb73d86cb64b99c7ffbaa99c962a8e0))


### Bug Fixes

* **pmon:** open the browser from the CLI, and surface a daemon that is not this build ([#70](https://github.com/ridi-oss/proxy-monster/issues/70)) ([17ac5bb](https://github.com/ridi-oss/proxy-monster/commit/17ac5bb590f83fc2691131e16dbb052e9d632880))


### Build & Dependencies

* require mysqlwire v0.1.1 ([#80](https://github.com/ridi-oss/proxy-monster/issues/80)) ([e64bebf](https://github.com/ridi-oss/proxy-monster/commit/e64bebf4c89e5e44ec6d76ade8b2c104a585a85c))

## [0.1.1](https://github.com/ridi-oss/proxy-monster/compare/pmon-v0.1.0...pmon-v0.1.1) (2026-07-31)


### Build & Dependencies

* move the Go toolchain to 1.26 ([f4f62e1](https://github.com/ridi-oss/proxy-monster/commit/f4f62e1196f76367aa08bf41608f5a6080557da5))


### Documentation

* **pmon:** install from the Homebrew tap ([#38](https://github.com/ridi-oss/proxy-monster/issues/38)) ([8d99938](https://github.com/ridi-oss/proxy-monster/commit/8d9993832a0e80bf81a2072e7413d8269abb94e1))

## 0.1.0 (2026-07-30)


### Build & Dependencies

* **deps:** depend on the published mysqlwire, not the sibling directory ([#11](https://github.com/ridi-oss/proxy-monster/issues/11)) ([63c9603](https://github.com/ridi-oss/proxy-monster/commit/63c9603ff28a6224102ed3923430b3f18a101f3f))
* release trains for the server, the client, and mysqlwire ([#12](https://github.com/ridi-oss/proxy-monster/issues/12)) ([f6c95f1](https://github.com/ridi-oss/proxy-monster/commit/f6c95f120685e052c576465c8e9ec00d4d5ce0be))
