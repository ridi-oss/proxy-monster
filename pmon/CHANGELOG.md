# Changelog

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
