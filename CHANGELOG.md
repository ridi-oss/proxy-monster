# Changelog

## [0.1.29](https://github.com/ridi-oss/proxy-monster/compare/server-v0.1.28...server-v0.1.29) (2026-10-04)


### Features

* **control-plane:** flag system-schema columns in the catalog browse ([d09d4df](https://github.com/ridi-oss/proxy-monster/commit/d09d4df307a4a5522e3274a6d19192ea5b2124b9))
* **editor:** report and set each editor session's namespace ([2c3430f](https://github.com/ridi-oss/proxy-monster/commit/2c3430f2776af529d529dd9b7dd13f33f6e8ad06))
* **web:** a column in the tree opens its table on the column, flashed ([b806d8c](https://github.com/ridi-oss/proxy-monster/commit/b806d8cddc8571683bc28159aba7739e2e4216b1))
* **web:** mark the session's search path in the schema tree and switch it ([e339ce7](https://github.com/ridi-oss/proxy-monster/commit/e339ce75b69f205edf05abee0d28baf7b5f157d5))
* **web:** name tree objects as SQL writes them ([84cfe44](https://github.com/ridi-oss/proxy-monster/commit/84cfe444a238d2fde92763a37ac7d374938322ff))
* **web:** rebuild the editor's schema explorer as a tree ([1d9afbf](https://github.com/ridi-oss/proxy-monster/commit/1d9afbf175764fed5f0546ed495d0df9ab32b544))
* **web:** show the datasource catalog's tables in the schema tree ([08f9d90](https://github.com/ridi-oss/proxy-monster/commit/08f9d90b58d179b65f730a46e32001ea903567bb))


### Bug Fixes

* **classification:** open PostgreSQL current_setting like SHOW &lt;guc&gt; ([e94bade](https://github.com/ridi-oss/proxy-monster/commit/e94bade9f3766479a4c93e7c93ce21ed22cf55f1))
* **mcp:** return the target DB error text from a failed run_query ([a9bdfd8](https://github.com/ridi-oss/proxy-monster/commit/a9bdfd8fa04cfbcac4144687103dfef0b35d5a84))
* **web:** clip long column types in the datasource catalog ([34269f4](https://github.com/ridi-oss/proxy-monster/commit/34269f4de70735b55ce99c1a0e328e8ddf52d837))
* **web:** keep the editor's datasource when navigating back to it ([0b14c40](https://github.com/ridi-oss/proxy-monster/commit/0b14c40647506dc1bd31fcdd33c76320b8a329d5))


### Refactoring

* **mcp:** serve tool descriptions in English only ([c856a8d](https://github.com/ridi-oss/proxy-monster/commit/c856a8d2cba066b2802665542757985d8c3310ca))


### Build & Dependencies

* **release:** fence the empty Release-As commit out of every train ([6dfe10f](https://github.com/ridi-oss/proxy-monster/commit/6dfe10fe32c9f1e6e5e7bac409fd5b93447b0341))

## [0.1.28](https://github.com/ridi-oss/proxy-monster/compare/server-v0.1.27...server-v0.1.28) (2026-10-01)


### Features

* **analyzer:** add the Athena engine and SQL submission ([7cfcf7d](https://github.com/ridi-oss/proxy-monster/commit/7cfcf7d698e7d0f87e9be9f32178da939df0887e))
* **analyzer:** emit catalog-qualified namespace candidates ([551f2eb](https://github.com/ridi-oss/proxy-monster/commit/551f2ebb9977195e64c234424e091e0b5fe69bb3))
* **analyzer:** resolve function calls against the catalog and fail closed ([7c19aeb](https://github.com/ridi-oss/proxy-monster/commit/7c19aeb13424adfbde126cfb6641cf64d38ec75e))
* **analyzer:** resolve PostgreSQL system columns as implicit catalog columns ([c171dcf](https://github.com/ridi-oss/proxy-monster/commit/c171dcfdca7eef72e9d1545df113b1eabf505040))
* authorize a metadata request without a SQL session ([cf5f9bd](https://github.com/ridi-oss/proxy-monster/commit/cf5f9bd998d5f1aec06e376874749fbbf562f13e))
* **catalog:** carry routines in the schema fragment ([e6a2db6](https://github.com/ridi-oss/proxy-monster/commit/e6a2db6036a1efcd160b0e71dd13eef1274763b3))
* **control-plane:** authorize provider-native requests with instructions ([a2fa18f](https://github.com/ridi-oss/proxy-monster/commit/a2fa18fb51fe4265211573741b4619925bfbd164))
* **control-plane:** count a rate per datasource ([b792be6](https://github.com/ridi-oss/proxy-monster/commit/b792be64c2094b3b06abb8b4c928e00c0676d2a2))
* **control-plane:** forward the function catalog ([9ad23c6](https://github.com/ridi-oss/proxy-monster/commit/9ad23c6601bb1c114f088634450b9e94c45e3c66))
* **control-plane:** GET /api/mcp/connect for the connect page ([8d653b9](https://github.com/ridi-oss/proxy-monster/commit/8d653b92c8850a794c92d7f4f3c0361112472ab9))
* **control-plane:** key the catalog by (catalog, schema), not schema alone ([0e93a9c](https://github.com/ridi-oss/proxy-monster/commit/0e93a9c8926d45bd453d97f429598b111eb4ff0b))
* **control-plane:** MCP access-request, grant, audit, history and self tools ([e2a849b](https://github.com/ridi-oss/proxy-monster/commit/e2a849b276ab2e75212d137c990241624968f17d))
* **control-plane:** MCP admin tools for groups, rates and datasources ([850974f](https://github.com/ridi-oss/proxy-monster/commit/850974fa72d9adce22c7806e144951e7e8887f06))
* **control-plane:** MCP initialize instructions name the instance ([7c45b4d](https://github.com/ridi-oss/proxy-monster/commit/7c45b4d51214e0a840daa429bb040220876474a2))
* **control-plane:** MCP query and approval tools ([fcfff3d](https://github.com/ridi-oss/proxy-monster/commit/fcfff3d9a2d9867cd7fa2e118012c4e54258e45d))
* **control-plane:** MCP token tools and the mcp:tokens scope ([91afbc1](https://github.com/ridi-oss/proxy-monster/commit/91afbc1d046ddeadf18cbd1ef0b3fd5adbb2c332))
* **control-plane:** page stored result views ([b832a5e](https://github.com/ridi-oss/proxy-monster/commit/b832a5e4d62e78a15fb02f079296f11a650408a7))
* **control-plane:** PM_INSTANCE_NAME and PM_INSTANCE_DESCRIPTION ([b0904cc](https://github.com/ridi-oss/proxy-monster/commit/b0904cc1019bc4db91180026e4ea44b4b6afcc50))
* **control-plane:** refresh the config catalog after DDL ([c10166f](https://github.com/ridi-oss/proxy-monster/commit/c10166fb4cc225096bf21485454b58a1d059dfce))
* **control-plane:** register the Athena engine and its request authorizer ([2d7dea2](https://github.com/ridi-oss/proxy-monster/commit/2d7dea2292830e6c384ce5c56e7e6e687e3c0c40))
* **control-plane:** report the server release as the MCP server version ([a5be660](https://github.com/ridi-oss/proxy-monster/commit/a5be66059e7388e502c7594635bb1c1d8905454f))
* decide Athena SQL through the control plane ([62c8c4e](https://github.com/ridi-oss/proxy-monster/commit/62c8c4e5c04eb3b76159d9c380c6383b33c7b876))
* **goproxy:** add the Athena enforcement-context cache ([5273f6a](https://github.com/ridi-oss/proxy-monster/commit/5273f6ab2ba1951cf8974f3dfea52e5857821d6e))
* **goproxy:** add the Athena JSON envelope, forwarder, and result masking ([7aa0728](https://github.com/ridi-oss/proxy-monster/commit/7aa0728acf56bb23a0c7259eada0199c0b3925f1))
* **goproxy:** carry the connection's catalog through every catalog fact ([a83b04f](https://github.com/ridi-oss/proxy-monster/commit/a83b04f28b9d0931fa365872aecf49f559b2b09d))
* **goproxy:** configure an Athena target and read its catalog ([9e1e555](https://github.com/ridi-oss/proxy-monster/commit/9e1e555421c1109d12b2c13320abf2dd2755fbdd))
* **goproxy:** decide and submit Athena SQL, natively and from the editor ([fbd9caa](https://github.com/ridi-oss/proxy-monster/commit/fbd9caaa2b9728df1ccdd1b4bdfa4298fb1e2838))
* **goproxy:** serve the Athena API through the forwarding provider ([6035769](https://github.com/ridi-oss/proxy-monster/commit/6035769fb17e975ef578596f6f774b945e705abb))
* **goproxy:** TLS to the target DB ([dcc71cd](https://github.com/ridi-oss/proxy-monster/commit/dcc71cd247b0cbfb63c737dae88704ec21580321))
* let a proxy publish nonsecret connection metadata at Register ([c59a78e](https://github.com/ridi-oss/proxy-monster/commit/c59a78e1a5e4e1f988328f9a8f7007e90e003a98))
* PM_DATASOURCE_DESCRIPTION reaches the control plane ([9666832](https://github.com/ridi-oss/proxy-monster/commit/9666832d517c3d67a3f397e315a281de77d0955e))
* **pmon:** add server commands and a server argument to the CLI ([145c0c3](https://github.com/ridi-oss/proxy-monster/commit/145c0c38b46c37ae92bea33aa17f32869c9a5f5d))
* **pmon:** broker PostgreSQL connections ([d9303df](https://github.com/ridi-oss/proxy-monster/commit/d9303df11e8d4101d0e1368a860ae532a6f0fd23))
* require the catalog on every catalog fact on the wire ([590cdc0](https://github.com/ridi-oss/proxy-monster/commit/590cdc0a6eb40924642f3cbc93b7e2dea22d57b9))
* **smoke:** drive the console in a real browser ([34b3e09](https://github.com/ridi-oss/proxy-monster/commit/34b3e09294656d4280b3ce0f6c9627a34bc9ca5b))
* **smoke:** end-to-end smoke harness (mise run smoke) ([b2c826a](https://github.com/ridi-oss/proxy-monster/commit/b2c826ac3c57da483423349e08faf84acd5df1c8))
* **web:** Connect an agent page ([ce66763](https://github.com/ridi-oss/proxy-monster/commit/ce66763c1e35e1989e326a129a86f734af688a9f))
* **web:** show the catalog on every table identity ([df1ea16](https://github.com/ridi-oss/proxy-monster/commit/df1ea168c26d50376c9146016380543babde27f3))


### Bug Fixes

* **control-plane:** never save a result without its execution decision ([1208f8a](https://github.com/ridi-oss/proxy-monster/commit/1208f8a438de1276e84a10c187429227c4e99204))
* **control-plane:** refuse an approval result view with no execution decision to charge ([3b8170c](https://github.com/ridi-oss/proxy-monster/commit/3b8170c5303ddbff392f1046b8f5645ba790163d))
* **control-plane:** view an editor result against its open session's catalog ([6de3c40](https://github.com/ridi-oss/proxy-monster/commit/6de3c40fc2ac9aecc9265991842e029a85eb4e1c))
* **postgres:** classify exact system columns ([d86bb42](https://github.com/ridi-oss/proxy-monster/commit/d86bb42f1fef1f04626fb63654077211daf90fb6))
* **postgres:** redact catalog option columns ([fb02adb](https://github.com/ridi-oss/proxy-monster/commit/fb02adb43f2ba2e78f18b813d48de92d59b8ee43))
* **postgres:** trust an xid cast only when it resolves to pg_catalog.xid ([e076747](https://github.com/ridi-oss/proxy-monster/commit/e0767474ec6eee95254734311caa4b8b62a43da5))
* **smoke:** send the required catalog on the seed classification ([48297c2](https://github.com/ridi-oss/proxy-monster/commit/48297c271e165def74e5ec96c2abb905c9b58035))


### Refactoring

* **analyzer:** let an engine own its namespace and catalog rules ([1f1c814](https://github.com/ridi-oss/proxy-monster/commit/1f1c8144460e51a0d061be44f47f1124adfcbfec))
* **control-plane:** describe each engine in one EngineDefinition ([dd40e69](https://github.com/ridi-oss/proxy-monster/commit/dd40e693ff2de56de48ab71f1f1e07cd000aa243))
* **control-plane:** extract AccessService ([b143bae](https://github.com/ridi-oss/proxy-monster/commit/b143baed27c477c52f2c31e8679b863e6d3e4697))
* **control-plane:** extract ApprovalService from the approval routes ([de450a6](https://github.com/ridi-oss/proxy-monster/commit/de450a6fa431fc0cc28378705b50d3f628c097a3))
* **control-plane:** extract AuditService ([286f89c](https://github.com/ridi-oss/proxy-monster/commit/286f89cb068759f3cbba32e50d5e65b8d1e98287))
* **control-plane:** extract EditorTaskService from the editor routes ([ae75ce4](https://github.com/ridi-oss/proxy-monster/commit/ae75ce42e5c0c59626ece184e886792352488373))
* **control-plane:** extract TokenService ([be29e3f](https://github.com/ridi-oss/proxy-monster/commit/be29e3fed0c3cc98dd9b710c2158480e52f8ccc5))
* **control-plane:** move datasource admin logic into DatasourceManagementService ([daaf614](https://github.com/ridi-oss/proxy-monster/commit/daaf6140d6c74d0003545e1c4e8696ccddbe4d0a))
* **goproxy:** a Provider opens a Db that owns its target ([ae984e6](https://github.com/ridi-oss/proxy-monster/commit/ae984e63410a05921c9b8ad3c759c909279d9ae0))
* **goproxy:** QueryEngine decides from callbacks alone, without a Db ([40ffb92](https://github.com/ridi-oss/proxy-monster/commit/40ffb9296c951d99049a3995e5af455ce3dcde04))
* **proto:** name every catalog object with one ObjectRef ([22b3c84](https://github.com/ridi-oss/proxy-monster/commit/22b3c8482efa446f1250db23393628e4c8dc1c31))


### Build & Dependencies

* **analyzer:** adopt sqlglot-go v0.37.2 ([666c998](https://github.com/ridi-oss/proxy-monster/commit/666c998f7ef821852f5d7b757e4d5803a9044fe0))
* **proto:** add catalog identity and metadata authorization to the wire contract ([494063c](https://github.com/ridi-oss/proxy-monster/commit/494063c82306abf5f5794debc41acd2b1a6e0ef5))
* **proto:** add the Athena analyzer contract ([2de3784](https://github.com/ridi-oss/proxy-monster/commit/2de3784fdfb9cb5bcc05a6588908004c76ab72a2))


### Documentation

* **agents:** never force a release with an empty Release-As commit ([d24f7af](https://github.com/ridi-oss/proxy-monster/commit/d24f7af04cd62f2e494c107b2000664e0b37f3b5))
* instance identity, datasource descriptions, and the connect page ([6c5d8f5](https://github.com/ridi-oss/proxy-monster/commit/6c5d8f50906d29bae59a4b14937ff42d93be455c))
* MCP console-parity tools ([cd59232](https://github.com/ridi-oss/proxy-monster/commit/cd592325909f1f56cb9c066f0008c950f9bfb12a))
* MCP query and approval tools ([9846ccb](https://github.com/ridi-oss/proxy-monster/commit/9846ccb37954ca610eeb834d7e6efd829f955125))
* record the Athena limitations and follow-ups ([cae1546](https://github.com/ridi-oss/proxy-monster/commit/cae15462e677389443af96dda3a5e14bf210cdb0))

## [0.1.27](https://github.com/ridi-oss/proxy-monster/compare/server-v0.1.26...server-v0.1.27) (2026-09-18)


### Features

* **web:** file a rate-reset request from the Workflows page ([3b4034e](https://github.com/ridi-oss/proxy-monster/commit/3b4034e9c48e3488407226e5209fc1af12a0fde0))


### Bug Fixes

* **web:** a rate denial's result header offers the reset, not approval or access ([fe91c08](https://github.com/ridi-oss/proxy-monster/commit/fe91c08a23f624d73638996681127178e66024f3))

## [0.1.26](https://github.com/ridi-oss/proxy-monster/compare/server-v0.1.25...server-v0.1.26) (2026-09-16)


### Features

* **analyzer:** emit the columns a statement returns ([92fca9a](https://github.com/ridi-oss/proxy-monster/commit/92fca9afba2f2931f4a940f0acf2571d9ea26064))
* **catalog:** introspect and store the function inventory ([#309](https://github.com/ridi-oss/proxy-monster/issues/309)) ([6dfac30](https://github.com/ridi-oss/proxy-monster/commit/6dfac304b7463c81cd6c57c589c8c02f42eb5c47))
* **control-plane:** a stored result view applies the viewer's own caps ([d0fb77d](https://github.com/ridi-oss/proxy-monster/commit/d0fb77d2ba0624af1a1773c9e218d85f9276f165))
* **control-plane:** deny a read whose [@cap](https://github.com/cap) rate window is spent ([6729a3c](https://github.com/ridi-oss/proxy-monster/commit/6729a3cc549f66c90aa1bc36d7839c23989347e3))
* **control-plane:** reset a principal's spent rate by admin or approval ([e8d6bf0](https://github.com/ridi-oss/proxy-monster/commit/e8d6bf0f7b37f6ed0355f66b22131d51b512e283))
* **goproxy:** observe PostgreSQL function and type visibility at Bind ([#312](https://github.com/ridi-oss/proxy-monster/issues/312)) ([46469aa](https://github.com/ridi-oss/proxy-monster/commit/46469aa4d98d829f637236060a6e626dababdab1))
* **mysqlproxy:** enforce result caps and keep the session ([967353a](https://github.com/ridi-oss/proxy-monster/commit/967353ab1ebccdf8800c2c36630e0405d72850d5))
* **pgproxy:** enforce result caps in both wire protocols ([caa9baa](https://github.com/ridi-oss/proxy-monster/commit/caa9baac05c257edec1230ba09ec37286ee2b9b1))
* **run:** narrow a run to the verdict cap and report the truncation ([3040f8a](https://github.com/ridi-oss/proxy-monster/commit/3040f8a9cff9ad2c93a150936c44ca31d0ab1963))
* verdicts carry the result cap the result.cap policies annotate ([8b72210](https://github.com/ridi-oss/proxy-monster/commit/8b7221016445f28498a752d81325f446dd07641c))
* **web:** label a capped result ([31e8ede](https://github.com/ridi-oss/proxy-monster/commit/31e8ede88ef89d8cd13d18cc431044588f38d099))


### Bug Fixes

* **goproxy:** queue a run query that races the previous statement's completion ([#311](https://github.com/ridi-oss/proxy-monster/issues/311)) ([12a505a](https://github.com/ridi-oss/proxy-monster/commit/12a505a0bd73fb0ccd2dc44958a7b033ed6bf134))


### Refactoring

* **catalog:** store the pushed catalog as one snapshot ([#308](https://github.com/ridi-oss/proxy-monster/issues/308)) ([50c0c87](https://github.com/ridi-oss/proxy-monster/commit/50c0c87b7082fe4ca92e01425c7377b9e9ae41ec))
* **control-plane:** name the datasource column list once ([9bb6e15](https://github.com/ridi-oss/proxy-monster/commit/9bb6e158132341eae65b92bc72774a82d81ff8de))
* **proto:** carry the session observation as one message ([#324](https://github.com/ridi-oss/proxy-monster/issues/324)) ([afb5ab9](https://github.com/ridi-oss/proxy-monster/commit/afb5ab9693e950057457193b5a0917f694fe4c86))
* **proto:** share one Column and CatalogSnapshot across every catalog boundary ([#305](https://github.com/ridi-oss/proxy-monster/issues/305)) ([701b26e](https://github.com/ridi-oss/proxy-monster/commit/701b26e4fddc134d4efe7f106d8322e29b1bf2b1))


### Build & Dependencies

* **proto:** add the shared function-catalog contract ([#307](https://github.com/ridi-oss/proxy-monster/issues/307)) ([be9def3](https://github.com/ridi-oss/proxy-monster/commit/be9def3d9e0f7f0e72d26e791f91cd2a95e2b40f))


### Documentation

* propose Athena API support ([#314](https://github.com/ridi-oss/proxy-monster/issues/314)) ([6b7600a](https://github.com/ridi-oss/proxy-monster/commit/6b7600a0f3362a58a74c42b10122030ebf44da17))
* result caps design ([c201d84](https://github.com/ridi-oss/proxy-monster/commit/c201d8422cb36e596fc6ee0c2cfa5a11e57608aa))

## [0.1.25](https://github.com/ridi-oss/proxy-monster/compare/server-v0.1.24...server-v0.1.25) (2026-09-07)


### Bug Fixes

* **analyzer:** support NATURAL JOIN lineage ([#295](https://github.com/ridi-oss/proxy-monster/issues/295)) ([0b51fc0](https://github.com/ridi-oss/proxy-monster/commit/0b51fc0d31f42f5b6c47594bd7d08d64e5666993))
* **mysqlproxy:** allow MariaDB's default NO_AUTO_CREATE_USER sql_mode flag ([#298](https://github.com/ridi-oss/proxy-monster/issues/298)) ([072c196](https://github.com/ridi-oss/proxy-monster/commit/072c19635318ba8f63fe43304573937cd2bb6a9b)), closes [#297](https://github.com/ridi-oss/proxy-monster/issues/297)

## [0.1.24](https://github.com/ridi-oss/proxy-monster/compare/server-v0.1.23...server-v0.1.24) (2026-09-02)


### Features

* **analyzer:** split a multi-statement batch at statement boundaries ([#278](https://github.com/ridi-oss/proxy-monster/issues/278)) ([ec81e29](https://github.com/ridi-oss/proxy-monster/commit/ec81e2925a014ba244bb043b22721e935d7b74ff))
* **control-plane:** accept a workflow request of several statements ([#287](https://github.com/ridi-oss/proxy-monster/issues/287)) ([4374ebd](https://github.com/ridi-oss/proxy-monster/commit/4374ebd537e95249382273eb8c43c92ee50405c9))
* **control-plane:** run a task's statements in order on one connection ([#286](https://github.com/ridi-oss/proxy-monster/issues/286)) ([c66937a](https://github.com/ridi-oss/proxy-monster/commit/c66937a7543e10eb26422331b430bc4e6de0005d))
* **control-plane:** store a failed query's target-DB diagnostic, encrypted and re-gatable ([#267](https://github.com/ridi-oss/proxy-monster/issues/267)) ([6f24b54](https://github.com/ridi-oss/proxy-monster/commit/6f24b54eaa5d301deff8c9d035adbd9798c43b2e))
* **editor:** run an editor submit's statements as one task, one result tab each ([#294](https://github.com/ridi-oss/proxy-monster/issues/294)) ([7a7d27e](https://github.com/ridi-oss/proxy-monster/commit/7a7d27e6d983ae25676a4166dc7a2d8671376165))
* **web:** review a workflow request statement by statement ([#292](https://github.com/ridi-oss/proxy-monster/issues/292)) ([1c6d302](https://github.com/ridi-oss/proxy-monster/commit/1c6d302d7dac49bd6904f13b04a4b59d0b14ee2e))


### Bug Fixes

* **analyzer:** classify EXPLAIN TABLE as a plan-only EXPLAIN ([#285](https://github.com/ridi-oss/proxy-monster/issues/285)) ([c338b4e](https://github.com/ridi-oss/proxy-monster/commit/c338b4ea81bcdad8ab718571be3090ac0d1af2a6))
* **analyzer:** keep output labels native across rewrites and references ([#273](https://github.com/ridi-oss/proxy-monster/issues/273)) ([0bcb57e](https://github.com/ridi-oss/proxy-monster/commit/0bcb57eea74682c2964728411da2ea6adffa0eb5))
* **analyzer:** trust information_schema helpers and txid_current ([#275](https://github.com/ridi-oss/proxy-monster/issues/275)) ([5bac93c](https://github.com/ridi-oss/proxy-monster/commit/5bac93c0d0f226f7fcb32acb6b0fa6e44801c608))
* **auditmon:** walk the tail in bounded batches ([#293](https://github.com/ridi-oss/proxy-monster/issues/293)) ([5190e51](https://github.com/ridi-oss/proxy-monster/commit/5190e5153548d7760e96e709c017da4f4a183149))
* **control-plane:** fail orphaned RUNNING children before V25 builds its index ([#280](https://github.com/ridi-oss/proxy-monster/issues/280)) ([9ad9254](https://github.com/ridi-oss/proxy-monster/commit/9ad92544b93e20cd478f3984f2335ed1e051da2d))
* **control-plane:** redact a failed query's diagnostic per decision and per viewer ([#228](https://github.com/ridi-oss/proxy-monster/issues/228)) ([#253](https://github.com/ridi-oss/proxy-monster/issues/253)) ([fb09aa3](https://github.com/ridi-oss/proxy-monster/commit/fb09aa3823cfdc21043e05e3983030594255ccaa))
* **control-plane:** release saved plan-only EXPLAIN results ([#283](https://github.com/ridi-oss/proxy-monster/issues/283)) ([316bc11](https://github.com/ridi-oss/proxy-monster/commit/316bc118bf7423c3f81e2f4d827eacaac51192f2))
* **engine:** gate SHOW GRANTS and SHOW PROCESSLIST by statement kind ([#266](https://github.com/ridi-oss/proxy-monster/issues/266)) ([1a1f6ba](https://github.com/ridi-oss/proxy-monster/commit/1a1f6ba39e7a46edaff53eac8567ad4c30b2a23f))
* **goproxy:** bound catalog reconciliation concurrency ([#87](https://github.com/ridi-oss/proxy-monster/issues/87)) ([81a5d16](https://github.com/ridi-oss/proxy-monster/commit/81a5d1629ea5ae41e17f71252976946ce0806362))
* **goproxy:** reopen the events stream promptly after a max-age rotation ([#282](https://github.com/ridi-oss/proxy-monster/issues/282)) ([4775e82](https://github.com/ridi-oss/proxy-monster/commit/4775e82d2773ac30babdc9fbdbc25b67c9c869d7))
* **pgproxy:** handle PostgreSQL protocol edge cases ([#245](https://github.com/ridi-oss/proxy-monster/issues/245)) ([0b9aaf5](https://github.com/ridi-oss/proxy-monster/commit/0b9aaf55d719cdff9d1a1da55a92579248c2b41c))


### Refactoring

* **analyzer:** engine behavior goes through the SPI, never a type check ([#274](https://github.com/ridi-oss/proxy-monster/issues/274)) ([36930b7](https://github.com/ridi-oss/proxy-monster/commit/36930b7bbd4fedda39f3c7c8e75859c710ff2240))
* **control-plane:** address a task's result children by ordinal ([#279](https://github.com/ridi-oss/proxy-monster/issues/279)) ([6956342](https://github.com/ridi-oss/proxy-monster/commit/6956342f62d97b73ff7736ba33b6b67edfd04370))


### Build & Dependencies

* **analyzer:** adopt sqlglot-go v0.29.0 ([#277](https://github.com/ridi-oss/proxy-monster/issues/277)) ([b90050d](https://github.com/ridi-oss/proxy-monster/commit/b90050d0faadbdae56adf66eb45692a1d6e5660f))
* **analyzer:** adopt sqlglot-go v0.33.0 ([#291](https://github.com/ridi-oss/proxy-monster/issues/291)) ([9ab16ac](https://github.com/ridi-oss/proxy-monster/commit/9ab16ac6555d8b3516e6e81fb13a06559df18d0e))
* **deps:** bump actions/download-artifact from 6 to 8 ([#210](https://github.com/ridi-oss/proxy-monster/issues/210)) ([33573fd](https://github.com/ridi-oss/proxy-monster/commit/33573fd91c8df2c4872f688b3d96018487d0487f))
* **deps:** bump aws-actions/amazon-ecr-login from 2.1.6 to 2.1.7 ([#255](https://github.com/ridi-oss/proxy-monster/issues/255)) ([641eb17](https://github.com/ridi-oss/proxy-monster/commit/641eb179d558d1d80a083714cb2c61b66f19bd13))
* **deps:** bump com.nimbusds:nimbus-jose-jwt from 9.40 to 10.9.1 ([#211](https://github.com/ridi-oss/proxy-monster/issues/211)) ([eaebe1c](https://github.com/ridi-oss/proxy-monster/commit/eaebe1c9e4bc706d7f3eb0fe031114d722deef1b))
* **deps:** bump docker/build-push-action from 6 to 7 ([#213](https://github.com/ridi-oss/proxy-monster/issues/213)) ([1f64281](https://github.com/ridi-oss/proxy-monster/commit/1f64281db2c8469b9b33c690fc1ae8dd43928657))
* **deps:** bump docker/login-action from 3 to 4 ([#208](https://github.com/ridi-oss/proxy-monster/issues/208)) ([97398e5](https://github.com/ridi-oss/proxy-monster/commit/97398e5bf39688e9b0186692c52da476cf99f9e0))
* **deps:** bump the go group across 1 directory with 4 updates ([#290](https://github.com/ridi-oss/proxy-monster/issues/290)) ([8ac895d](https://github.com/ridi-oss/proxy-monster/commit/8ac895d322c05399b01114d6da4f3952d197419e))
* **deps:** bump the go group across 4 directories with 8 updates ([#256](https://github.com/ridi-oss/proxy-monster/issues/256)) ([d431547](https://github.com/ridi-oss/proxy-monster/commit/d431547ff28646ad24ec82226b8387510ba3ce5a))
* **deps:** bump the jvm group across 1 directory with 10 updates ([#254](https://github.com/ridi-oss/proxy-monster/issues/254)) ([e3de0b5](https://github.com/ridi-oss/proxy-monster/commit/e3de0b540a6d5e5a7fdafcefc22c4616055798cc))
* **deps:** bump the jvm group with 3 updates ([#288](https://github.com/ridi-oss/proxy-monster/issues/288)) ([4a16407](https://github.com/ridi-oss/proxy-monster/commit/4a16407f63abc947a82b7f40bd0a461d27d0b68d))
* **deps:** bump the web group across 1 directory with 10 updates ([#268](https://github.com/ridi-oss/proxy-monster/issues/268)) ([3af3fa4](https://github.com/ridi-oss/proxy-monster/commit/3af3fa440545eac963c701da0abbb9d5d9b0f949))
* **deps:** bump the web group in /web with 2 updates ([#289](https://github.com/ridi-oss/proxy-monster/issues/289)) ([8d2533f](https://github.com/ridi-oss/proxy-monster/commit/8d2533f9986a37f8cbd38fb8d6ade57803116c45))


### Documentation

* describe pmon upstream TLS as chain verification, not pinning ([#276](https://github.com/ridi-oss/proxy-monster/issues/276)) ([abdff7b](https://github.com/ridi-oss/proxy-monster/commit/abdff7b22afefc11eee94d30b7303f0446450a5f))
* trim KNOWN_LIMITATIONS to concrete, example-first entries ([#272](https://github.com/ridi-oss/proxy-monster/issues/272)) ([d93038d](https://github.com/ridi-oss/proxy-monster/commit/d93038d94f74dcfc6b44f084976ec3fb34fc66a2))

## [0.1.23](https://github.com/ridi-oss/proxy-monster/compare/server-v0.1.22...server-v0.1.23) (2026-08-28)


### Features

* **goproxy:** carry both raw and redacted forms of a failed query's target-DB error ([#261](https://github.com/ridi-oss/proxy-monster/issues/261)) ([279ca2e](https://github.com/ridi-oss/proxy-monster/commit/279ca2e82df806e0e267613b42b580ac1e8eb3d2))


### Bug Fixes

* **control-plane:** refetch an unheld schema before relaying it unanalyzed ([#258](https://github.com/ridi-oss/proxy-monster/issues/258)) ([63ae665](https://github.com/ridi-oss/proxy-monster/commit/63ae665fbe945daf631b2a5310a751f1613399b8))


### Refactoring

* **analyzer:** fold identifiers once, up front, instead of per consumer ([#257](https://github.com/ridi-oss/proxy-monster/issues/257)) ([70bf790](https://github.com/ridi-oss/proxy-monster/commit/70bf790ad57d918cbd0e06aee83dc7379929c724))
* **control-plane:** store a query result as protobuf, not kotlinx JSON ([#265](https://github.com/ridi-oss/proxy-monster/issues/265)) ([9ccff9e](https://github.com/ridi-oss/proxy-monster/commit/9ccff9e1ee8efdd5705b98292585d69dfb2639ff))


### Build & Dependencies

* **web:** commit the agent files next dev regenerates ([#260](https://github.com/ridi-oss/proxy-monster/issues/260)) ([a4ff9a4](https://github.com/ridi-oss/proxy-monster/commit/a4ff9a4b9d4d08716cf8ac86befa952dc905f25a))

## [0.1.22](https://github.com/ridi-oss/proxy-monster/compare/server-v0.1.21...server-v0.1.22) (2026-08-24)


### Bug Fixes

* **control-plane:** gate stored-result views on a decision fingerprint, not column labels ([#229](https://github.com/ridi-oss/proxy-monster/issues/229)) ([#241](https://github.com/ridi-oss/proxy-monster/issues/241)) ([06c189c](https://github.com/ridi-oss/proxy-monster/commit/06c189c98cc6c288b4ef0956cb580f27c00becfd))

## [0.1.21](https://github.com/ridi-oss/proxy-monster/compare/server-v0.1.20...server-v0.1.21) (2026-08-21)


### Reverts

* surface a failed query's target-DB error ([#202](https://github.com/ridi-oss/proxy-monster/issues/202)) ([#227](https://github.com/ridi-oss/proxy-monster/issues/227)) ([203ca88](https://github.com/ridi-oss/proxy-monster/commit/203ca88e720d2c5cb9e5e7767238ed98abea546e))


### Build & Dependencies

* **release:** recognize revert-type commits + cut server 0.1.21 ([#233](https://github.com/ridi-oss/proxy-monster/issues/233)) ([f57c488](https://github.com/ridi-oss/proxy-monster/commit/f57c4887897e4e9066e2234908ed4ab49e5aebdc))

## [0.1.20](https://github.com/ridi-oss/proxy-monster/compare/server-v0.1.19...server-v0.1.20) (2026-08-20)


### Bug Fixes

* **analyzer:** allow VALUES() in INSERT … ON DUPLICATE KEY UPDATE ([#224](https://github.com/ridi-oss/proxy-monster/issues/224)) ([44944af](https://github.com/ridi-oss/proxy-monster/commit/44944af2a409ecdf49dc50615276c92603c0ff5b))
* uncorrupt Slack reason links + one Approve & run button ([#226](https://github.com/ridi-oss/proxy-monster/issues/226)) ([94f99c0](https://github.com/ridi-oss/proxy-monster/commit/94f99c0bf4f34bc822c6e21daea0255a6819d8fb))

## [0.1.19](https://github.com/ridi-oss/proxy-monster/compare/server-v0.1.18...server-v0.1.19) (2026-08-20)


### Features

* **control-plane:** surface a failed query's target-DB error, confidential like the rows ([#202](https://github.com/ridi-oss/proxy-monster/issues/202)) ([ef0c271](https://github.com/ridi-oss/proxy-monster/commit/ef0c271bce0a55ca3d2313b80cc93da141b03880))
* **web:** list every role a query can run under, auto-discovered in the composer ([#201](https://github.com/ridi-oss/proxy-monster/issues/201)) ([b5d0280](https://github.com/ridi-oss/proxy-monster/commit/b5d02802fe2495a5ce8c403a3957a2db49f215be))


### Bug Fixes

* **goproxy:** hex BIT/GEOMETRY and any non-UTF-8 result cell ([#219](https://github.com/ridi-oss/proxy-monster/issues/219)) ([cf5069a](https://github.com/ridi-oss/proxy-monster/commit/cf5069ab0b1a45ab6876c5ce7aa705cedde31f61))
* **mysqlproxy:** show binary values in web results ([#205](https://github.com/ridi-oss/proxy-monster/issues/205)) ([d785d9b](https://github.com/ridi-oss/proxy-monster/commit/d785d9b70206eb9cc2386813d2f68fd7477bc842))
* **web:** reload the page on same-window identity changes ([#207](https://github.com/ridi-oss/proxy-monster/issues/207)) ([8456af7](https://github.com/ridi-oss/proxy-monster/commit/8456af70864172fd497f89487f9e6cf0ef5fcd0f))
* **web:** session-routing e2e accepts the ?next= login redirect ([#199](https://github.com/ridi-oss/proxy-monster/issues/199)) ([efd69df](https://github.com/ridi-oss/proxy-monster/commit/efd69dfe2e0e3f7dbe5dc7fb377dcf3e14127869))


### Build & Dependencies

* bump mysqlwire to v0.1.4 in goproxy and pmon ([#220](https://github.com/ridi-oss/proxy-monster/issues/220)) ([d45f214](https://github.com/ridi-oss/proxy-monster/commit/d45f214010ac98df0ae9b4ae8e27ce23fe8dc6f9))

## [0.1.18](https://github.com/ridi-oss/proxy-monster/compare/server-v0.1.17...server-v0.1.18) (2026-08-14)


### Bug Fixes

* **analyzer:** classify MySQL account management and keep its result viewable ([#200](https://github.com/ridi-oss/proxy-monster/issues/200)) ([a5b609b](https://github.com/ridi-oss/proxy-monster/commit/a5b609ba74630c467c5ba57a27641206661fb345))


### Build & Dependencies

* **deps:** bump the web group across 1 directory with 12 updates ([#184](https://github.com/ridi-oss/proxy-monster/issues/184)) ([2a57582](https://github.com/ridi-oss/proxy-monster/commit/2a57582f26c1ff02cb2dc91a42376f851e959330))
* **deps:** bump typescript from 5.9.3 to 6.0.3 in /web ([#9](https://github.com/ridi-oss/proxy-monster/issues/9)) ([6f69117](https://github.com/ridi-oss/proxy-monster/commit/6f69117a304782f08f5830724285592f651546b3))

## [0.1.17](https://github.com/ridi-oss/proxy-monster/compare/server-v0.1.16...server-v0.1.17) (2026-08-13)


### Bug Fixes

* **control-plane:** record a DML statement's affected-row count on the saved result ([#130](https://github.com/ridi-oss/proxy-monster/issues/130)) ([5d01b2c](https://github.com/ridi-oss/proxy-monster/commit/5d01b2c8f5bd2fac3aa563351e03acf0012a5199))


### Build & Dependencies

* **deps:** bump CI actions — checkout/setup-node/setup-go v7, setup-buildx v4, release-please v5 ([#194](https://github.com/ridi-oss/proxy-monster/issues/194)) ([c77ea17](https://github.com/ridi-oss/proxy-monster/commit/c77ea17ab83287bcce7268099968d3a8142ff5f7))
* **deps:** bump gradle-wrapper from 8.14.5 to 9.6.1 ([#6](https://github.com/ridi-oss/proxy-monster/issues/6)) ([588b383](https://github.com/ridi-oss/proxy-monster/commit/588b383670f40a2e141e100b7349377d898ea884))
* **deps:** bump mysqlwire to v0.1.3 in goproxy and pmon ([#196](https://github.com/ridi-oss/proxy-monster/issues/196)) ([54d0491](https://github.com/ridi-oss/proxy-monster/commit/54d049160706fd8c99683aa5caa97c4d29b76e44))
* **deps:** bump the go group across 4 directories with 14 updates ([#181](https://github.com/ridi-oss/proxy-monster/issues/181)) ([47f3f3c](https://github.com/ridi-oss/proxy-monster/commit/47f3f3c57c7d2ceba31e201c3e2e7187ea28015f))
* **deps:** bump the jvm group across 1 directory with 45 updates ([#195](https://github.com/ridi-oss/proxy-monster/issues/195)) ([95af897](https://github.com/ridi-oss/proxy-monster/commit/95af89772c16a9ae25d74c10e0aa38e8928e7329))

## [0.1.16](https://github.com/ridi-oss/proxy-monster/compare/server-v0.1.15...server-v0.1.16) (2026-08-13)


### Bug Fixes

* **control-plane:** deliver both the requester's receipt and the approver message ([#188](https://github.com/ridi-oss/proxy-monster/issues/188)) ([f5515ec](https://github.com/ridi-oss/proxy-monster/commit/f5515ec48c4c817106c6e020d531de40a48ea724))


### Refactoring

* **control-plane:** build the approval authz resource from the request row ([#189](https://github.com/ridi-oss/proxy-monster/issues/189)) ([bce0163](https://github.com/ridi-oss/proxy-monster/commit/bce0163fed9f49fd6ea666be501e25128f9e902d))


### Documentation

* reclassify the Bind-coercion search_path limitation as accepted (out-of-scope UDF) ([#190](https://github.com/ridi-oss/proxy-monster/issues/190)) ([98b55d2](https://github.com/ridi-oss/proxy-monster/commit/98b55d29af60a8956480c49b6313399042897ca9))

## [0.1.15](https://github.com/ridi-oss/proxy-monster/compare/server-v0.1.14...server-v0.1.15) (2026-08-13)


### Features

* **control-plane:** model EXPLAIN and table ANALYZE as metadata-output reads ([#175](https://github.com/ridi-oss/proxy-monster/issues/175)) ([2d58e3d](https://github.com/ridi-oss/proxy-monster/commit/2d58e3da420eaa125d275d537e0414ec2a35dc08))


### Bug Fixes

* **control-plane:** let a self-approving requester get the approver message ([#186](https://github.com/ridi-oss/proxy-monster/issues/186)) ([a6196ba](https://github.com/ridi-oss/proxy-monster/commit/a6196bacec39918dc89b6c3d2c33efb8f880736c))

## [0.1.14](https://github.com/ridi-oss/proxy-monster/compare/server-v0.1.13...server-v0.1.14) (2026-08-12)


### Features

* **control-plane:** recut statement disclosure to omit|auto|full and notify the requester ([#182](https://github.com/ridi-oss/proxy-monster/issues/182)) ([bf1d6e2](https://github.com/ridi-oss/proxy-monster/commit/bf1d6e281bb463c3aa99a873d72752d4c614f7be))


### Bug Fixes

* **control-plane:** PM_AUTH_DEBUG is a login method, nothing else ([#174](https://github.com/ridi-oss/proxy-monster/issues/174)) ([2174b2c](https://github.com/ridi-oss/proxy-monster/commit/2174b2c92c85387c9b81b45fc88228075f38fca5))

## [0.1.13](https://github.com/ridi-oss/proxy-monster/compare/server-v0.1.12...server-v0.1.13) (2026-08-11)


### Bug Fixes

* **control-plane:** close unmanifested system tables fail-closed (GHSA-j984-q948-4xq8) ([#170](https://github.com/ridi-oss/proxy-monster/issues/170)) ([064b31c](https://github.com/ridi-oss/proxy-monster/commit/064b31c08ffd303fd157442dbe3e561d776ca56a))
* **control-plane:** gate per-datasource metadata on datasource.connect ([#171](https://github.com/ridi-oss/proxy-monster/issues/171)) ([a366c2b](https://github.com/ridi-oss/proxy-monster/commit/a366c2b64b3cd39dda06fb384e3100cc3cd1e9db))
* **engine:** classify value-bearing system tables away from catalog ([#173](https://github.com/ridi-oss/proxy-monster/issues/173)) ([e15840d](https://github.com/ridi-oss/proxy-monster/commit/e15840ddc153d909b839891a6eae07b27789fc61))

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
