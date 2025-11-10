## [v0.1.0-beta.21] - 2025-11-10

### Bug Fixes

- Trying to fix verifier issue for old kernels (#253)

[v0.1.0-beta.20..v0.1.0-beta.21](https://github.com/elastiflow/mermin/compare/v0.1.0-beta.20...v0.1.0-beta.21)



## [v0.1.0-beta.20] - 2025-11-10

### Bug Fixes

- Set security context to privileged mode (#250)

[v0.1.0-beta.19..v0.1.0-beta.20](https://github.com/elastiflow/mermin/compare/v0.1.0-beta.19...v0.1.0-beta.20)



## [v0.1.0-beta.19] - 2025-11-08

### Features

- Add configurable TCX ordering and optimize tunnel port lookups (#248)

[v0.1.0-beta.18..v0.1.0-beta.19](https://github.com/elastiflow/mermin/compare/v0.1.0-beta.18...v0.1.0-beta.19)



## [v0.1.0-beta.18] - 2025-11-08

### Features

- Add configurable ebpf parser to reduce verifier complexity (#245)

[v0.1.0-beta.17..v0.1.0-beta.18](https://github.com/elastiflow/mermin/compare/v0.1.0-beta.17...v0.1.0-beta.18)



## [v0.1.0-beta.17] - 2025-11-08

### Bug Fixes

- **cni tests:** Add flow generator (#231)
### Features

- Log the resolved interfaces on startup at info level (#236)
- Add tc priority support for safe multi-program coexistence (#246)

[v0.1.0-beta.16..v0.1.0-beta.17](https://github.com/elastiflow/mermin/compare/v0.1.0-beta.16...v0.1.0-beta.17)



## [v0.1.0-beta.16] - 2025-11-07

### Bug Fixes

- Docs links in main docs page (#226)
- CNI tests (#229)

[v0.1.0-beta.15..v0.1.0-beta.16](https://github.com/elastiflow/mermin/compare/v0.1.0-beta.15...v0.1.0-beta.16)



## [v0.1.0-beta.15] - 2025-11-06

### Bug Fixes

- **helm:** Invalid tag mermin Helm chart (#222)

[v0.1.0-beta.14..v0.1.0-beta.15](https://github.com/elastiflow/mermin/compare/v0.1.0-beta.14...v0.1.0-beta.15)



## [v0.1.0-beta.14] - 2025-11-05

### Bug Fixes

- Docker tags should not have  prefix (#211)
- Add "v" prefix back to the docker tags (#217)
- Add host network namespace switching for ebpf attachment (#209)
- Add new  cap (#219)

[v0.1.0-beta.13..v0.1.0-beta.14](https://github.com/elastiflow/mermin/compare/v0.1.0-beta.13...v0.1.0-beta.14)



## [v0.1.0-beta.13] - 2025-11-04

### Bug Fixes

- Fix ring buffer initialization timing to prevent write failures (#205)
- **helm:** Re-iterate on the example deployments (#207)

[v0.1.0-beta.12..v0.1.0-beta.13](https://github.com/elastiflow/mermin/compare/v0.1.0-beta.12...v0.1.0-beta.13)



## [v0.1.0-beta.12] - 2025-11-04

### Features

- Add kernel-aware tc attachment and graceful ebpf shutdown (#199)

[v0.1.0-beta.11..v0.1.0-beta.12](https://github.com/elastiflow/mermin/compare/v0.1.0-beta.11...v0.1.0-beta.12)



## [v0.1.0-beta.11] - 2025-11-04

### Features

- Change default interface discovery to cni/k8s patterns (#197)

[v0.1.0-beta.10..v0.1.0-beta.11](https://github.com/elastiflow/mermin/compare/v0.1.0-beta.10...v0.1.0-beta.11)



## [v0.1.0-beta.10] - 2025-11-03

### Bug Fixes

- **helm:** Bump Mermin dependency in Composite chart (#190)
### Features

- Subscribe to opentelemetry logs (#194)
- **chart:** Add optional host networking in daemonset (#196)

[v0.1.0-beta.9..v0.1.0-beta.10](https://github.com/elastiflow/mermin/compare/v0.1.0-beta.9...v0.1.0-beta.10)



## [v0.1.0-beta.9] - 2025-10-28

### Bug Fixes

- Flow timestamp ordering and refactor export config structure (#188)
### Features

- **config:** Flow to k8s object association (#181)

[v0.1.0-beta.8..v0.1.0-beta.9](https://github.com/elastiflow/mermin/compare/v0.1.0-beta.8...v0.1.0-beta.9)



## [v0.1.0-beta.8] - 2025-10-24

### Bug Fixes

- **ci:** Dependency install for mermin-netobserv-os-stack (#178)
- **ci:** Use reusable workflow for non-mermin charts (#180)
- **k8s:** Prevent span drops on decoration failure with fallback mechanism (#186)
### Features

- **helm:** Bump mermin-netobserv-os-stack dependencies (#176)

[v0.1.0-beta.7..v0.1.0-beta.8](https://github.com/elastiflow/mermin/compare/v0.1.0-beta.7...v0.1.0-beta.8)



## [v0.1.0-beta.7] - 2025-10-22

### Bug Fixes

- **helm:** Wrong changelog path for an umbrella chart (#168)
- Use correct bump_version_yaml_path for stack chart (#171)
- **otlp:** Refactor tls implementation with proper rustls integration (#175)
- **helm:** Add example for simple Mermin with NetObserv and Opensearch deployment (#170)
### Features

- **agent:** Log cleanup (#159)
- **k8s:** Add configurable owner reference filtering (#173)
- **k8s:** Add selector-based resource relations support (#174)

[v0.1.0-beta.6..v0.1.0-beta.7](https://github.com/elastiflow/mermin/compare/v0.1.0-beta.6...v0.1.0-beta.7)



## [v0.1.0-beta.6] - 2025-10-21

### Features

- **helm:** Add the "Mermin NetObserv OS" umbrella chart (#142)

[v0.1.0-beta.5..v0.1.0-beta.6](https://github.com/elastiflow/mermin/compare/v0.1.0-beta.5...v0.1.0-beta.6)



## [v0.1.0-beta.5] - 2025-10-21

### Features

- **config:** Span batch size opts (#161)
- **otlp:** Add tls support with mutual authentication and insecure_skip_verify mode (#164)
- **agent:** Flow span src/dst configuration (#139)
- **config:** Support communityid seed config option (#163)

[v0.1.0-beta.4..v0.1.0-beta.5](https://github.com/elastiflow/mermin/compare/v0.1.0-beta.4...v0.1.0-beta.5)



## [v0.1.0-beta.4] - 2025-10-16

### Bug Fixes

- **helm:** Simplify the config in values (#156)
### Features

- **conf:** Support tunnel options config (#140)

[v0.1.0-beta.3..v0.1.0-beta.4](https://github.com/elastiflow/mermin/compare/v0.1.0-beta.3...v0.1.0-beta.4)



## [v0.1.0-beta.3] - 2025-10-15

### Bug Fixes

- **ci:** Release helm packages to gh-pages (#151)

[v0.1.0-beta.2..v0.1.0-beta.3](https://github.com/elastiflow/mermin/compare/v0.1.0-beta.2...v0.1.0-beta.3)



## [v0.1.0-beta.2] - 2025-10-14

### Bug Fixes

- **ci:** Separate tag for "mermin" helm chart (#149)

[v0.1.0-beta.1..v0.1.0-beta.2](https://github.com/elastiflow/mermin/compare/v0.1.0-beta.1...v0.1.0-beta.2)



## [v0.1.0-beta.1] - 2025-10-14

### Bug Fixes

- **ci:** "fetch-depth" should be 0 for releases (#143)
- **ci:** Simplify the "is_release" regex (#145)
### Features

- **helm:** Split "mermin" and "mermin-netobserv-os-stack" to separate charts (#141)

[v0.1.0-beta.0..v0.1.0-beta.1](https://github.com/elastiflow/mermin/compare/v0.1.0-beta.0...v0.1.0-beta.1)



## [0.1.0-alpha.6](https://github.com/elastiflow/mermin/compare/v0.1.0-alpha.5...v0.1.0-alpha.6) (2025-10-08)

### Features

* add regex and glob pattern matching for interface discovery ([#134](https://github.com/elastiflow/mermin/issues/134)) ([7c9ceea](https://github.com/elastiflow/mermin/commit/7c9ceeaef5a6a335c582000d3b7e7a2c8429bb3d))
* **span:** async flow span producer with interval-based recording and protocol-aware timeouts ([#135](https://github.com/elastiflow/mermin/issues/135)) ([852e3ef](https://github.com/elastiflow/mermin/commit/852e3ef7b3a48b4a270d88beae87a7a981e13d3c))


## [0.1.0-alpha.5](https://github.com/elastiflow/mermin/compare/v0.1.0-alpha.4...v0.1.0-alpha.5) (2025-10-07)

### Features

* **tcp_flags:** tcp flags and bytes spec ([#132](https://github.com/elastiflow/mermin/issues/132)) ([8767b27](https://github.com/elastiflow/mermin/commit/8767b27d3467b80889718e0b51f2c061d71b7e46))


## [0.1.0-alpha.4](https://github.com/elastiflow/mermin/compare/v0.1.0-alpha.3...v0.1.0-alpha.4) (2025-10-02)

### Features

* **ebpf:** add ip-in-ip and ipsec tunnel detection with refactored encapsulation handling ([#130](https://github.com/elastiflow/mermin/issues/130)) ([798a5a7](https://github.com/elastiflow/mermin/commit/798a5a76ac16b6e9b8a24cc9f10c8d8e88d4026f))
* **helm:** Add GKE example ([#127](https://github.com/elastiflow/mermin/issues/127)) ([a0a1301](https://github.com/elastiflow/mermin/commit/a0a130132b028afc113f1c33a5d92ef972e71b6b))


## [0.1.0-alpha.3](https://github.com/elastiflow/mermin/compare/v0.1.0-alpha.2...v0.1.0-alpha.3) (2025-10-01)

### Features

* **configuration:** support hcl files ([#117](https://github.com/elastiflow/mermin/issues/117)) ([e5e6e9b](https://github.com/elastiflow/mermin/commit/e5e6e9b2364061752282a49bd0a998b479f4ecaa))

### Bug Fixes

* **ebpf:** refactors the ebpf code to stay in compliance with the verifier ([#125](https://github.com/elastiflow/mermin/issues/125)) ([160f7e8](https://github.com/elastiflow/mermin/commit/160f7e8f2a0d9a46efdbe58cd844ee43ab8e8bea))


## [0.1.0-alpha.2](https://github.com/elastiflow/mermin/compare/v0.1.0-alpha.1...v0.1.0-alpha.2) (2025-09-27)

### Features

* **agent:** Implement Kubernetes Probes ([#94](https://github.com/elastiflow/mermin/issues/94)) ([3804b9f](https://github.com/elastiflow/mermin/commit/3804b9fc5d17bee124dfaf5c69fde4eb28deb93e))
* **CI:** Add CNI Testing ([#95](https://github.com/elastiflow/mermin/issues/95)) ([297f3f4](https://github.com/elastiflow/mermin/commit/297f3f4e84363da318a54c4818f6737b90d59d15))
* **ci:** Add PR Title linter ([#105](https://github.com/elastiflow/mermin/issues/105)) ([af69a20](https://github.com/elastiflow/mermin/commit/af69a2028e1178c1383d9f91bff4835ee73555af))
* **configuration:** implement exporter configs and placeholder authentication ([#110](https://github.com/elastiflow/mermin/issues/110)) ([df8233c](https://github.com/elastiflow/mermin/commit/df8233c2dfc31d5947496e08c4cd68a788ab04bc))
* **eng-101:** Semconv: Define for Network Traces + Flow Spans ([#115](https://github.com/elastiflow/mermin/issues/115)) ([70cb160](https://github.com/elastiflow/mermin/commit/70cb160e043159c5b2d4648b9d4caa67966ddec2))
* **flow:** populate flow span attributes with enhanced network protocol support ([#121](https://github.com/elastiflow/mermin/issues/121)) ([c235734](https://github.com/elastiflow/mermin/commit/c235734c906d2c83392199d200f69cad3f21bb74))
* **mermin-ebpf:** adjust integration tests to utilize percpuarray  ([#106](https://github.com/elastiflow/mermin/issues/106)) ([5245b14](https://github.com/elastiflow/mermin/commit/5245b141b6da1a1f56cf426560b123f0426a3e23))
* **otlp exporter:** fully connected mermin userspace program ([#96](https://github.com/elastiflow/mermin/issues/96)) ([fc17ff8](https://github.com/elastiflow/mermin/commit/fc17ff8525c36f909c95cfb9f8bea67595160df5))
* **span-flow:** implements new span flow spec fields ([#118](https://github.com/elastiflow/mermin/issues/118)) ([afb4a88](https://github.com/elastiflow/mermin/commit/afb4a88f01780d06d92a89fec0a179f0c94d64aa))
* **tc-attach:** attach to ingress and egress for each interface ([#113](https://github.com/elastiflow/mermin/issues/113)) ([0a064a2](https://github.com/elastiflow/mermin/commit/0a064a2385f380b551e3a44716501b308e304640))
* **tcp flags:** add support for extracting tcp flags from packet meta ([#100](https://github.com/elastiflow/mermin/issues/100)) ([fc68c6d](https://github.com/elastiflow/mermin/commit/fc68c6d78e6313a7602586b637dc89a16f4debe6))
* **wireguard:** add wireguard support to ebpf parsing ([#101](https://github.com/elastiflow/mermin/issues/101)) ([28b000a](https://github.com/elastiflow/mermin/commit/28b000af9ddc499b0f4bf800e0ab7da54675b63d))

### Bug Fixes

* Address clippy errors about unused code ([#102](https://github.com/elastiflow/mermin/issues/102)) ([890d6a8](https://github.com/elastiflow/mermin/commit/890d6a8cf661bf8e319627527028e611b4bcdea2))
* **CI:** fix cni test failures from new log output ([#108](https://github.com/elastiflow/mermin/issues/108)) ([9ad6ba8](https://github.com/elastiflow/mermin/commit/9ad6ba836c5561c0874ddc7dbcb61238c231fc36))
* **ci:** Improve docker build time ([#107](https://github.com/elastiflow/mermin/issues/107)) ([234c191](https://github.com/elastiflow/mermin/commit/234c191769cb117dd5054227fb294cc46a6bdd71)), closes [/github.com/rust-lang/cargo/issues/2644#issuecomment-2335499312](https://github.com/elastiflow//github.com/rust-lang/cargo/issues/2644/issues/issuecomment-2335499312)
* use the correct namespace when checking network policies ([#120](https://github.com/elastiflow/mermin/issues/120)) ([9d39c9f](https://github.com/elastiflow/mermin/commit/9d39c9f9ca3344e1d4f8efd17e7560fec1a381c6))


## [0.1.0-alpha.1](https://github.com/elastiflow/mermin/compare/v0.0.0...v0.1.0-alpha.1) (2025-09-16)

### Features

* Add release workflow ([#72](https://github.com/elastiflow/mermin/issues/72)) ([3b10150](https://github.com/elastiflow/mermin/commit/3b10150cae932df42b2e96009875244e88b2cb37)), closes [/pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap03.html#tag_03_206](https://github.com/elastiflow//pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap03.html/issues/tag_03_206)
* basic network types ([#8](https://github.com/elastiflow/mermin/issues/8)) ([78bc047](https://github.com/elastiflow/mermin/commit/78bc047da77d13c12ed95468091594de90ed0633))
* **build:** Overhaul Docker build and eBPF toolchain handling ([#27](https://github.com/elastiflow/mermin/issues/27)) ([69ef545](https://github.com/elastiflow/mermin/commit/69ef545871f51275e78800e31f6d20057bae96fe))
* **ENG-12:** IPv4 header support ([#12](https://github.com/elastiflow/mermin/issues/12)) ([379e47f](https://github.com/elastiflow/mermin/commit/379e47f452ba678a5b7cd6f58dca7c14b7d8d757))
* **ENG-14 and ENG-15:** UDP and TCP header support ([#14](https://github.com/elastiflow/mermin/issues/14)) ([2c6da66](https://github.com/elastiflow/mermin/commit/2c6da664a48cc3dcc9c60d89d4967d9b0d283520))
* **eng-169:** parse tunneling packet headers ([#77](https://github.com/elastiflow/mermin/issues/77)) ([3da368c](https://github.com/elastiflow/mermin/commit/3da368c17088620a5a81d14d01b0b7ec7e713088))
* **ENG-172:** Attach mermin to multiple interfaces ([#85](https://github.com/elastiflow/mermin/issues/85)) ([513aab9](https://github.com/elastiflow/mermin/commit/513aab98e9c9b7ef68c2fcf632b43e887f2bed55))
* **eng-17:** extract l3 bytes and introduce packet metadata ([#15](https://github.com/elastiflow/mermin/issues/15)) ([21bb91a](https://github.com/elastiflow/mermin/commit/21bb91adce21b20d657a6553e3cd4ad07c1acab7))
* **eng-18:** simplify PacketMeta and write to PACKETS ring buffer ([#17](https://github.com/elastiflow/mermin/issues/17)) ([15aacac](https://github.com/elastiflow/mermin/commit/15aacac4b5d7ad5096df0509c24c46d3ba96fca0))
* **ENG-20:** Receive events on ring buffer within user space prog ([#18](https://github.com/elastiflow/mermin/issues/18)) ([f732124](https://github.com/elastiflow/mermin/commit/f73212450e8eec23083ec6499fc7575bbbb57c53))
* **ENG-23:** Integration tests for actual network packets ([#25](https://github.com/elastiflow/mermin/issues/25)) ([e72f4a3](https://github.com/elastiflow/mermin/commit/e72f4a3af3411dff0e20947c4a4f53ad26106928))
* **ENG-24:** Linting and Formating w/ CI Pipeline ([#16](https://github.com/elastiflow/mermin/issues/16)) ([657dac5](https://github.com/elastiflow/mermin/commit/657dac5076e6921951673a24b5be2e9db4c5bb05))
* **eng-26:** foundational flow producer with flow map and event channels ([#92](https://github.com/elastiflow/mermin/issues/92)) ([8a3691d](https://github.com/elastiflow/mermin/commit/8a3691dc90302b40fe240aa6db8f6f2167b15dba))
* **eng-28:** runtime mod with cli and config integrations ([#38](https://github.com/elastiflow/mermin/issues/38)) ([2acacfe](https://github.com/elastiflow/mermin/commit/2acacfe23ce5211f6143cd7e70dfc8b42cb19271))
* **eng-28:** update configuration system and add flow management ([#43](https://github.com/elastiflow/mermin/issues/43)) ([da0ec9b](https://github.com/elastiflow/mermin/commit/da0ec9bac9d79464e5ebdde067a1bef2be54db36))
* **ENG-30:** Add empty ClusterRole ([#24](https://github.com/elastiflow/mermin/issues/24)) ([bb22d90](https://github.com/elastiflow/mermin/commit/bb22d9018aca83050c0fe9dbb8cc4335345bbced))
* **ENG-30:** Implement IP Address to Pod Resource Mapping ([#48](https://github.com/elastiflow/mermin/issues/48)) ([4fde6ba](https://github.com/elastiflow/mermin/commit/4fde6bafe342b96fd96fe9c085f7a3587faa255d))
* **eng-34:** add Helm chart and kind config for local deployment ([#22](https://github.com/elastiflow/mermin/issues/22)) ([8da512e](https://github.com/elastiflow/mermin/commit/8da512ec8022854c88fb998ef04cbc6850939f78)), closes [#23](https://github.com/elastiflow/mermin/issues/23)
* **eng-34:** dockerfile improvements ([#19](https://github.com/elastiflow/mermin/issues/19)) ([cf8c18d](https://github.com/elastiflow/mermin/commit/cf8c18d1b89d499e9392cef6589f9380497d805d)), closes [#21](https://github.com/elastiflow/mermin/issues/21)
* **ENG-36:** Use kube-rs' kube-runtime crate to watch resources  ([#42](https://github.com/elastiflow/mermin/issues/42)) ([c01a4d5](https://github.com/elastiflow/mermin/commit/c01a4d5ef2b13444b6720c9f7375718e01c6bc1d)), closes [#40](https://github.com/elastiflow/mermin/issues/40)
* **ENG-42:** Implement Traffic Flow to Network Policy Correlation ([#60](https://github.com/elastiflow/mermin/issues/60)) ([44c25b4](https://github.com/elastiflow/mermin/commit/44c25b457ccccaad00a9bb7ce4535cc1a2e7eb3d))
* **ENG-46:** Add Support for VXLAN Encapsulation ([#69](https://github.com/elastiflow/mermin/issues/69)) ([8d34ec0](https://github.com/elastiflow/mermin/commit/8d34ec07b840c9ca65c880fda57e5bd080605d5a))
* **ENG-47:** Add Support for Geneve Encapsulation ([#41](https://github.com/elastiflow/mermin/issues/41)) ([96f67a0](https://github.com/elastiflow/mermin/commit/96f67a08284430e63172ad89a39a61a85726d9cb))
* **Eng-51-esp:** Implement ESP header parsing ([#37](https://github.com/elastiflow/mermin/issues/37)) ([56cdeb3](https://github.com/elastiflow/mermin/commit/56cdeb3ceca711f3202e9aea8d1cfedd1183a5b7))
* **Eng-51-hop:** Implement Hop-by-Hop header parsing ([#39](https://github.com/elastiflow/mermin/issues/39)) ([0eb07f8](https://github.com/elastiflow/mermin/commit/0eb07f833ea28b213ef0e27e9ab3fb033c1937d8))
* **ENG-52:** Add Robust Handling for IPv4 Options and Encapsulation ([#87](https://github.com/elastiflow/mermin/issues/87)) ([cd18c5b](https://github.com/elastiflow/mermin/commit/cd18c5b29b9d741616f4e48f5c648d88fa8cb360))
* implement IPv4/IPv6 community ID generation with comprehensive IP protocol support ([#49](https://github.com/elastiflow/mermin/issues/49)) ([7cb6fb1](https://github.com/elastiflow/mermin/commit/7cb6fb10004fe76b4a26e6f2f81aedc5a12f291e))
* implement ipv6 Destination Option header parsing and testing ([#70](https://github.com/elastiflow/mermin/issues/70)) ([fddce9f](https://github.com/elastiflow/mermin/commit/fddce9ffbcc98470d3e8573494a95c9963beb473))
* implement ipv6 fragment header parsing and testing ([#68](https://github.com/elastiflow/mermin/issues/68)) ([37b05e9](https://github.com/elastiflow/mermin/commit/37b05e9507fd09f2d6379eef327aedfdf51e5caa))
* implement ipv6 Mobility header parsing and testing ([#71](https://github.com/elastiflow/mermin/issues/71)) ([62149e6](https://github.com/elastiflow/mermin/commit/62149e6ed8092a0e1ed4591b2f8c18068fde0d7b))
* implement ipv6 Shim6 header parsing and testing ([#73](https://github.com/elastiflow/mermin/issues/73)) ([4b6e8bd](https://github.com/elastiflow/mermin/commit/4b6e8bd8f0943027f9ce8f40294e6c0e2abaea10))
* implement TCP/UDP parsing and refactor parser loop ([#9](https://github.com/elastiflow/mermin/issues/9)) ([fac3468](https://github.com/elastiflow/mermin/commit/fac34681a87cceddb041fa3f7138e98667ab4a23))
* Integration tests in Network Types for ETH ([#10](https://github.com/elastiflow/mermin/issues/10)) ([748140b](https://github.com/elastiflow/mermin/commit/748140bc69a1ace408f8683f435a8e09548b31b2)), closes [#11](https://github.com/elastiflow/mermin/issues/11)
* Introduce release channels for releases ([#97](https://github.com/elastiflow/mermin/issues/97)) ([f73333b](https://github.com/elastiflow/mermin/commit/f73333b8724e8a5613cdd2c90332a3ae6a40b75f))
* minimal commenting out of parsing functions to allow building ([#59](https://github.com/elastiflow/mermin/issues/59)) ([8ac33c6](https://github.com/elastiflow/mermin/commit/8ac33c6249f4e589a48baf4acb604bc20b3689ed))
* Packet parsing refactor ([#65](https://github.com/elastiflow/mermin/issues/65)) ([1c506d2](https://github.com/elastiflow/mermin/commit/1c506d214266651d6dd29ebe680a31cb657d56ee))
* parser options refactor ([#63](https://github.com/elastiflow/mermin/issues/63)) ([6bf96e1](https://github.com/elastiflow/mermin/commit/6bf96e1b49e334b2b211bf2f51942e38d68f7d75)), closes [#61](https://github.com/elastiflow/mermin/issues/61)
* reduce the number of arguments to parser default constructor ([#61](https://github.com/elastiflow/mermin/issues/61)) ([1afaa07](https://github.com/elastiflow/mermin/commit/1afaa0763a0cee9b1ef99a4162c1523a1d29d179))

### Bug Fixes

* Add missing release steps ([#79](https://github.com/elastiflow/mermin/issues/79)) ([fcfff7d](https://github.com/elastiflow/mermin/commit/fcfff7d3a9763d390849b025c70626143484d638))
* Clear changelog ([#81](https://github.com/elastiflow/mermin/issues/81)) ([db0adbb](https://github.com/elastiflow/mermin/commit/db0adbb9b7c47f921297e2607af006ba6671cff1))
* mermin-ebpf test shim ([#90](https://github.com/elastiflow/mermin/issues/90)) ([6db60d7](https://github.com/elastiflow/mermin/commit/6db60d7c19162e610aef37cb8cae15fd5bebfb19))
* Missing "alpha" branch to trigger release ([f8968da](https://github.com/elastiflow/mermin/commit/f8968da74e02b9ca363babe448d17c8ec813c1b7))
* Wrong arch in the GHCR ([#82](https://github.com/elastiflow/mermin/issues/82)) ([2466464](https://github.com/elastiflow/mermin/commit/246646445d1c74b1fff6fd55c3132d3537fbbaf9))
