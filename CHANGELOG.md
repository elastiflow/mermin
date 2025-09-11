## [0.1.0](https://github.com/elastiflow/mermin/compare/v0.0.0...v0.1.0) (2025-09-11)

### Features

* Add release workflow ([#72](https://github.com/elastiflow/mermin/issues/72)) ([3b10150](https://github.com/elastiflow/mermin/commit/3b10150cae932df42b2e96009875244e88b2cb37)), closes [/pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap03.html#tag_03_206](https://github.com/elastiflow//pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap03.html/issues/tag_03_206)
* basic network types ([#8](https://github.com/elastiflow/mermin/issues/8)) ([78bc047](https://github.com/elastiflow/mermin/commit/78bc047da77d13c12ed95468091594de90ed0633))
* **build:** Overhaul Docker build and eBPF toolchain handling ([#27](https://github.com/elastiflow/mermin/issues/27)) ([69ef545](https://github.com/elastiflow/mermin/commit/69ef545871f51275e78800e31f6d20057bae96fe))
* **ENG-12:** IPv4 header support ([#12](https://github.com/elastiflow/mermin/issues/12)) ([379e47f](https://github.com/elastiflow/mermin/commit/379e47f452ba678a5b7cd6f58dca7c14b7d8d757))
* **ENG-14 and ENG-15:** UDP and TCP header support ([#14](https://github.com/elastiflow/mermin/issues/14)) ([2c6da66](https://github.com/elastiflow/mermin/commit/2c6da664a48cc3dcc9c60d89d4967d9b0d283520))
* **eng-17:** extract l3 bytes and introduce packet metadata ([#15](https://github.com/elastiflow/mermin/issues/15)) ([21bb91a](https://github.com/elastiflow/mermin/commit/21bb91adce21b20d657a6553e3cd4ad07c1acab7))
* **eng-18:** simplify PacketMeta and write to PACKETS ring buffer ([#17](https://github.com/elastiflow/mermin/issues/17)) ([15aacac](https://github.com/elastiflow/mermin/commit/15aacac4b5d7ad5096df0509c24c46d3ba96fca0))
* **ENG-20:** Receive events on ring buffer within user space prog ([#18](https://github.com/elastiflow/mermin/issues/18)) ([f732124](https://github.com/elastiflow/mermin/commit/f73212450e8eec23083ec6499fc7575bbbb57c53))
* **ENG-23:** Integration tests for actual network packets ([#25](https://github.com/elastiflow/mermin/issues/25)) ([e72f4a3](https://github.com/elastiflow/mermin/commit/e72f4a3af3411dff0e20947c4a4f53ad26106928))
* **ENG-24:** Linting and Formating w/ CI Pipeline ([#16](https://github.com/elastiflow/mermin/issues/16)) ([657dac5](https://github.com/elastiflow/mermin/commit/657dac5076e6921951673a24b5be2e9db4c5bb05))
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
* implement IPv4/IPv6 community ID generation with comprehensive IP protocol support ([#49](https://github.com/elastiflow/mermin/issues/49)) ([7cb6fb1](https://github.com/elastiflow/mermin/commit/7cb6fb10004fe76b4a26e6f2f81aedc5a12f291e))
* implement ipv6 Destination Option header parsing and testing ([#70](https://github.com/elastiflow/mermin/issues/70)) ([fddce9f](https://github.com/elastiflow/mermin/commit/fddce9ffbcc98470d3e8573494a95c9963beb473))
* implement ipv6 fragment header parsing and testing ([#68](https://github.com/elastiflow/mermin/issues/68)) ([37b05e9](https://github.com/elastiflow/mermin/commit/37b05e9507fd09f2d6379eef327aedfdf51e5caa))
* implement ipv6 Mobility header parsing and testing ([#71](https://github.com/elastiflow/mermin/issues/71)) ([62149e6](https://github.com/elastiflow/mermin/commit/62149e6ed8092a0e1ed4591b2f8c18068fde0d7b))
* implement ipv6 Shim6 header parsing and testing ([#73](https://github.com/elastiflow/mermin/issues/73)) ([4b6e8bd](https://github.com/elastiflow/mermin/commit/4b6e8bd8f0943027f9ce8f40294e6c0e2abaea10))
* implement TCP/UDP parsing and refactor parser loop ([#9](https://github.com/elastiflow/mermin/issues/9)) ([fac3468](https://github.com/elastiflow/mermin/commit/fac34681a87cceddb041fa3f7138e98667ab4a23))
* Integration tests in Network Types for ETH ([#10](https://github.com/elastiflow/mermin/issues/10)) ([748140b](https://github.com/elastiflow/mermin/commit/748140bc69a1ace408f8683f435a8e09548b31b2)), closes [#11](https://github.com/elastiflow/mermin/issues/11)
* minimal commenting out of parsing functions to allow building ([#59](https://github.com/elastiflow/mermin/issues/59)) ([8ac33c6](https://github.com/elastiflow/mermin/commit/8ac33c6249f4e589a48baf4acb604bc20b3689ed))
* Packet parsing refactor ([#65](https://github.com/elastiflow/mermin/issues/65)) ([1c506d2](https://github.com/elastiflow/mermin/commit/1c506d214266651d6dd29ebe680a31cb657d56ee))
* parser options refactor ([#63](https://github.com/elastiflow/mermin/issues/63)) ([6bf96e1](https://github.com/elastiflow/mermin/commit/6bf96e1b49e334b2b211bf2f51942e38d68f7d75)), closes [#61](https://github.com/elastiflow/mermin/issues/61)
* reduce the number of arguments to parser default constructor ([#61](https://github.com/elastiflow/mermin/issues/61)) ([1afaa07](https://github.com/elastiflow/mermin/commit/1afaa0763a0cee9b1ef99a4162c1523a1d29d179))

### Bug Fixes

* Add missing release steps ([#79](https://github.com/elastiflow/mermin/issues/79)) ([fcfff7d](https://github.com/elastiflow/mermin/commit/fcfff7d3a9763d390849b025c70626143484d638))
* Clear changelog ([#81](https://github.com/elastiflow/mermin/issues/81)) ([db0adbb](https://github.com/elastiflow/mermin/commit/db0adbb9b7c47f921297e2607af006ba6671cff1))



