## [v0.1.0-beta.49] - 2026-02-05

### Bug Fixes

- Ensure tcp stats and icmp stats metrics are tracked correctly (#425)
- Independent src and dst association blocks (#423)
- Remove standard globs for non-string filters (#411)
### Features

- **metrics:** Add read ops metric for flow events (#426)
- **metrics:** Remove ebpf map_bytes_total, add flow_stats ops tracking (#428)

[v0.1.0-beta.48..v0.1.0-beta.49](https://github.com/elastiflow/mermin/compare/v0.1.0-beta.48...v0.1.0-beta.49)



## [v0.1.0-beta.48] - 2026-02-03

### Bug Fixes

- **health:** Remove unused metrics and streamline health checks (#417)

[v0.1.0-beta.47..v0.1.0-beta.48](https://github.com/elastiflow/mermin/compare/v0.1.0-beta.47...v0.1.0-beta.48)



## [v0.1.0-beta.47] - 2026-02-03

### Features

- **pipeline:** Restructure pipeline configuration (#395)
- Flowstats protocol-specific maps (#375)
- **metrics:** Housekeeping items (#401)
- Add ring buffer size metrics via mmap producer/consumer positions (#416)

[v0.1.0-beta.46..v0.1.0-beta.47](https://github.com/elastiflow/mermin/compare/v0.1.0-beta.46...v0.1.0-beta.47)



re## [v0.1.0-beta.46] - 2026-01-27

### Bug Fixes

- Simplify copying sources for docker build (#397)
- Mermin wrongfully detects pod ip (#399)
### Features

- Add direction-aware container attributes with port-based resolution (#392)

[v0.1.0-beta.45..v0.1.0-beta.46](https://github.com/elastiflow/mermin/compare/v0.1.0-beta.45...v0.1.0-beta.46)



## [v0.1.0-beta.45] - 2026-01-20

### Bug Fixes

- Add missing "commonLabels" (#393)
### Features

- Add docker hub as an upload target for mermin docker images (#371)

[v0.1.0-beta.44..v0.1.0-beta.45](https://github.com/elastiflow/mermin/compare/v0.1.0-beta.44...v0.1.0-beta.45)



## [v0.1.0-beta.44] - 2026-01-15

### Features

- Add "priorityClassName" (#383)

[v0.1.0-beta.43..v0.1.0-beta.44](https://github.com/elastiflow/mermin/compare/v0.1.0-beta.43...v0.1.0-beta.44)



## [v0.1.0-beta.43] - 2026-01-13

### Features

- Add bytesize dependency and enhance ebpf ring buffer configuration (#365)
- **config:** Ensure attributes metadata can be set individually (#369)
- **provider:** Add http support to output (#363)
- Address metrics improvements (#368)
- **enrichment:** Tcp time-based metrics (#358)

[v0.1.0-beta.42..v0.1.0-beta.43](https://github.com/elastiflow/mermin/compare/v0.1.0-beta.42...v0.1.0-beta.43)



er ## [v0.1.0-beta.42] - 2025-12-22

### Features

- Mermin tcx log (#357)
- Add mermin subcomands to test ebpf filesystem (#298)
- Support k8s annotations (#361)

[v0.1.0-beta.41..v0.1.0-beta.42](https://github.com/elastiflow/mermin/compare/v0.1.0-beta.41...v0.1.0-beta.42)



## [v0.1.0-beta.41] - 2025-12-12

### Bug Fixes

- Update the base image to Debian 13 (#350)
### Features

- Add client/server direction inference with semantic conventions (#347)
- **enrichment:** Connection state (#351)

[v0.1.0-beta.40..v0.1.0-beta.41](https://github.com/elastiflow/mermin/compare/v0.1.0-beta.40...v0.1.0-beta.41)



## [v0.1.0-beta.40] - 2025-12-05

### Features

- Release beta.40 (#342)

[v0.1.0-beta.39..v0.1.0-beta.40](https://github.com/elastiflow/mermin/compare/v0.1.0-beta.39...v0.1.0-beta.40)
