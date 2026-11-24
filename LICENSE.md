# Nodus-CLI 开源协议与第三方依赖登记

作者：可莉唯一的狗

Nodus-CLI 自有代码采用 MIT 许可协议（见 [LICENSE](LICENSE)）；所接入的 `Nodus-Core`（`1.0.0-dev`）采用 MIT 许可协议，第三方依赖适用各自的上游宽松协议。

## 一、Nodus-CLI 直接依赖选用许可登记

| 组件 | 锁定版本 | 来源 | 上游 SPDX 许可表达式 | Nodus-CLI 实际选用许可 | 原文与声明出处 |
| --- | --- | --- | --- | --- | --- |
| `Nodus-Core` (`nodus_core`) | `1.0.0-dev`（基线提交 `c60587d1`，含本地未提交联调改动） | 本地路径 `../Nodus Core` (`https://github.com/teaoea/Nodus-Core`) | `MIT` | `MIT` | `../Nodus Core/LICENSE` |
| `serde` | `=1.0.228` | `crates.io` (`Cargo.lock`) | `MIT OR Apache-2.0` | `MIT` | Cargo registry 源码 `LICENSE-MIT` |
| `serde_json` | `=1.0.149` | `crates.io` (`Cargo.lock`) | `MIT OR Apache-2.0` | `MIT` | Cargo registry 源码 `LICENSE-MIT` |
| `zeroize` | `=1.9.0` | `crates.io` (`Cargo.lock`) | `Apache-2.0 OR MIT` | `MIT` | Cargo registry 源码 `LICENSE-MIT` |
| `nix` | `=0.31.3` | `crates.io` (`Cargo.lock`) | `MIT` | `MIT` | `notices/nix-0.31.3/LICENSE` |

## 二、全部锁定依赖与传递依赖清单（`Cargo.lock` 固定）

本节列出 `Nodus-CLI` 与 `Nodus-Core` 联合锁定的全部依赖组件版本与协议声明（随附许可证原文与 NOTICE 保留于 `notices/` 目录）。协议中的 `OR` 表示可选协议（均选用其中的 `MIT`、`BSD`、`ISC`、`Zlib` 或 `Apache-2.0` 宽松路径），`AND` 表示同时满足的宽松协议组合。

| 组件                       | 版本                          | 开源协议                                            |
| -------------------------- | ----------------------------- | --------------------------------------------------- |
| adler2 | 2.0.1 | 0BSD OR MIT OR Apache-2.0 |
| alloc-no-stdlib | 2.0.4 | BSD-3-Clause |
| brotli-decompressor | 5.0.3 | BSD-3-Clause OR MIT |
| crc32fast | 1.5.2 | MIT OR Apache-2.0 |
| flate2 | 1.1.9 | MIT OR Apache-2.0 |
| miniz_oxide | 0.8.9 | MIT OR Zlib OR Apache-2.0 |
| simd-adler32 | 0.3.10 | MIT |
| aes | 0.8.4 | MIT OR Apache-2.0 |
| arrayvec | 0.7.8 | MIT OR Apache-2.0 |
| blake3 | 1.8.7 | CC0-1.0 OR Apache-2.0 OR Apache-2.0 WITH LLVM-exception |
| constant_time_eq | 0.4.2 | CC0-1.0 OR MIT-0 OR Apache-2.0 |
| md-5 | 0.10.6 | MIT OR Apache-2.0 |
| cpufeatures                | 0.2.17                        | MIT OR Apache-2.0                                   |
| curve25519-dalek           | 4.1.3                         | BSD-3-Clause                                        |
| curve25519-dalek-derive    | 0.1.1                         | MIT/Apache-2.0                                      |
| fiat-crypto                | 0.2.9                         | MIT OR Apache-2.0 OR BSD-1-Clause                   |
| rand_core                  | 0.6.4                         | MIT OR Apache-2.0                                   |
| x25519-dalek               | 2.0.1                         | BSD-3-Clause                                        |
| zeroize_derive             | 1.5.0                         | Apache-2.0 OR MIT                                   |
| block-buffer               | 0.12.1                        | MIT OR Apache-2.0                                   |
| cmov                       | 0.5.4                         | Apache-2.0 OR MIT                                   |
| crypto-common              | 0.2.2                         | MIT OR Apache-2.0                                   |
| ctutils                    | 0.4.3                         | Apache-2.0 OR MIT                                   |
| digest                     | 0.11.3                        | MIT OR Apache-2.0                                   |
| hybrid-array               | 0.4.15                        | MIT OR Apache-2.0                                   |
| keccak                     | 0.2.2                         | Apache-2.0 OR MIT                                   |
| kem                        | 0.3.0                         | Apache-2.0 OR MIT                                   |
| ml-kem                     | 0.3.2                         | Apache-2.0 OR MIT                                   |
| module-lattice             | 0.2.3                         | Apache-2.0 OR MIT                                   |
| sha3                       | 0.11.0                        | MIT OR Apache-2.0                                   |
| typenum                    | 1.20.1                        | MIT OR Apache-2.0                                   |
| aho-corasick               | 1.1.4                         | Unlicense OR MIT                                    |
| arraydeque                 | 0.5.1                         | MIT/Apache-2.0                                      |
| hashlink                   | 0.12.2                        | MIT OR Apache-2.0                                   |
| yaml-rust2                 | 0.13.0                        | MIT OR Apache-2.0                                   |
| QuickJS                    | 随 rquickjs-sys 内嵌          | MIT                                                 |
| allocator-api2             | 0.2.21                        | MIT OR Apache-2.0                                   |
| asn1-rs                    | 0.7.2                         | MIT OR Apache-2.0                                   |
| asn1-rs-derive             | 0.6.0                         | MIT OR Apache-2.0                                   |
| asn1-rs-impl               | 0.2.0                         | MIT/Apache-2.0                                      |
| atomic-waker               | 1.1.2                         | Apache-2.0 OR MIT                                   |
| autocfg                    | 1.5.1                         | Apache-2.0 OR MIT                                   |
| base64                     | 0.23.1                        | MIT OR Apache-2.0                                   |
| bit-vec                    | 0.9.1                         | Apache-2.0 OR MIT                                   |
| bitflags                   | 2.13.2                        | MIT OR Apache-2.0                                   |
| bytes                      | 1.12.1                        | MIT                                                 |
| cc                         | 1.6.0                         | MIT OR Apache-2.0                                   |
| cfg-if                     | 1.0.5                         | MIT OR Apache-2.0                                   |
| core-foundation            | 0.10.1                        | MIT OR Apache-2.0                                   |
| core-foundation-sys        | 0.8.7                         | MIT OR Apache-2.0                                   |
| cpufeatures                | 0.3.1                         | MIT OR Apache-2.0                                   |
| data-encoding              | 2.11.1                        | MIT                                                 |
| der-parser                 | 10.0.0                        | MIT OR Apache-2.0                                   |
| deranged                   | 0.5.8                         | MIT OR Apache-2.0                                   |
| displaydoc                 | 0.2.7                         | MIT OR Apache-2.0                                   |
| either                     | 1.19.0                        | MIT OR Apache-2.0                                   |
| equivalent                 | 1.0.2                         | Apache-2.0 OR MIT                                   |
| find-msvc-tools            | 0.1.14                        | MIT OR Apache-2.0                                   |
| fnv                        | 1.0.7                         | Apache-2.0 / MIT                                    |
| foldhash                   | 0.2.0                         | Zlib                                                |
| form_urlencoded            | 1.2.2                         | MIT OR Apache-2.0                                   |
| futures-core               | 0.3.34                        | MIT OR Apache-2.0                                   |
| futures-sink               | 0.3.34                        | MIT OR Apache-2.0                                   |
| getrandom                  | 0.2.17                        | MIT OR Apache-2.0                                   |
| h2                         | 0.4.20                        | MIT                                                 |
| hashbrown                  | 0.17.1                        | MIT OR Apache-2.0                                   |
| http                       | 1.4.2                         | MIT OR Apache-2.0                                   |
| httparse                   | 1.10.1                        | MIT OR Apache-2.0                                   |
| icu_collections            | 2.3.0                         | Unicode-3.0                                         |
| icu_locale_core            | 2.3.0                         | Unicode-3.0                                         |
| icu_normalizer             | 2.3.0                         | Unicode-3.0                                         |
| icu_normalizer_data        | 2.3.0                         | Unicode-3.0                                         |
| icu_properties             | 2.3.0                         | Unicode-3.0                                         |
| icu_properties_data        | 2.3.0                         | Unicode-3.0                                         |
| icu_provider               | 2.3.1                         | Unicode-3.0                                         |
| idna                       | 1.1.0                         | MIT OR Apache-2.0                                   |
| idna_adapter               | 1.2.2                         | Apache-2.0 OR MIT                                   |
| indexmap                   | 2.14.2                        | Apache-2.0 OR MIT                                   |
| itoa                       | 1.0.18                        | MIT OR Apache-2.0                                   |
| lazy_static                | 1.5.1                         | MIT OR Apache-2.0                                   |
| libc                       | 0.2.190                       | MIT OR Apache-2.0                                   |
| litemap                    | 0.8.3                         | Unicode-3.0                                         |
| lock_api                   | 0.4.14                        | MIT OR Apache-2.0                                   |
| log                        | 0.4.34                        | MIT OR Apache-2.0                                   |
| memmap2                   | 0.9.9                         | MIT OR Apache-2.0                                   |
| memchr                     | 2.8.3                         | Unlicense OR MIT                                    |
| minimal-lexical            | 0.2.1                         | MIT/Apache-2.0                                      |
| mio                        | 1.2.4                         | MIT                                                 |
| nom                        | 7.1.3                         | MIT                                                 |
| num-bigint                 | 0.4.8                         | MIT OR Apache-2.0                                   |
| num-conv                   | 0.2.2                         | MIT OR Apache-2.0                                   |
| num-integer                | 0.1.47                        | MIT OR Apache-2.0                                   |
| num-traits                 | 0.2.19                        | MIT OR Apache-2.0                                   |
| oid-registry               | 0.8.1                         | MIT OR Apache-2.0                                   |
| once_cell                  | 1.21.4                        | MIT OR Apache-2.0                                   |
| openssl-probe              | 0.2.1                         | MIT OR Apache-2.0                                   |
| parking_lot                | 0.12.5                        | MIT OR Apache-2.0                                   |
| parking_lot_core           | 0.9.12                        | MIT OR Apache-2.0                                   |
| pem                        | 4.0.0                         | MIT                                                 |
| percent-encoding           | 2.3.2                         | MIT OR Apache-2.0                                   |
| pin-project-lite           | 0.2.17                        | Apache-2.0 OR MIT                                   |
| portable-atomic            | 1.15.0                        | Apache-2.0 OR MIT                                   |
| potential_utf              | 0.1.6                         | Unicode-3.0                                         |
| powerfmt                   | 0.2.1                         | MIT OR Apache-2.0                                   |
| proc-macro2                | 1.0.107                       | MIT OR Apache-2.0                                   |
| quote                      | 1.0.47                        | MIT OR Apache-2.0                                   |
| rand_core                  | 0.10.1                        | MIT OR Apache-2.0                                   |
| rcgen                      | 0.14.10                       | MIT OR Apache-2.0                                   |
| redox_syscall              | 0.5.18                        | MIT                                                 |
| ring                       | 0.17.14                       | Apache-2.0 AND ISC                                  |
| rquickjs                   | 0.14.0                        | MIT                                                 |
| rquickjs-core              | 0.14.0                        | MIT                                                 |
| rquickjs-sys               | 0.14.0                        | MIT                                                 |
| rustc_version              | 0.4.1                         | MIT OR Apache-2.0                                   |
| rusticata-macros           | 4.1.0                         | MIT/Apache-2.0                                      |
| rustls                     | 0.23.44                       | Apache-2.0 OR ISC OR MIT                            |
| rustls-native-certs        | 0.8.4                         | Apache-2.0 OR ISC OR MIT                            |
| rustls-pki-types           | 1.15.1                        | MIT OR Apache-2.0                                   |
| rustls-webpki              | 0.103.15                      | ISC                                                 |
| schannel                   | 0.1.29                        | MIT                                                 |
| scopeguard                 | 1.2.0                         | MIT OR Apache-2.0                                   |
| security-framework         | 3.7.0                         | MIT OR Apache-2.0                                   |
| security-framework-sys     | 2.17.0                        | MIT OR Apache-2.0                                   |
| semver                     | 1.0.28                        | MIT OR Apache-2.0                                   |
| serde                      | 1.0.228                       | MIT OR Apache-2.0                                   |
| serde_core                 | 1.0.228                       | MIT OR Apache-2.0                                   |
| serde_derive               | 1.0.228                       | MIT OR Apache-2.0                                   |
| serde_json                 | 1.0.149                       | MIT OR Apache-2.0                                   |
| shlex                      | 2.0.1                         | MIT OR Apache-2.0                                   |
| slab                       | 0.4.12                        | MIT                                                 |
| smallvec                   | 1.16.1                        | MIT OR Apache-2.0                                   |
| socket2                    | 0.6.5                         | MIT OR Apache-2.0                                   |
| stable_deref_trait         | 1.2.1                         | MIT OR Apache-2.0                                   |
| subtle                     | 2.6.1                         | BSD-3-Clause                                        |
| syn                        | 2.0.119                       | MIT OR Apache-2.0                                   |
| syn                        | 3.0.6                         | MIT OR Apache-2.0                                   |
| synstructure               | 0.13.2                        | MIT                                                 |
| thiserror                  | 2.0.21                        | MIT OR Apache-2.0                                   |
| thiserror-impl             | 2.0.21                        | MIT OR Apache-2.0                                   |
| time                       | 0.3.55                        | MIT OR Apache-2.0                                   |
| time-core                  | 0.1.9                         | MIT OR Apache-2.0                                   |
| time-macros                | 0.2.32                        | MIT OR Apache-2.0                                   |
| tinystr                    | 0.8.4                         | Unicode-3.0                                         |
| tokio                      | 1.53.1                        | MIT                                                 |
| tokio-macros               | 2.7.2                         | MIT                                                 |
| tokio-rustls               | 0.26.5                        | MIT OR Apache-2.0                                   |
| tokio-util                 | 0.7.20                        | MIT                                                 |
| tracing                    | 0.1.44                        | MIT                                                 |
| tracing-core               | 0.1.36                        | MIT                                                 |
| unicode-ident              | 1.0.26                        | (MIT OR Apache-2.0) AND Unicode-3.0                 |
| untrusted                  | 0.9.0                         | ISC                                                 |
| url                        | 2.5.8                         | MIT OR Apache-2.0                                   |
| utf8_iter                  | 1.0.4                         | Apache-2.0 OR MIT                                   |
| wasi                       | 0.11.1+wasi-snapshot-preview1 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT |
| windows-link               | 0.2.1                         | MIT OR Apache-2.0                                   |
| windows-sys                | 0.52.0                        | MIT OR Apache-2.0                                   |
| windows-sys                | 0.61.2                        | MIT OR Apache-2.0                                   |
| windows-targets            | 0.52.6                        | MIT OR Apache-2.0                                   |
| windows_aarch64_gnullvm    | 0.52.6                        | MIT OR Apache-2.0                                   |
| windows_aarch64_msvc       | 0.52.6                        | MIT OR Apache-2.0                                   |
| windows_i686_gnu           | 0.52.6                        | MIT OR Apache-2.0                                   |
| windows_i686_gnullvm       | 0.52.6                        | MIT OR Apache-2.0                                   |
| windows_i686_msvc          | 0.52.6                        | MIT OR Apache-2.0                                   |
| windows_x86_64_gnu         | 0.52.6                        | MIT OR Apache-2.0                                   |
| windows_x86_64_gnullvm     | 0.52.6                        | MIT OR Apache-2.0                                   |
| windows_x86_64_msvc        | 0.52.6                        | MIT OR Apache-2.0                                   |
| writeable                  | 0.6.4                         | Unicode-3.0                                         |
| x509-parser                | 0.18.1                        | MIT OR Apache-2.0                                   |
| yasna                      | 0.6.0                         | MIT OR Apache-2.0                                   |
| yoke                       | 0.8.3                         | Unicode-3.0                                         |
| yoke-derive                | 0.8.2                         | Unicode-3.0                                         |
| zerofrom                   | 0.1.8                         | Unicode-3.0                                         |
| zerofrom-derive            | 0.1.7                         | Unicode-3.0                                         |
| zeroize                    | 1.9.0                         | Apache-2.0 OR MIT                                   |
| zerotrie                   | 0.2.5                         | Unicode-3.0                                         |
| zerovec                    | 0.11.8                        | Unicode-3.0                                         |
| zerovec-derive             | 0.11.6                        | Unicode-3.0                                         |
| zmij                       | 1.0.23                        | MIT                                                 |
| psl                        | 2.1.238                       | MIT/Apache-2.0                                      |
| psl-types                  | 2.0.11                        | MIT/Apache-2.0                                      |
| libproc                    | 0.14.11                       | MIT                                                 |
| bindgen                    | 0.72.1                        | BSD-3-Clause                                        |
| cexpr                      | 0.6.0                         | Apache-2.0/MIT                                      |
| clang-sys                  | 1.9.1                         | Apache-2.0                                          |
| glob                       | 0.3.4                         | MIT OR Apache-2.0                                   |
| itertools                  | 0.13.0                        | MIT OR Apache-2.0                                   |
| libloading                 | 0.8.9                         | ISC                                                 |
| regex                      | 1.13.1                        | MIT OR Apache-2.0                                   |
| regex-automata             | 0.4.18                        | MIT OR Apache-2.0                                   |
| regex-syntax               | 0.8.11                        | MIT OR Apache-2.0                                   |
| rustc-hash                 | 2.1.3                         | Apache-2.0 OR MIT                                   |
| shlex                      | 1.3.0                         | MIT OR Apache-2.0                                   |
| errno                      | 0.3.14                        | MIT OR Apache-2.0                                   |
| convert_case               | 0.12.0                        | MIT                                                 |
| ipnetwork                  | 0.21.1                        | MIT OR Apache-2.0                                   |
| maxminddb                  | 0.32.0                        | ISC                                                 |
| prettyplease               | 0.2.37                        | MIT OR Apache-2.0                                   |
| proc-macro-crate           | 3.5.0                         | MIT OR Apache-2.0                                   |
| relative-path              | 2.0.2                         | MIT OR Apache-2.0                                   |
| rquickjs-macro             | 0.14.0                        | MIT                                                 |
| toml_datetime              | 1.1.1+spec-1.1.0              | MIT OR Apache-2.0                                   |
| toml_edit                  | 0.25.15+spec-1.1.0            | MIT OR Apache-2.0                                   |
| toml_parser                | 1.1.3+spec-1.1.0              | MIT OR Apache-2.0                                   |
| unicode-segmentation       | 1.13.3                        | MIT OR Apache-2.0                                   |
| winnow                     | 1.0.4                         | MIT                                                 |

## 协议密码基础依赖（Cargo.lock固定）

| 组件             | 版本   | SPDX              |
| ---------------- | ------ | ----------------- |
| aead             | 0.5.2  | MIT OR Apache-2.0 |
| block-buffer     | 0.10.4 | MIT OR Apache-2.0 |
| chacha20         | 0.9.1  | Apache-2.0 OR MIT |
| chacha20poly1305 | 0.10.1 | Apache-2.0 OR MIT |
| cipher           | 0.4.4  | MIT OR Apache-2.0 |
| crypto-common    | 0.1.7  | MIT OR Apache-2.0 |
| digest           | 0.10.7 | MIT OR Apache-2.0 |
| generic-array    | 0.14.7 | MIT               |
| hmac             | 0.12.1 | MIT OR Apache-2.0 |
| inout            | 0.1.4  | MIT OR Apache-2.0 |
| opaque-debug     | 0.3.1  | MIT OR Apache-2.0 |
| poly1305         | 0.8.0  | Apache-2.0 OR MIT |
| sha2             | 0.10.9 | MIT OR Apache-2.0 |
| universal-hash   | 0.5.1  | MIT OR Apache-2.0 |
| version_check    | 0.9.5  | MIT/Apache-2.0    |

## 其他已锁定依赖

系统 DNS 配置由平台模块只读调用原生 API 或读取系统文件，不再链接专用 DNS 解析或系统 DNS 适配库。以下仍为其他模块实际使用的锁定依赖。

| 组件 | 版本 | 上游 SPDX 声明 |
| --- | --- | --- |
| base64 | 0.22.1 | MIT OR Apache-2.0 |
| blake2 | 0.10.6 | MIT OR Apache-2.0 |
| boringtun | 0.7.1 | BSD-3-Clause |
| cfg_aliases | 0.2.2 | MIT |
| hex | 0.4.3 | MIT OR Apache-2.0 |
| ip_network | 0.4.1 | BSD-2-Clause |
| ip_network_table | 0.2.0 | BSD-2-Clause |
| ip_network_table-deps-treebitmap | 0.5.0 | MIT |
| nix | 0.31.3 | MIT |
| tracing-attributes | 0.1.31 | MIT |

## 浏览器模板公开字段来源

四类TLS ClientHello模板的公开字段与版本映射参考uTLS提交`aa6edf4b11af`（BSD-3-Clause），未链接或引入Go/uTLS库；保留上游声明于`notices/utls/LICENSE`，固定来源见`notices/utls/SOURCE.md`。不改变其他依赖许可或历史自有源码许可证。

HTTP/2主动请求与解密复用已锁定的h2 0.4.20（MIT）、bytes 1.12.1（MIT）及http 1.4.2（选择MIT）作为直接生产依赖；来源和原文沿用上表及notices登记，未升级或新增传递依赖。独立测试对端使用外部Node.js的内置http2/nghttp2，不打包进Core产物。
