# ML-KEM (CRYSTALS-Kyber) + ChaCha20-Poly1305 混合加密库

纯 C99 实现，无第三方加密依赖。包含两条链路：

1. **ML-KEM 密钥封装**（FIPS 203 / CRYSTALS-Kyber），三档参数集 ML-KEM-512 / 768 / 1024，与标准参考实现逐字节互通；
2. **混合加密层**：ML-KEM 协商共享秘密，派生 ChaCha20-Poly1305（RFC 8439）对称密钥，明文按 **64 KiB 分块**独立 AEAD 封装，每块绑定块序号与总块数防重排。

随机源在 Windows 上使用系统 CNG `BCryptGenRandom`（回退 `CryptGenRandom`），Linux 回退 `getrandom`。

## 目录结构

| 路径 | 作用 |
| --- | --- |
| `include/kyber.h` | **公开头**：ML-KEM 密钥对、封装、解封、长度查询 |
| `include/hybrid.h` | **公开头**：KEM + ChaCha20-Poly1305 混合加密、64 KiB 分块与容器序列化 |
| `include/chacha20poly1305.h` | **公开头**：ChaCha20 流密码、Poly1305、RFC 8439 AEAD seal/open |
| `include/kyber_export.h` | 导入/导出可见性宏（公开头内部使用，无需直接引用） |
| `src/` | 全部内部实现与私有头（NTT、多项式向量、CBD、Keccak、约简、cmov、熵源等），第三方无需直接引用 |
| `lib/libkyber.a` | 静态库产物 |
| `lib/kyber.dll` + `lib/libkyber.dll.a` | 动态库产物（DLL + 导入库） |
| `lib/kyber.def` | DLL 导出符号白名单 |
| `examples/example.c` | 最小可运行示例 |
| `tools/filecrypt.c` | 命令行文件/目录混合加密工具（keygen / encrypt / decrypt） |
| `test_kyber.c` | 端到端回归测试 |
| `build.ps1` | 从源码编译并运行回归测试 |
| `build_lib.ps1` | 编译生成 `lib/libkyber.a` 静态库 |
| `build_dll.ps1` | 编译生成 `lib/kyber.dll` 与导入库 |

## 库产物一览

| 形态 | 文件 | 链接方式 |
| --- | --- | --- |
| 静态库 | `lib/libkyber.a` | 编译期链入，产物无外部库依赖 |
| 动态库 | `lib/kyber.dll` + `lib/libkyber.dll.a` | 运行时加载 DLL，链接导入库 |

## 作为静态库使用

### 1. 构建静态库

```powershell
powershell -ExecutionPolicy Bypass -File build_lib.ps1
# 产物：lib/libkyber.a
```

### 2. 第三方工程链接

只需要把 `include/` 目录加入头文件搜索路径，链接 `lib/libkyber.a`（Windows 另需 `advapi32`）：

```bash
gcc -O2 -std=c99 -Wall -Wextra -Wpedantic -DKYBER_STATIC -I include \
    myapp.c -L lib -lkyber -ladvapi32 -o myapp
```

第三方源码仅 `#include "kyber.h"` / `"hybrid.h"` / `"chacha20poly1305.h"`，不引用 `src/` 下任何私有头。

## 作为动态库（DLL）使用

### 1. 构建 DLL

```powershell
powershell -ExecutionPolicy Bypass -File build_dll.ps1
# 产物：lib/kyber.dll、lib/libkyber.dll.a（导入库）
```

DLL 已静态链接 gcc 运行库，外部仅依赖 Windows 系统库 `KERNEL32` / `ADVAPI32` / `msvcrt`，不携带 MinGW 专用运行库 DLL。导出符号由 `lib/kyber.def` 白名单限定，内部实现不对外暴露。

### 2. 第三方工程链接（链接导入库）

```bash
gcc -O2 -std=c99 -Wall -Wextra -Wpedantic -I include \
    myapp.c -L lib -lkyber.dll -ladvapi32 -o myapp
```

运行时把 `kyber.dll` 放到可执行文件同目录（或加入 `PATH`）。头文件默认按 dllimport 处理，无需额外定义宏。

### 3. 从源码直接编译（不产出库）

```bash
gcc -O2 -std=c99 -Wall -Wextra -Wpedantic -DKYBER_STATIC -I include -I src \
    myapp.c src/*.c -ladvapi32 -o myapp
```

编译建议 `-O2`；本机实测 `-O3 -march=native` 触发不利向量化，反而更慢。

## 参数集与标准长度

| 参数集 | k | η1 | η2 | 公钥 | 私钥 | 密文 | 共享秘密 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| ML-KEM-512  | 2 | 3 | 2 | 800 B  | 1632 B | 768 B  | 32 B |
| ML-KEM-768  | 3 | 2 | 2 | 1184 B | 2400 B | 1088 B | 32 B |
| ML-KEM-1024 | 4 | 2 | 2 | 1568 B | 3168 B | 1568 B | 32 B |

## 对外 API（`kyber.h`）

```c
typedef enum { KYBER_512 = 0, KYBER_768 = 1, KYBER_1024 = 2 } kyber_mode;

size_t kyber_pk_len(kyber_mode mode);
size_t kyber_sk_len(kyber_mode mode);
size_t kyber_ct_len(kyber_mode mode);
size_t kyber_ss_len(void);

int kyber_keypair(uint8_t *pk, uint8_t *sk, kyber_mode mode);
int kyber_encaps (uint8_t *ct, uint8_t *ss, const uint8_t *pk, kyber_mode mode);
int kyber_decaps (uint8_t *ss, const uint8_t *ct, const uint8_t *sk, kyber_mode mode);

/* 确定性变体，用于测试 / 与参考向量对拍 */
int kyber_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t coins[64], kyber_mode mode);
int kyber_encaps_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk,
                         const uint8_t coins[32], kyber_mode mode);
```

## 混合加密 API（`hybrid.h`）

```c
#define HYBRID_CHUNK 65536u   /* 64 KiB / 块 */

size_t hybrid_seal_capacity(kyber_mode mode, size_t plainlen);

/* 发送方：用公钥 pk 封装并加密 plain，容器写入 out。
 * out 容量至少 hybrid_seal_capacity(mode, plainlen)；返回容器长度，失败 -1。 */
int hybrid_seal(const uint8_t *pk, kyber_mode mode,
                const uint8_t *plain, size_t plainlen, uint8_t *out);

/* 接收方：用私钥 sk 解封并校验容器，明文写入 out；返回明文长度，失败 -1。 */
int hybrid_open(const uint8_t *sk, kyber_mode mode,
                const uint8_t *container, size_t containerlen, uint8_t *out);
```

### 容器布局（多字节整数均小端）

```
[ KEM 密文                : kyber_ct_len(mode) 字节 ]
[ 会话 nonce 前缀          : 8 字节（系统随机）    ]
[ 总块数                  : uint32               ]
[ 逐块记录：                                    ]
    [ nonce               : 12 字节（前缀 || 块号）]
    [ 块密文长度          : uint32               ]
    [ Poly1305 标签       : 16 字节              ]
    [ 块密文              : 长度字节             ]
```

每块 AAD = 块号（4 B）‖ 总块数（4 B）；对称密钥由共享秘密经 SHA3-512 域分离派生。

## 安全与实现说明

- KEM 解封对非法密钥采用伪随机共享秘密（CCA 语义安全），标签比较为常数时间。
- AEAD 先校验 Poly1305 标签通过后再解密；篡改标签或密文均拒绝。
- 共享秘密、对称密钥在使用后显式清零。
- Poly1305 一次性密钥由 ChaCha20 第 0 块生成，数据从第 1 块加密（RFC 8439）。

## 测试覆盖

- **KEM 互通**：三档与 PQClean clean 参考实现对拍，公钥 / 私钥 / 密文 / 共享秘密逐字节一致，双向交叉解封（参考私钥解本方密文、本方私钥解参考密文）通过。
- **AEAD 标准向量**：ChaCha20 块函数 RFC 8439 A.2.1；Poly1305 A.3 与空消息向量；ChaCha20-Poly1305 A.5.1（含 AAD）密文、标签、往返、篡改拒绝全部通过。
- **混合层回归**：三档空 / 短 / 单块 / 200 KiB 多块往返一致；篡改密文字节被拒绝。

## 性能（同机 vs PQClean clean）

对照对象为 [PQClean](https://github.com/PQClean/PQClean) 的 ML-KEM **clean 纯 C 参考实现**（非 AVX2 SIMD 目录）。同机、同 `-O2 -std=c99`、确定性 `*_derand`、预热 50 次后取 1000 轮平均，单位 µs：

| 档位 | 操作 | 本实现 | PQClean clean | 本实现 / clean |
| --- | --- | --- | --- | --- |
| 512  | KeyGen | 73.95  | 74.35  | 0.99× |
| 512  | Encaps | 83.55  | 83.51  | 1.00× |
| 512  | Decaps | 97.62  | 98.43  | 0.99× |
| 768  | KeyGen | 123.66 | 123.62 | 1.00× |
| 768  | Encaps | 140.26 | 139.00 | 1.01× |
| 768  | Decaps | 157.82 | 157.61 | 1.00× |
| 1024 | KeyGen | 193.10 | 193.24 | 1.00× |
| 1024 | Encaps | 211.37 | 211.43 | 1.00× |
| 1024 | Decaps | 235.41 | 236.52 | 1.00× |

三档三操作均与 clean 参考持平（±1% 内）。测量环境为 32 位 MinGW GCC 9.2；绝对耗时受位数与编译目标影响，表中比值为同机相对结果。未同机对比 PQClean AVX2、OpenSSL 3.5 ML-KEM、liboqs 等 SIMD/封装路径。

## 命令行文件加密工具（`tools/filecrypt.c`）

基于混合加密层的命令行工具，支持单文件与整目录递归加解密，目录结构在加解密后原样保留。

### 子命令

```
filecrypt keygen  [-m 512|768|1024] -pk 公钥文件 -sk 私钥文件
filecrypt encrypt -pk 公钥文件 -in <文件或目录> -out <输出目录>
filecrypt decrypt -sk 私钥文件 -in <文件或目录> -out <输出目录>
```

- `-m` 仅 `keygen` 使用，默认 `768`；encrypt/decrypt 的参数集从密钥文件中读取。
- 公钥可公开分发，私钥必须保密。密钥文件为自描述格式（magic + 用途 + 档位 + 长度 + 原始密钥）。
- 加密产物为 `<原名>.enc` 容器；解密时去掉 `.enc` 后缀还原，无后缀则追加 `.dec`。

### 典型流程

```bash
# 1. 接收方生成密钥对
filecrypt keygen -m 768 -pk pub.key -sk priv.key

# 2. 发送方用公钥加密整个目录
filecrypt encrypt -pk pub.key -in docs -out docs_enc

# 3. 接收方用私钥解密整个目录
filecrypt decrypt -sk priv.key -in docs_enc -out docs_dec
```

### 编译

链接静态库：

```bash
gcc -O2 -std=c99 -Wall -Wextra -Wpedantic -DKYBER_STATIC -I include \
    tools/filecrypt.c lib/libkyber.a -ladvapi32 -o filecrypt.exe
```

链接 DLL（运行时需 `kyber.dll` 在 exe 同目录）：

```bash
gcc -O2 -std=c99 -Wall -Wextra -Wpedantic -I include \
    tools/filecrypt.c lib/libkyber.dll.a -ladvapi32 -o filecrypt.exe
```

### 已验证场景

空文件、短文本、200 KiB 多块文件、子目录递归、中文文件名，三档参数集往返字节一致；篡改密文字节、使用错误私钥均在解封阶段被常数时间拒绝。当前按整文件读入内存处理，单文件体积受可用内存限制。

## 平台与限制

- 仅实现 FIPS 203 ML-KEM 与 RFC 8439 AEAD；未包含密钥协商协议层、持久化格式或流式大文件接口。
- 纯 C 可移植路径，未使用 SIMD 汇编；高性能场景可另行追加 AVX2 路径。
- `libkyber.a` 与 `kyber.dll` 均由 MinGW gcc 生成（COFF 归档 / PE），供 MinGW / Clang 链接；MSVC（Visual Studio）建议直接把 `src/*.c` 加入工程编译，或用 `cl` 重新构建，不直接消费 MinGW 归档与导入库。
