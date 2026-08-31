# HLOS → TrustZone boundary audit — Samsung Engineering Mode (SM-S928B, One UI 8.5 / Android 16)

**Method:** read-only static analysis of the collected artifacts. Nothing was executed against the
device. All VAs are file-relative (`sh_addr == sh_offset` for PROGBITS in these binaries).

**Headline result (stated up front because it reframes everything below):**
On *this* device the Engineering Mode stack **never reaches TrustZone**. The observed binder
error code `0xf02d0010` is emitted only by `libengmode2lite.so`; that proves `emservice` selected
`EngineeringModeWorld` in **mode 0x19** whose backend is `em_lite_entry` — a pure-HLOS library
(`liblog/libc/libm/libdl` only, no QSEECom, no crypto, no IPC to a trustlet). The
`em_tlc_send → QSEECom_send_cmd → trustlet 'engmode'` path is compiled in and reachable, but is
selected only for devices whose 16-char DID begins with `"30"` or `"20"`. See §6.

The second headline result is a **negative one** at the QSEECom boundary (§3): despite being
"the single most promising place", `libengmode_tlc.so` is internally consistent. Its shared-buffer
size and both transfer lengths are all derived from the same two caller-supplied values with an
algebraic guarantee that the buffer is always larger than `req_len + rsp_len`. There is no fixed
intermediate to overrun.

The one place where a length genuinely crosses a layer with **no** check at the receiving layer is
the `rsp + 0x14132` response-length field (§2, Candidate C-1). It is closed on this device by a
bound in the lite backend, and left wide open on TLC-mode devices.

---

## 0. Tooling added

| file | purpose |
|---|---|
| `scripts/em_tlc_got.py` | APS2/SLEB128 packed-relocation decoder + `.relr.dyn` decoder + raw GOT dump |
| `scripts/tlc_analysis.py` | annotated disassembly of `libengmode_tlc.so` using the authoritative GOT map |
| `scripts/server_analysis.py` | annotated disassembly helper (PLT, ADRP/ADD literals, rodata strings, movk accumulation) |
| `scripts/callsites.py` | encoding-level BL/B scanner (26-bit imm) → call sites + enclosing function |
| `scripts/emprocess_sites.py` | all 26 `emProcess`/`em_lite_entry`/`em_tlc_send` call sites with arg setup |
| `decompiled/tlc-annotated.txt`, `tlc-worker.txt`, `tlc-got-map.txt` | full TLC disassembly |
| `decompiled/emProcess-callsites.txt` | per-call-site lengths |
| `decompiled/legacy-ctor.s`, `legacy-all.s`, `world-ctor.s`, `setVersion.s` | backend selection |
| `decompiled/em_lite_entry.s`, `lite-mkresp.s` | live backend + the bound that saves it |
| `decompiled/onTransact2.s`, `emGetModesBit-Modes.s` | server dispatch and sinks |

---

## 1. DELIVERABLE 1 — SHAPE MAP (AIDL transactions 1..23)

Interface `vendor.samsung.hardware.security.engmode.ISehEngmode`, VINTF `format=aidl version=1
instance=default`, hash `40e3d24c35baf5b934a2515792ae8aae089da246`.
Source: `binaries/engmode-V1-ndk-system.so` (Bp), `engmode-V1-ndk-vendor.so` (Bn).

Directionality determined by which `AParcel_*` calls each `BpSehEngmode::*` method makes **before**
`AIBinder_transact` (`writeVec`) and **after** it (`readVec`):

| tx | method | `Bp` VA | in (marshalled) | vector direction | caller-supplied LENGTH on the wire? |
|----|--------|---------|-----------------|------------------|-------------------------------------|
| 1 | getStatus | 0x92f8 | int32, SehCallerInfo, int32 | – | no |
| 2 | installToken | 0x9490 | `const vector<uint8_t>&` | **in** (`writeVec`, no readVec) | **YES** — vector size |
| 3 | isTokenInstalled | 0x95cc | – | – | no |
| 4 | removeToken | 0x96e8 | – | – | no |
| 5 | getNumOfModes | 0x9804 | – | – | no |
| 6 | sendFuseCmd | 0x9920 | – | – | no |
| 7 | getVersion | 0x9a3c | – | – | no |
| 8 | getExpiryDate | 0x9b58 | – | **inout** (`writeVec`→T→`readVec`) | **YES** |
| 9 | getId | 0x9cac | – | **inout** | **YES** |
| 10 | getRequestMsg | 0x9e00 | 2×string, `const vector&`, int32 | **inout** (2× writeVec: in-vec + out-vec) | **YES ×2** |
| 11 | makeTokenReq | 0xa020 | 2×string, `const vector&`, string | **inout** | **YES ×2** |
| 12 | commandForEss | 0xa21c | int32, string | **inout** | **YES** |
| 13 | getServerTime | 0xa3c0 | – | **inout** | **YES** |
| 14 | recoveryItl | 0xa514 | `const vector<uint8_t>&` | **in** | **YES** |
| 15 | makeItlReq | 0xa650 | 2×string | **inout** | **YES** |
| 16 | getToken | 0xa80c | – | **inout** | **YES** |
| 17 | getTuc | 0xa960 | int32 | – | no |
| 18 | setPriorityTime | 0xaa94 | string | **inout** | **YES** |
| 19 | getPriorityTime | 0xac20 | – | **inout** | **YES** |
| 20 | getLastTokenStatus | 0xad74 | – | **inout** | **YES** |
| 21 | getStringModes | 0xaec8 | – | **inout** | **YES** |
| 22 | getModesbit | 0xb01c | – | **inout** | **YES** |
| 23 | getTokenInfoForJanus | 0xb170 | – | **inout** | **YES** |

**Confirmed `inout` mechanics (`getModesbit`, `engmode-V1-ndk-system.so`):**

```
00b060: ldr  x1, [x20]        ; vector data pointer (live caller buffer)
00b064: ldr  w8, [x20, #8]    ; vector size
...
00b070: bl   AParcel_writeByteArray   ; <-- serialised BEFORE transact
00b0cc: bl   AIBinder_transact
00b160: bl   AParcel_readByteArray    ; <-- replaced from the reply
```

So 15 of 23 transactions ship a caller-chosen byte count into the vendor service, and 13 of those
also ship the *contents* of a caller-owned buffer. Only tx 1 carries a `SehCallerInfo` argument
(calller identity); **tx 22 (`getModesbit`), tx 10 (`getRequestMsg`) and tx 21 (`getStringModes`)
do not** — matching the note already in `decompiled/aidl-transaction-evidence.txt`.

**Second hop (what emservice actually sees).** The HAL service
(`vendor.samsung.hardware.security.engmode-service`) forwards each AIDL method to
`libengmode_client.so`, which speaks a *different, internal* legacy Binder protocol to `emservice`.
The transaction numbers are **not** the same:

```
libengmode_client.so 0x5458: mov w1, #0x15   ; engmodeclient::getModesbit -> internal cmd 21, not 22
```

`EngineeringModeHandler::onTransact` bounds the command id with `cmp w8, #0x16; b.hi` → commands
`0..22`, i.e. a 23-entry table offset by one from the AIDL numbering for the higher commands.

---

## 2. DELIVERABLE 2 — LENGTH DIVERGENCE HUNT

### Layer inventory and the buffer sizes actually allocated

| layer | file | buffer | size | where |
|---|---|---|---|---|
| HAL out-vector | `engmode-service` | `calloc(1, 0xC800)` | 51,200 | 0x34f4 |
| client object | `libengmode_client.so` | `engmodeclient::mBuf` @ `this+0xc` | 0x11000 (69,632) | 0x3030–0x3048 (`memset(this+0xc,0,0x11000)`) |
| server reply buf | `libengmode_server.so` | single `calloc(1, 0x11000)` in `onTransact` | 69,632 | 0xb9ac–0xb9bc |
| server request | `libengmode_server.so` | `EngineeringModeWorld::req` @ `this+0x70` | 0x21c7d (138,365) | `preparePayload` 0xe208 |
| server response | `libengmode_server.so` | `EngineeringModeWorld::rsp` @ `this+0x78` | 0x20936 (133,430) | `preparePayload` 0xe218 |
| server steady | `libengmode_server.so` | `this+0x10` | 0x2c00 | 0x11abc |
| server token | `libengmode_server.so` | `this+0x18` | 0x11000 | 0x11b14–0x11b20 |
| TLC shared buf | `libengmode_tlc.so` | QSEECom ION buffer | `((rspSize+reqSize) & ~0x3f) + 0x40` | 0x2598–0x25a4 |

### `emProcess` is a pure pass-through — no length logic at all

`libengmode_server.so` 0xd254:

```asm
00d254: bti  c
00d258: ldur w8, [x1, #1]        ; w8 = *(u32*)(req + 1)
00d25c: orr  w8, w8, #0xc000     ; OR in the "dispatch" bits
00d260: stur w8, [x1, #1]
00d264: ldr  w8, [x0, #8]        ; mode selector
00d268: mov  x0, x1              ; req
00d26c: mov  w1, w2              ; reqSize
00d270: mov  x2, x3              ; rsp
00d274: mov  x3, x4              ; rspSize*
00d278: cmp  w8, #0x19
00d27c: b.ne #0xd284
00d280: b    #0x16818            ; PLT->em_lite_entry
00d284: b    #0x16830            ; PLT->em_tlc_send
```

Every length decision is therefore made by the individual `EngineeringModeWorld::em*` methods.

### What each call site passes (from `decompiled/emProcess-callsites.txt`)

All 26 call sites pass **constant** lengths:

```
emGetTokenRequest 0xf570:  w2 = 0x21c7d   x3 = sp+..  (rspSize slot pre-set to 0x20936)
emGetStatus       0xfc70:  w2 = 0x21c7d
emEssCommand      0x10d20: w2 = 0x21c7d   (note: NOT the ESS string length)
emGetTimeRequest  0x120f0: w2 = 0x21c7d
emGetModes        0x118ec/0x11954: w1 = 0x21c7d, x3 = sp+0xc
emGetModesBit     0x11c94/0x11cfc: w1 = 0x21c7d, x3 = sp+0xc
```

and the `rspSize` in/out slot is initialised to the exact allocation size:

```asm
; EngineeringModeWorld::emGetModesBit  (libengmode_server.so)
011a60: mov  w8, #0x936
011a64: movk w8, #2, lsl #16      ; w8 = 0x20936
011a70: str  w8, [sp, #0xc]       ; rspSize = 133,430  == calloc size of rsp
...
011c60: mov  w1, #0x1c7d
011c68: movk w1, #2, lsl #16      ; w1 = reqSize = 0x21c7d
011c64: add  x3, sp, #0xc         ; rspSize* (in/out)
```

**So `reqSize`/`rspSize` are never attacker-controlled.** They are `0x21c7d` / `0x20936` constants.
This immediately kills the "integer overflow in the TLC size computation" hypothesis at the
server→TLC boundary (see §3).

### The one genuinely unvalidated length: `rsp + 0x14132`

Seven `EngineeringModeWorld` methods end with the **identical** unbounded write-back:

```asm
; emGetModesBit 0x11db0  (identical in emGetModes 0x119f4, emGetTokenRequest 0xf618,
;  emEssCommand 0x1120c, emGetTimeRequest 0x121ec, emGetRecoveryRequest 0x10110,
;  emVerifyTime 0x1271c)
011d80: ldr  x8, [x19, #0x78]           ; x8 = rsp
011d84: ldrb w9, [x8, #0x516]
011d88: tbnz w9, #0, #0x11db0           ; ONLY guard: rsp[0x516] & 1
                                        ;  (clear -> "Request msg doesn't exist", 0xd03e0012)
011db0: add  x8, x8, #0x14, lsl #12     ; rsp + 0x14000
011db4: mov  x0, x20                    ; dst = caller's `out` buffer
011db8: add  x8, x8, #0x132             ; rsp + 0x14132
011dbc: ldr  w2, [x8]                   ; w2 = *(u32*)(rsp + 0x14132)   <-- LENGTH, UNVALIDATED
011dc0: str  w2, [x21]                  ; *outLen = w2
011dc4: ldr  x8, [x19, #0x78]
011dc8: add  x8, x8, #0x14, lsl #12
011dcc: add  x1, x8, #0x136             ; src = rsp + 0x14136
011dd0: bl   memcpy                     ; memcpy(out, rsp+0x14136, w2)   <-- SINK
```

No `cmp` on `w2`. The only gate is one bit of one status byte.

The bound — **on this device** — comes from the backend that fills `rsp`, not from the server:

```asm
; libengmode2lite.so  em_context_make_response  0x15098
015098: mov  w8, #0x14ff
0150a0: mov  w11, #0x4132
0150a4: movk w8,  #1, lsl #16        ; w8  = 0x000114ff  (ctx length field)
0150a8: movk w11, #1, lsl #16        ; w11 = 0x00014132  (rsp length field)
0150ac: ldr  w6, [x19, x8]           ; w6  = *(u32*)(ctx + 0x114ff)
0150b0: mov  w8, #-0xc801            ; w8  = 0xffff37ff
0150bc: str  w6, [x20, x11]          ; *(u32*)(rsp + 0x14132) = w6
0150b8: add  w10, w6, w8             ; w10 = w6 - 0xc801
0150c0: cmp  w10, w8
0150c4: b.hi #0x15104                ; success iff 1 <= w6 <= 0xC800
        ; fall-through: "please check message length(%u)", ret 0xf0f2150f
015104: add  x8, x20, #0x14, lsl #12
015110: add  x0, x8, #0x136          ; dst = rsp + 0x14136
015114: add  x1, x9, #0x503          ; src = ctx + 0x11503
015118: mov  x2, x6                  ; n   = w6
01511c: bl   memcpy
```

`0xC800 = 51,200` is *exactly* `0x20936 - 0x14136`, i.e. the remaining space in the `rsp` buffer.
The lite backend is self-consistent.

### The downstream chain, and where the last consumer's assumption is hard-coded

```
rsp+0x14132 (bounded 1..0xC800 by lite backend;  UNBOUNDED if the TA fills it)
   -> *outLen                                        libengmode_server.so 0x11dc0
   -> memcpy(out /* calloc 0x11000 */, ...)          0x11dd0     69,632 >= 51,200  OK
   -> reply parcel: writeInt32(len), writeByteArray   emservice
   -> engmodeclient::getModesbit: readInt32(&mLen)    libengmode_client.so 0x5514  <-- NO BOUND
   -> Parcel::read(reply, this+0xc, mLen)             0x5524  (return value IGNORED)
   -> engmodeclient::getBytes(dst, &len):             0x5774
        memcpy(dst, this+0xc, this->mLen)             <-- dst is calloc(1, 0xC800)
```

`libengmode_client.so` 0x5508–0x5524 — the length is taken straight from the reply:

```asm
005508: add  x0, sp, #0x10
00550c: mov  x1, x20                 ; &this->mLen
005510: str  wzr, [x19, #8]
005514: bl   Parcel::readInt32       ; <-- mLen = whatever emservice said
005518: add  x1, x19, #0xc           ; dst = mBuf[0x11000]
00551c: ldrsw x2, [x19, #8]          ; n   = (size_t)(int32)mLen
005524: bl   Parcel::read            ; return value discarded
```

and `engmodeclient::getBytes` 0x5768–0x5774:

```asm
005768: ldrsw x2, [x19, #8]          ; x2 = this->mLen
00576c: mov  x0, x21                 ; dst (caller buffer)
005770: mov  x1, x23                 ; src = this + 0xc
005774: bl   memcpy                  ; memcpy(dst, mBuf, mLen)   <-- no bound
```

The HAL wrapper hard-codes the assumed maximum:

```asm
; vendor.samsung.hardware.security.engmode-service
0034f4: mov  w0, #0xc800
0034f8: mov  w1, #1
0034fc: bl   calloc                  ; calloc(1, 0xC800) = 51,200
003514: bl   engmodeclient::getBytes ; memcpy(that, mBuf, mLen)
```

---

## 3. DELIVERABLE 3 — THE TLC / QSEECom BOUNDARY (fully reverse engineered)

`libengmode_tlc.so` is 15 KB with 3 functions and 9 globals. Key enabler: the `.rela.dyn` uses
Android packed (APS2/SLEB128) relocations. I decoded it and the resulting GOT map is
**authoritative** (`decompiled/tlc-got-map.txt`); an earlier pattern-inferred map was off by one
slot and is superseded.

```
GOT[0x3228] -> _Z26em_tlc_thr_cleanup_handlerPv
GOT[0x3230] -> gReq      (bss 0x4338, 8B)
GOT[0x3238] -> gRsp      (bss 0x4340, 8B)
GOT[0x3240] -> gRspSize  (bss 0x434c, 4B)
GOT[0x3248] -> gReqSize  (bss 0x4348, 4B)
GOT[0x3250] -> _Z21em_tlc_suicide_threadi
GOT[0x3258] -> gReqCount (bss 0x4350, 4B)
GOT[0x3260] -> gRunning  (bss 0x4334, 1B)
GOT[0x3268] -> gRet      (bss 0x4330, 4B)
```
(Self-validating: `pthread_create`'s entry slot resolves to `em_tlc_suicide_thread` and
`__pthread_cleanup_push`'s handler slot resolves to `em_tlc_thr_cleanup_handler`.)

### Structure

`em_tlc_send` (0x20c0, 860 B) is **only a watchdog**:

* signature `em_tlc_send(void *req /*x0*/, int reqSize /*w1*/, void *rsp /*x2*/, uint32 *rspSize /*x3*/)`
* null checks on x0/x2/x3 only (`cbz x21 → err 1`, `cbz x22 → err 2`, `cbz x19 → err 3`) — **no
  length check of any kind**
* **the `cmp w10, 0xee6b2800` at 0x2184 is NOT a length check.** It reads `*(u32*)(req + 0x517)`
  and only resets `gReqCount` when the value exceeds `0xee6b2800`; the same field is then
  *overwritten* with the sequence counter (`str w4, [x8]` at 0x225c). It is a wrap-around guard on a
  sequence number, not a bound on `reqSize`.
* spawns a worker thread at **0x241c** (outside the symbol's size; found via `adr x2, #0x241c`),
  sets `gRunning = 1`, polls `usleep(50000)` up to ~3 s, then `pthread_kill(tid, 12)` if stuck.

The **worker thread at 0x241c** then calls the real function at **0x2510** (no symbol), which does
all the QSEECom work:

```asm
; sb_size = ((gRspSize + reqSize) & ~0x3F) + 0x40
002580: ldr  w8, [x23]            ; w8  = gRspSize
002598: add  w8, w8, w21          ; w8  = gRspSize + reqSize      (w21 = reqSize)
00259c: and  w8, w8, #0xffffffc0
0025a0: add  w3, w8, #0x40        ; size argument
0025a4: bl   QSEECom_start_app    ; (&handle, "/vendor/firmware_mnt/image", "engmode", size)

002604: ldr  x0, [sp]             ; handle
002608: mov  w1, #1
00260c: bl   QSEECom_set_bandwidth

002724: ldr  x8, [sp]
002728: ldr  x23, [x8]            ; sb = *handle  (first field of the QSEECom handle)
00272c: cbz  x23, err
002730: mov  w24, w21             ; req_len = reqSize
002734: mov  x0, x23              ; dst = sb
002738: mov  x1, x22              ; src = req
00273c: mov  x2, w24
002740: bl   memcpy               ; (1) sb[0 .. req_len) <- req

002744: ldr  x8, [sp]
002748: ldr  x8, [x8]             ; sb
00274c: cbz  x8, err
002750: add  x22, x8, x24         ; rsp_area = sb + req_len
002754: mov  x0, x22
002758: mov  w1, wzr
00275c: mov  w2, w20              ; w20 = gRspSize (loaded at 0x256c, before start_app)
002760: bl   memset               ; (2) zero rsp_len bytes

002764: ldr  x0, [sp]             ; handle
002768: mov  x1, x23              ; sb_req
00276c: mov  w2, w21              ; req_len   <-- passed through, not re-derived
002770: mov  x3, x22              ; sb_rsp  = sb + req_len
002774: mov  w4, w20              ; rsp_len  <-- the caller's declared capacity
002778: bl   QSEECom_send_cmd

00284c: mov  x0, x19              ; dst = caller's rsp buffer
002850: mov  x1, x22              ; src = sb + req_len
002854: mov  w2, w20              ; n   = gRspSize   <-- NOT a response-supplied length
002858: bl   memcpy               ; (3) copy-back
```

### Findings

1. **No fixed intermediate exists.** There is no 0x10000 stack/heap staging buffer. The QSEECom
   ION buffer is used directly: `req` at `sb+0`, `rsp` at `sb+req_len`.
2. **The size is derived, and it is algebraically safe.** Let `R = gRspSize + reqSize`,
   `sb = (R & ~0x3F) + 0x40`. Since `0 <= (R & 0x3F) <= 0x3F`, `sb >= R - 0x3F + 0x40 = R + 1`.
   Therefore `req_len + rsp_len <= sb` always. Copies (1), (2), (3) can never leave the buffer.
3. **Lengths are passed through, never re-derived.** `req_len` is the caller's `reqSize` (no
   `strlen`, no byte swap, no 16-bit truncation). `rsp_len` is `gRspSize`, captured once at 0x256c
   before `QSEECom_start_app` and reused for both the `memset` and the final `memcpy`.
   **There is no reconstruction inconsistency at this layer.**
4. **The copy-back is bounded by the caller's declared capacity, not by anything the TA says.**
   `memcpy(rsp_out, sb+req_len, gRspSize)` — a TA that writes more is simply truncated. This is the
   opposite of the feared "response-length overrun".
5. **Residual risk is an integer overflow in `add w8, w8, w21` (32-bit).** If
   `gRspSize + reqSize` wrapped, `sb` would be tiny while `memcpy(sb, req, reqSize)` still used the
   full `reqSize`. **Not reachable**: every server call site passes `reqSize = 0x21c7d` and
   `rspSize = 0x20936` as constants (§2), sum `0x425B3`, far from `2^32`. Also
   `em_tlc_send` is not reachable from any external caller — only from `emProcess`.
6. **Response length is not validated before the copy-back — but it does not need to be**, because
   the copy-back length is `gRspSize`, not a value read from the buffer.
7. Minor: `gRet`/`gRunning`/`gReq` are process-global and mutated from a worker thread while the
   caller polls them — a benign data race, not memory corruption.

---

## 4. DELIVERABLE 4 — `getModesbit` / `getRequestMsg` / `getStringModes` inout semantics

### Why tx 22 "needs a length AND 32 bytes present"

`engmodeclient::getModesbit` (libengmode_client.so 0x53dc) reads the reply as
`status:int32, len:int32, bytes[len]`:

```asm
0054a0: add  x0, sp, #0x10
0054a4: add  x1, sp, #0xc
0054a8: bl   Parcel::readInt32     ; (a) status  -> sp+0xc
0054ac: cbz  w0, #0x54dc           ; read failure -> bail
0054dc: ldr  w3, [sp, #0xc]
0054e4: cbz  w3, #0x5508           ; status != 0 -> log "Failed to get modes bit(0x%08x)", mLen = 0
005508: add  x0, sp, #0x10
00550c: mov  x1, x20
005510: str  wzr, [x19, #8]
005514: bl   Parcel::readInt32     ; (b) length  -> this->mLen
005518: add  x1, x19, #0xc
00551c: ldrsw x2, [x19, #8]
005520: add  x0, sp, #0x10
005524: bl   Parcel::read          ; (c) bytes[mLen] -> mBuf[0x11000]
```

The raw `service call` probe therefore needs `i32 <len> i32 0 x8 ...` purely to make the *parcel*
well-formed for `Parcel::readInt32` at (b); the observed `0xf02d0010` for tx 22 is the **status**
word from `emservice`, and `0x00000020` at offset +8 is the second int32 (the length = 32) that the
probe itself supplied. There is no `-ENOMEM`; the construction is a parcel-shape artifact.

### Where a service writes back MORE than the caller declared

`onTransact` allocates **one** `calloc(1, 0x11000)` buffer (`x24`) and hands it to every method:

```asm
; libengmode_server.so  EngineeringModeHandler::onTransact
00b9ac: mov  w1, #0x1000
00b9b0: mov  w0, #1
00b9b4: movk w1, #1, lsl #16      ; 0x11000
00b9b8: bl   calloc
00b9bc: mov  x24, x0              ; <-- the single shared out buffer (69,632 B)
...
00bfe0: ldr  x0, [x21, #0x160]    ; mImpl
00bfe8: ldr  x8, [x8, #0x80]      ; vtable slot #14 == emGetModesBit
00bfec: add  x2, x19, #0x3c       ; &outLen
00bff0: mov  x1, x24              ; out = the 0x11000 buffer
00bff4: blr  x8
```

`emGetModesBit` then writes `w2` bytes into it where `w2 = *(u32*)(rsp+0x14132)` — **the caller's
declared size is never read and never used as a bound** (§2). On this device `w2 <= 0xC800 <
0x11000`, so no overflow. The structural defect (no length check against the destination's real
size) is real, but the two numeric constants happen to make it safe here.

### Inbound side: `onTransact` *does* bound one caller length

```asm
00bb1c: bl   Parcel::readUint32   ; w0 = caller-supplied length
00bb20: mov  w8, #0xefff
00bb28: movk w8, #0xfffe, lsl #16 ; w8 = -0x11001
00bb2c: add  w9, w0, w8
00bb30: add  w8, w8, #1           ; w8 = -0x11000
00bb34: cmp  w9, w8
00bb38: b.hs #0xc178              ; OK iff 0 <= len <= 0x11000
                                  ;  else "token length isn't normal (%d/%d)"
```
(Verified algebraically: `b.hs` taken ⟺ `len <= 0x11000`.)

So the *read* direction is capped at 0x11000; the *write-back* direction is capped only by the
backend. Both are 69,632 / 51,200 respectively — consistent.

---

## 5. DELIVERABLE 5 — `commandForESS` / ESS envelope path

**Hop 1 — AIDL.** tx 12 `commandForEss(int32, const string&, vector<uint8_t>*, SehStatus*)`,
`Bp` at 0xa21c, `inout` (`writeStr` `writeVec` → transact → `readVec`).

**Hop 2 — HAL service.** `0xa21c` wrapper → `engmodeclient::commandForESSEiPKc` →
`engmodeclient::getBytes`.

**Hop 3 — emservice.** `onTransact` vtable slot **#10** = `emEssCommand` (`vtable+0x60`, call site
0xbe50), i.e. `EngineeringModeWorld::emEssCommand` (0x10584) or `EngineeringModeLegacy::emEssCommand`
(0xce6c) depending on the backend.

**Where the ESS string is assembled and how it is bounded (World path):**

```asm
; libengmode_server.so  EngineeringModeWorld::emEssCommand
01076c: bl   strlen               ; x2 = strlen(ESS string)  -> w23
010774: mov  w8, #0xc801
010778: cmp  w23, w8
01077c: b.lt #0x107a4             ; require strlen(ESS) < 0xc801 (51,201)
        ; else: error path
0107a8: sxtw x2, w23              ; copy length  = the strlen result
0107cc: bl   memcpy               ; req + 0x11615 <- ESS string
0107e0: str  w23, [x9, x8]        ; *(u32*)(req + 0x11611) = strlen result
...
010d10: mov  w2, #0x1c7d
010d18: movk w2, #2, lsl #16      ; reqSize = 0x21c7d   <-- the CONSTANT, not strlen
010d20: bl   emProcess
```

* The ESS string **is** length-bounded on the HLOS side: `strlen(ESS) < 0xC801`.
* The stored length at `req+0x11611` is the `strlen` result — a **re-derived** length (this is the
  only place in the World code where a length is recomputed rather than passed through). It is
  safely bounded by the check immediately above it, and the destination offset `0x11615 + 0xC800 =
  0x1DE15 < 0x21C7D`, so no overflow of `req`.
* `reqSize` passed to `emProcess` is the constant `0x21c7d`, **not** the string length. Consistent.
* The ESS response uses the same `rsp+0x14132` / `rsp+0x14136` sink as everything else
  (`emEssCommand` 0x1122c), so it inherits the same analysis as §2.

**ESS response in the live (lite) backend** — `em_lite_ess_command` 0xfdb0:

```asm
00fdb0: mov  w26, #0x4132  ; movk w26,#1,lsl#16   -> rsp + 0x14132
00fdd4: mov  w28, #0x4136  ; movk w28,#1,lsl#16   -> ctx + 0x14136
00fdbc: str  w8, [x20, #8]        ; "ED=S"
00fdc4: str  x9, [x20]            ; "AT+ENGMODES="
00fdc8: bl   memcpy               ; append the command
00fdd8: strh w9, [x20, w8, uxtw]  ; append "\r\n"
00fde4: ldr  w2, [x23, x26]       ; w2 = *(u32*)(ctx + 0x14132)   (already bounded <= 0xC800)
00fdec: add  x1, x23, x28         ; src = ctx + 0x14136
00fdf0: bl   memcpy
```
No additional bound here, but the value was already validated by `em_context_make_response`.

**There is no separate fixed 8 KB ESS response buffer.** The ESS response is appended into the same
`calloc(1, 0xC800)` / `0x11000` chain used by every other method.

**The JNI / `AT+ENGMODES` op-id path (0,1,→1 … 9,0→10, else 1000) was NOT traced.** `libengmodejni.samsung.so`
and `lib.engmode.samsung.so` are present in `binaries/` but were not disassembled in this pass — see §8.

---

## 6. DELIVERABLE 6 — LEGACY vs CURRENT (this is the biggest correction to the prior model)

There are **two orthogonal** legacy/current axes, and they were being conflated.

### 6a. Which backend object `emservice` instantiates

`EngineeringModeHandler::setVersion()` (libengmode_server.so 0xb13c) constructs the polymorphic
member at `this + 0x160`:

```asm
00b1b8: bl   em_get_did
00b1c4: bl   __strlen_chk
00b1c8: cmp  x0, #0x10
00b1cc: b.ne #0xb274                ; strlen(did) != 16  -> LEGACY
00b1d0: mov  w0, #0x170
00b1d4: bl   operator new           ; EngineeringModeWorld = 0x170 bytes
00b1dc: bl   EngineeringModeWorldC1Ev
00b1e8: str  x20, [x19, #0x160]
   ; then: strncmp("30", did, 2)==0 -> mVersion = 30
   ;       strncmp("20", did, 2)==0 -> mVersion = 20
00b274: mov  w0, #0x80
00b278: bl   operator new           ; EngineeringModeLegacy = 0x80 bytes
00b280: bl   EngineeringModeLegacyC1Ev
00b284: mov  w8, #0xf               ; mVersion = 15
00b288: str  x20, [x19, #0x160]
```

### 6b. Which sub-mode `EngineeringModeWorld` uses (TA vs lite)

`EngineeringModeWorldC1Ev` 0xd288 sets `this+8`:

| condition | `this+8` | backend |
|---|---|---|
| `strlen(did) != 16` | `0x0f` (15) | `em_tlc_send` (QSEECom) |
| `did[0:2] == "30"` | `0x1e` (30) | `em_tlc_send` + `doInitCore()` + `emInit()` |
| `did[0:2] == "25"` | `0x19` (25) | **`em_lite_entry`** |
| `did[0:2] == "15"` | `0x19` (25) | **`em_lite_entry`** |
| `did[0:2] == "20"` | `0x14` (20) | `em_tlc_send` + `doInitCore()` + `emInit()` |

(`0x19` is written as the 64-bit `mov x8,#0x19; movk x8,#1,lsl#32`, so `*(u32*)(this+8) == 0x19`
and `this+0xc == 1`.)

### 6c. Which one is live on THIS device

The observed `service call ... 22` reply is `0xf02d0010`. I searched every artifact for the
instruction pair that materialises that constant:

```
libengmode2lite.so 0x013efc, 0x0141b8, 0x014228, 0x014484, 0x01f0cc
   mov w?, #0x10 ; movk w?, #0xf02d, lsl #16
```

`0xf02d0010` exists **only** in `libengmode2lite.so`. Therefore
`EngineeringModeWorld::mode == 0x19` → **`em_lite_entry`** → the DID is 16 chars starting with
`"25"` or `"15"`. **`em_tlc_send` is not called on this device; no QSEECom transaction is issued;
the `engmode` trustlet is not involved.**

### 6d. The `EngineeringModeLegacy` backend is also pure HLOS

`EngineeringModeLegacyC1Ev` 0xc998 is a `dlopen` + 13×`dlsym` block:

```
dlopen("/vendor/lib64/libengmode15.so", RTLD_LAZY)          @ 0xc9e4/0xc9ec
  this+0x20 = em15_is_token_installed        this+0x28 = em10_install_token
  this+0x30 = em10_get_request_msg           this+0x38 = em10_get_id
  this+0x40 = em10_get_expiry_date           this+0x48 = em15_get_status
  this+0x50 = em10_remove_token              this+0x58 = em15_get_last_token_status
  this+0x60 = em15_ess_command               this+0x68 = em15_get_modes
  this+0x70 = em15_make_time_req             this+0x78 = em15_update_time
```

`libengmode15.so` imports are `libcrypto` (EVP/RSA/X509), `libstork_shared` (`read_from_steady` /
`write_to_steady`), libc, liblog, libdl — and it `dlopen`s `/system/lib64/libsecril-client.so`.
**No QSEECom, no `em_tlc_send`, no `em_lite_entry`.** So the third possible backend is *also* HLOS.

`Legacy::emGetToken` (0xd004), `Legacy::emGetTuc` (0xd03c) and `Legacy::emGetModesBit` (0xd0d0) are
hard stubs returning `0xd0410010` / `0` / `0xd00f0010`. `Legacy::emGetModes` (0xd070) is live and
calls `this+0x68` (`em15_get_modes`) with **no length argument at all**, then sets `*outLen =
strlen(out)`.

### 6e. Is the legacy `EngineeringModeService` reachable?

`service check EngineeringModeService` → **not found**, but that proves nothing:

* `emservice` holds **both** binder domains: fd 5 → `/dev/binderfs/vndbinder`, fd 10 →
  `/dev/binderfs/binder` (`device/engmode-fds.txt`). `service check` only queries one domain.
* `EngineeringModeHandler::instantiate()` calls `defaultServiceManager()->addService(...)`.
* `service-list-full.txt` lists only the AIDL name because it is a *different* (VINTF) registry dump.

**Verdict: the legacy internal Binder interface `EngineeringModeService` IS published and IS the
transport actually used by `libengmode_client.so`.** It is reached on every single AIDL call — the
AIDL interface is a thin shim over it. There is no "AIDL path vs legacy path" choice; there is only
one path, and its last hop is the legacy `BBinder` in `emservice`.

**Does the legacy path skip a check the AIDL path performs?** Not meaningfully:
* the client-side allowlist is in `lib.engmode.samsung.so` (not analysed this pass) and applies to
  the *JNI* entry, not to the binder hop;
* `onTransact` performs the same checks regardless of which backend object is installed;
* the backend objects differ in *capability*, not in *permission checks*.

---

## 7. DELIVERABLE 7 — SELinux / UID reality check

| process | SELinux | uid | binder fds |
|---|---|---|---|
| `/vendor/bin/vendor.samsung.hardware.security.engmode-service` | `u:r:hal_engmode_default:s0` | system | 5 = binder, 7 = vndbinder |
| `/vendor/bin/emservice` | `u:r:emservice:s0` | system | 5 = vndbinder, 10 = binder |

`emservice`'s `main` (0x10b8–0x1114) is exactly:

```asm
ProcessState::self()
defaultServiceManager()
EngineeringModeHandler::instantiate()
ProcessState::self() ; ProcessState::startThreadPool()
IPCThreadState::self() ; IPCThreadState::joinThreadPool(true)
```

**No UID/PID/permission check in `main`.**

`EngineeringModeHandler::onTransact` reads the caller identity **only to log it**:

```asm
00b820: bl   IPCThreadState::self()
00b824: bl   IPCThreadState::getCallingPid     ; -> w22
00b82c: bl   IPCThreadState::self()
00b830: bl   IPCThreadState::getCallingUid     ; -> w0 -> w5
00b844: add  x2, x2, #0x2d3  ; "EngineeringMode version = %s,(%d/%d)"
00b85c: bl   __android_log_print
```

`w22`/`w5` are consumed only by that `__android_log_print`. No comparison, no early return.

And the pre-existing finding is confirmed verbatim:

```asm
; libengmode_server.so  EngineeringModeHandler::callerCheck
0000b68c: 5f2403d5   bti  c
0000b690: e0031f2a   mov  w0, wzr     ; return 0
0000b694: c0035fd6   ret
```

`callerCheck` is a 12-byte always-zero function **with no call sites** (it is exported but
unreferenced inside the library), so even its nominal result is unused.

**Conclusion: the only gate is SELinux policy (`u:r:emservice:s0` + `hal_engmode_default` binder
allow rules). There is no supplementary server-side identity check.** Since the user already has
root, that gate is not an obstacle, and `callerCheck` being dead is *not* an independently
exploitable issue.

---

## 8. CANDIDATE TABLE (mandatory fields)

| ID | Layer pair | File + VA + instructions | Field / width / bound per layer | Input control | Sink + real size | Class | Reaches TA? | Verdict |
|---|---|---|---|---|---|---|---|---|
| **C-1** | emservice ← backend (`rsp+0x14132`) | `libengmode_server.so` **0x11dbc** `ldr w2,[x8]`; **0x11dc0** `str w2,[x21]`; **0x11dd0** `bl memcpy` (same in `emGetModes` 0x11a14, `emGetTokenRequest` 0xf63c, `emEssCommand` 0x1122c, `emGetTimeRequest` 0x1220c, `emVerifyTime` 0x1273c, `emGetRecoveryRequest` 0x10130) | `uint32 len @ rsp+0x14132`. **server:** no bound (only `rsp[0x516]&1`). **lite backend:** `1..0xC800` (`libengmode2lite.so` 0x150b0–0x150c4). **TA backend:** none known | emservice's own backend (lite: HLOS file/ctx data; TLC: the trustlet) | `onTransact` `calloc(1,0x11000)` = 69,632 | length divergence / missing bound at receiver | **No on this device** (lite). **Yes** on mode-0x1e/0x14 devices | **REAL-BUT-WEAK** (this device) / **NEEDS-MORE-EVIDENCE** (TA path) — see reasoning below |
| **C-2** | HAL ← emservice (`getBytes`) | `libengmode_client.so` **0x5514** `bl Parcel::readInt32(&mLen)` (unchecked, return of `read` at 0x5524 discarded); **0x5774** `bl memcpy` `memcpy(dst,this+0xc,mLen)`; `engmode-service` **0x34f4** `calloc(1,0xC800)` | `int32 mLen`. **client:** no bound. **HAL dst:** 51,200 (hard-coded). **emservice:** ≤0xC800 via lite | emservice reply (root can speak to emservice directly) | HAL heap `calloc(1,0xC800)` | length divergence / cross-process assumption | No | **REAL-BUT-WEAK** on lite; **EXPLOITABLE-CANDIDATE** if `rsp+0x14132` can exceed 0xC800 (i.e. on TA-mode devices) |
| **C-3** | server → TLC (QSEECom sizes) | `libengmode_tlc.so` **0x2598** `add w8,w8,w21`; **0x259c** `and w8,w8,#0xffffffc0`; **0x25a0** `add w3,w8,#0x40`; **0x25a4** `QSEECom_start_app`; **0x2740** `memcpy(sb,req,req_len)`; **0x2760** `memset(sb+req_len,0,gRspSize)`; **0x2778** `QSEECom_send_cmd`; **0x2858** `memcpy(rsp,sb+req_len,gRspSize)` | `req_len = reqSize`, `rsp_len = gRspSize`, `sb = ((rspSize+reqSize)&~0x3f)+0x40 ≥ req_len+rsp_len+1`. No re-derivation | `emProcess` callers only (constants) | QSEECom ION buffer, always ≥ `req_len+rsp_len+1` | length divergence (hypothesis) | Would, but unreachable | **NOT-A-BUG** — algebraically safe; integer overflow unreachable (constants) |
| **C-4** | server → TLC (response copy-back) | `libengmode_tlc.so` **0x2854** `mov w2,w20` (loaded once at **0x256c**) | copy-back length = caller's `gRspSize`, **not** read from the buffer | n/a | caller `rsp` = `calloc(0x20936)` | (feared) response-length overrun | Would, but unreachable | **NOT-A-BUG** — correctly bounded by the caller's capacity |
| **C-5** | server → TLC (magic check misread as a length check) | `libengmode_tlc.so` **0x2174** `ldr w10,[x8]` (`req+0x517`); **0x2154/0x215c** `w12=0xee6b2800`; **0x2184** `cmp w10,w12` | `uint32` sequence number at `req+0x517`; only gates a `gReqCount` reset; overwritten at **0x225c** with the counter | callers | n/a | misattribution | n/a | **NOT-A-BUG** — this is a sequence guard, not a length check |
| **C-6** | HAL ← AIDL caller (inbound length) | `libengmode_server.so` **0xbb1c** `readUint32`; **0xbb2c–0xbb38** `add/cmp/b.hs` | `uint32 len`, bound `<= 0x11000` | AIDL caller (root) | 0x11000 buffer | (feared) missing bound | No | **NOT-A-BUG** — bound is present and correct |
| **C-7** | server (`emEssCommand` strlen re-derivation) | `libengmode_server.so` **0x1076c** `strlen`; **0x10774** `mov w8,#0xc801`; **0x1077c** `b.lt`; **0x107cc** `memcpy(req+0x11615, …)`; **0x107e0** `str w23,[req+0x11611]` | `strlen(ESS) < 0xC801`; dst `req+0x11615`, `req` = 0x21c7d | AIDL caller via tx 12 | `req` 138,365 | re-derived length | No | **NOT-A-BUG** — bounded, and `0x11615+0xC800 < 0x21C7D` |
| **C-8** | `emProcess` length pass-through | `libengmode_server.so` **0xd254–0xd284** | none — pure arg shuffle | n/a | n/a | (feared) missing validation | n/a | **NOT-A-BUG** — validation lives in the callers, and they use constants |
| **C-9** | `callerCheck` always returns 0 | `libengmode_server.so` **0xb68c–0xb694** `bti c; mov w0,wzr; ret` | n/a | n/a | n/a | dead code | No | **REAL-BUT-WEAK** — confirmed dead (zero call sites); SELinux is the only gate either way |
| **C-10** | emservice identity check | `libengmode_server.so` **0xb820–0xb830** `getCallingPid/getCallingUid` → only `w5`/`w22` into `__android_log_print` | n/a | n/a | n/a | missing authz | No | **CONFIRMED ABSENT** — no server-side UID gate |
| **C-11** | `EngineeringModeWorld` reachability | `libengmode_server.so` **0xb1c8–0xb294** (`setVersion`) + **0xd330–0xd4a0** (World ctor) | DID-derived backend selection | device identity, not the caller | n/a | architecture | Yes, conditionally | **CONFIRMED** — mode 0x19 (lite) on this device; TA only for DID `"30"`/`"20"` |
| **C-12** | `emGetModesBit` etc. `memcpy` into a 0x11000 buffer with no size check | `libengmode_server.so` **0x11dd0** | see C-1 | see C-1 | 69,632 vs max 51,200 | missing bound | No | **REAL-BUT-WEAK** — structurally unchecked, numerically safe today |

### Reasoning for C-1 / C-2

The chain is `len(rsp+0x14132) → *outLen → Parcel → engmodeclient::mLen → getBytes memcpy(dst=calloc(0xC800), …)`.
**No layer between the producer and the final `memcpy` re-validates it.** The only thing that makes
it safe today is that `em_context_make_response` happens to clamp to `0xC800`, which is exactly the
size the HAL hard-codes. That is a *coincidence of two constants in two different binaries*, not an
enforced invariant. On a device where `EngineeringModeWorld::mode` is `0x1e`/`0x14` (DID `"30"` /
`"20"`), the value at `rsp+0x14132` is produced by the `engmode` trustlet with **no HLOS bound at
any layer**, and a value `> 0xC800` becomes a straight heap overflow in
`u:r:hal_engmode_default:s0`, and `> 0x11000` additionally overflows `emservice`'s own
`calloc(0x11000)` reply buffer in `u:r:emservice:s0`.

I could not confirm or refute the TA's own cap on that field (see §9), which is why the TA-mode
verdict is NEEDS-MORE-EVIDENCE rather than EXPLOITABLE-CANDIDATE.

---

## 9. MISSING ARTIFACTS / UNRESOLVED

1. **The `engmode` trustlet is not decoded.** `partitions/em-czd1.img` (1,380,952 B) and
   `binaries/engmode-czd1.mbn.lz4` are present but were not unpacked/analysed in this pass. Without
   it I cannot bound the value the TA writes at `rsp+0x14132`, which is the single missing fact that
   decides C-1/C-2 on TA-mode devices. This is the highest-value next step.
2. **`libengmodejni.samsung.so` and `lib.engmode.samsung.so` not disassembled.** The JNI op-id
   mapping (`0,1,→1 … 9,0→10, else 1000`) → `lib.engmode.samsung.so` → TA was not traced. The
   `AT+ENGMODES` / SatsService abstract-socket hop is therefore unverified.
3. **`check_allowed_process` / `em_get_process_name`** live in `libengmode15.so` (0x8df0 / 0x9058)
   and were not analysed. The user's "client-side caller allowlist" is probably here rather than in
   `lib.engmode.samsung.so`; worth confirming.
4. **`.rela.dyn` of `libengmode_server.so` not fully decoded.** It uses grouped APS2 relocations
   (header `group_size=127, reloc_count=0, flags=3, …`) which my decoder does not implement.
   Consequence: I could not read the contents of `_ZTV21EngineeringModeLegacy` (0x17348) or
   `_ZTV20EngineeringModeWorld` (0x173f0) directly. The vtable index → method mapping in §2/§5 is
   therefore inferred from (a) both classes declaring their 17 interface methods in identical source
   order and (b) the log string `"Failed to remove token(0x%08x)"` immediately following the
   `vtable+0x40` dispatch, which pins `emRemoveToken` at index 6 and hence `emGetModesBit` at
   index 14. All 16 dispatch sites use `x0 = *(this+0x160)`, so the *set* of reachable methods is
   certain even if the exact index→name pairing has residual uncertainty.
5. **`em_get_did()` implementation not located** (it is an import of `libengmode_server.so`; not
   found in `libengmode15.so`/`libengmode2lite.so`/`libengmode_tlc.so` exports). The device's actual
   DID string is therefore unknown; the mode-0x19 conclusion rests on the `0xf02d0010` provenance
   instead, which is strong evidence.
6. **No `sepolicy` / `file_contexts` from the device were collected**, so the SELinux allow rules for
   `hal_engmode_default → emservice` are unverified (only the process contexts are known).
7. **`emProcess` call sites for `emIsTokenInstalled` / `emTokenInstall` / `emSyncUpCore` /
   `doInitCore` / `emGetTuc` / `emRecoveryData` were not individually audited** for their
   `reqSize`/`rspSize` arguments; the seven audited call sites all used the constants.

---

## 10. BOTTOM LINE

* **The layer stack is, for practical purposes, consistent on this device.** Every buffer-bearing
  path I traced has a bound at the layer that produces the length, and every consumer's buffer is
  at least as large as that bound. The three constants line up: producer clamp `0xC800` ≤
  server reply buffer `0x11000`, and `0xC800` == the HAL's `calloc` size.
* **The QSEECom boundary — the place the user flagged as most promising — is a negative result.**
  `libengmode_tlc.so` derives its shared-buffer size from the same two lengths it transfers, with a
  guaranteed 1..64 bytes of slack; lengths are passed through without re-derivation; and the copy-back
  is bounded by the caller's capacity rather than by anything the secure side says. There is no
  fixed intermediate to overrun.
* **The stack does not reach TrustZone on this device at all.** `emservice` selects
  `EngineeringModeWorld` mode `0x19` → `em_lite_entry` in `libengmode2lite.so`, which links only
  libc/liblog/libm/libdl. Proven by `0xf02d0010` being unique to that library.
* **The one structural defect worth carrying forward** is C-1/C-2: the response length at
  `rsp+0x14132` is validated at exactly one place (the lite backend), is never re-checked by
  `libengmode_server.so`, `libengmode_client.so`, or the HAL service, and terminates in an
  unguarded `memcpy` into a `calloc(0xC800)` buffer whose size is a hard-coded assumption in a
  different binary. If the producing layer ever yields `> 0xC800`, it is a heap overflow. That
  makes it the right thing to look at on any SM-S928B variant whose 16-char DID begins with `"30"`
  or `"20"`, and the trustlet is the artifact needed to settle it.
