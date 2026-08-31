# Mapa de Vuln Research — revisão adversarial (S24 Ultra, DZDP)

Alvo: SM-S928B (`e3q`), `S928BXXU5DZDP`, Android 16 / One UI 8.5, patch **2026-04-05**.
Root: KernelSU temporário. Bootloader travado durante toda a coleta.
Data: 2026-08-29. Modo: somente análise estática e procedimentos read-only.

Este documento é uma **revisão adversarial** do repo. O repo é tratado como evidência,
não como verdade. Onde este documento contradiz `findings.md`, a contradição é
explicitada com instruções/offsets verificáveis.

Níveis usados: **CONFIRMADO** (duas observações independentes ou verificação byte-level
nesta revisão) · **PROVÁVEL** · **POSSÍVEL** · **ESPECULAÇÃO**.

---

## 1. Resumo executivo

**Conclusão honesta: o caminho realista é extremamente improvável sem uma
vulnerabilidade pré-AVB ou de Secure World. E a rota de Secure World está
arquiteturalmente bloqueada para chegar ao estado do `engmode`. Então, na prática,
é pré-AVB ou nada.**

O que sobrou de pé depois da revisão:

1. **A cadeia documentada em `findings.md` está correta no essencial.** ABL lê
   `IsUnlocked` de `devinfo+0x0d` e alimenta AVB; o bit 3 do Engineering Mode
   alimenta `SetUnlocked`; o token é RSA sobre SHA-256 com âncoras fixas; estado
   em RPMB. Isso se sustenta.
2. **A criptografia do token não é o ponto fraco e não há bug de parser pré-auth
   utilizável no trustlet.** Auditoria dedicada do parser encontrou um defeito
   aritmético real, mas ele é um **out-of-bounds read / DoS**, não escrita, e não
   toca o bitmap de modos.
3. **A fronteira HLOS→TA é consistente.** Todas as verificações do lado HLOS são
   mais estritas ou iguais às da TA (`<0x40` vs `<0x80`; `<0xc801` vs 11 tokens).
   Essa é a direção segura. Não há divergência explorável.
4. **O OEM-lock HAL não existe neste aparelho.** Nem HIDL (`lshal`), nem AIDL
   (nenhum manifest VINTF `android.hardware.oemlock*`), nem binário. O backend
   ativo é `PersistentDataBlockLock`, que é puro HLOS. **Hipótese morta.**
5. **Nenhuma TA mudou entre o dump de abril-2026 e o bootloader de julho-2026.**
   `engmode`, `keymint`, `tz`, `vaultkeeper`, `hyp`, `storsec`, `bksecapp`,
   `uefi_sec` são **byte-idênticos**. Só `devcfg` (blob de config/fuses) e `abl`
   mudaram. Não há janela de patch-diff em Secure World neste intervalo.
6. **O único alvo com par pré/pós-correção real e caminho direto até a decisão de
   unlock é o ABL.** Existe um cluster de CVEs de boot/ABL de junho-2026
   (destacando-se **CVE-2026-24088**, "cryptographic issue ... allows unauthorized
   write access to load a customized bootloader", CVSS 8.2) com o aparelho
   provavelmente em estado pré-correção (SPL 2026-04-05) e o DZG1 (jul-2026) como
   pós-correção. **Isso é a prioridade.**

O que **não** deve ser feito: continuar cavando o trustlet `engmode`, a fronteira
HLOS→TA, o OEM-lock HAL ou o parser de `devinfo`. Todos foram auditados e fechados
com evidência nesta revisão.

---

## 2. O que a pesquisa já provou

Tratado como estabelecido (CONFIRMADO salvo indicação):

| # | Fato | Base |
|---|---|---|
| P1 | `ABL.IsUnlocked` lê `devinfo+0x0d` e alimenta o callback AVB | `0x41ed0` → `ldrb w3,[x19,#0xe35]` (= base `0x170e28` + `0x0d`); callback `0x51048`; `AvbOps+0x48` |
| P2 | `SetUnlocked` (`0x424cc`) é o **único** escritor de `+0x0d`: `strb w19,[x1,#0xd]` em `0x42524` | verificado nesta revisão |
| P3 | Bit 3 do EM → `SetUnlocked` via `BLInitToken → GetEMBit(3)` | `findings.md` claim 5 (PROVÁVEL: não domina todo caminho até AVB) |
| P4 | Política OEM/FRP do One UI 7 foi removida no 8.5 | `0xa141c` `mov w0,wzr` |
| P5 | `androidboot.other.locked=1` é incondicional no 8.5 | `0x4d01c` |
| P6 | Token: `ENG`/`MODE`/`VALI`/`INTE`, MODE dentro da região assinada | `0xa654`–`0xa674`, `0x3070`, `0x32e4` |
| P7 | Âncoras: 4 SPKI RSA, **2048 bits**, fixas, não rotacionadas entre CZD1/DZDP/DZG1 | verificado: DER walk em `0xf3cca` → `SEQUENCE(0x122)`, `modulus len=0x101` = 2048 bits, exp `010001`. Hashes: `42edf9dd…`, `cde6a83f…`, `8ed537b2…`, `e02fa229…` |
| P8 | Estado EM em RPMB cifrado (AES-GCM + `qsee_kdf`) | imports `qsee_stor_*` |
| P9 | `emservice` roda em `u:r:emservice:s0`, uid system; **nenhuma** checagem de identidade server-side | `device_extra/ps-context-full.txt` + disasm |

**Correção a `findings.md`:** a entrada em "Things that went nowhere" dizendo que
os dois hashes de âncora RSA citados em `original-research.md` "não têm extrato
correspondente no repo" está **errada**. `sha256` dos 0x126 bytes em VA `0xf3cca`
= `42edf9dd5623f3149bceb84e9ab085e4c919e8691a4501af9c58bab16ab91ec6` e em
`0xf3f16` = `8ed537b2f076791f7d93d14c1e1bc28d15151045a1615330549844ab0311cca4`.
**São exatamente os dois hashes do documento original.** Eles verificam.

---

## 3. Fronteiras que ainda importam

Ordenadas por valor decrescente.

**F-1. Pré-AVB / ABL (e XBL abaixo dele).** É a única fronteira onde uma primitiva
entrega diretamente o objetivo: executar ou alterar estado **antes** da decisão AVB.
Entradas potencialmente controláveis por root aqui são as partições **não cobertas
por AVB** que o ABL lê: `devinfo`, `persistent`, `frp`, `secdata`, `steady`.

**F-2. Download / Odin.** Roda em XBL/ABL, aceita input por USB com o aparelho
travado. É a única fronteira de entrada externa que sobrevive ao lock. Correlaciona
com CVE-2026-24085/24087/24089/24091/24092 (handlers fastboot).

**F-3. Trustlet `engmode` (pré-auth).** Importa porque é o guardião do estado, mas
a auditoria dedicada não achou primitiva de escrita pré-auth. Resta apenas a
possibilidade de um parser bug **não** coberto pela revisão.

**F-4. Secure World lateral.** Importa em teoria. Na prática está bloqueada
(ver §4, linha SW) e não há janela de patch-diff.

**F-5. HLOS→TA.** Não importa mais: auditada, consistente.

---

## 4. Ranking das superfícies de ataque

Para cada linha: fronteira, primitiva buscada, o que root já dá, o que falta,
evidência pró/contra, lacuna, experimento, custo, probabilidade, condição de parada.

---

### Linha A — ABL / pré-AVB (patch-diff do cluster CVE-2026-2408x/24090)

**Classificação: PRIORIDADE ALTA**

1. **Fronteira:** HLOS-root → partição não verificada / protocolo USB → código ABL
   executando antes e independente de `avb_slot_verify`. Atravessa a fronteira
   entre "input não confiável" e "código que decide o estado de unlock".
2. **Primitiva ganha que KernelSU não dá:** execução arbitrária ou escrita arbitrária
   **antes** do AVB. Isso é qualitativamente diferente de root: permite
   `SetUnlocked(1)` com persistência, ou pular a verificação, sem nenhum token.
   KernelSU é pós-boot, pós-AVB, volátil.
3. **Pode afetar:** `devinfo.IsUnlocked` **antes do AVB** (sim), ABL inteiro (sim),
   decisão de secure boot (sim). Não afeta diretamente a TA `engmode` nem o RPMB,
   e **não precisa**.
4. **Evidência a favor:**
   - `abl.elf` **muda** entre o dump do aparelho (abr-2026) e DZG1 (jul-2026):
     PT_LOAD sha `7df5e15b…` vs `e875b1c2…`. Par pré/pós existe.
   - CVE-2026-24088 (jun-2026, Qualcomm, High 8.2): "cryptographic issue while
     processing a specific partition which allows unauthorized write access to
     load a customized bootloader". O aparelho com SPL 2026-04-05 é anterior ao
     aviso (2026-06) → provável estado vulnerável. **PUBLICADO, mas re-verificar
     a fonte primária** (o boletim de julho-2026 da Qualcomm não renderizou).
   - CVE-2026-24090 (boot flow via partition-table entries, 7.1) e
     24085/24087/24089/24091/24092 (handlers fastboot, 7.2).
   - ABL lê partições não cobertas por AVB: `devinfo` (fixo `0xcd0`, `0x4260c`),
     e a política One UI 7 lia `persistent`.
5. **Evidência contra:**
   - O One UI 8.5 **removeu** a leitura de `persistent` (`0xa141c` retorna 0), o
     que reduz o que o ABL parseia de partições não verificadas.
   - `DeviceInfoInit` (`0x425ec`) faz leitura **fixa de `0xcd0` bytes** para um
     buffer fixo, sem nenhum campo de offset/comprimento vindo do conteúdo.
     **O parser de `devinfo` não é superfície de ataque.** (Novo, desta revisão.)
   - Os CVEs são relatados como "High", não "Critical", e a Qualcomm os rotula
     como acesso a escrita/fluxo de boot, nem sempre como execução de código.
   - Entrega: com BL travado, não dá para substituir o ABL. O input precisa vir de
     USB (fastboot/Odin) ou de uma partição não verificada. Isso é uma restrição
     real que derruba a probabilidade.
6. **Não coletado:** inner FV do `abl.elf` do DZG1 (o `abl.elf` é um FV
   comprimido; diff byte-level da imagem inteira dá ~30% de churn e é **ruído**).
   Também falta o extrator aplicado ao DZG1 (existe para CZD1 e DZDP).
7. **Experimento read-only de maior retorno:** extrair o inner FV do `abl.elf`
   DZG1 e fazer diff ancorado por string/função contra
   `decompiled/abl-inner-oneui8.fv.bin`, procurando **comparação nova** (`cmp` +
   branch) ou validação nova em handlers de fastboot/partição. Sem device.
8. **Custo:** 1–2 dias (extração + diff ancorado). 3–5 dias se virar análise manual.
9. **Probabilidade de primitiva útil:** **baixa-média (~15–25%)**. É a melhor das
   opções disponíveis, o que diz mais sobre as outras do que sobre esta.
10. **Condição de parada:** se o diff DZG1-vs-DZDP do inner FV mostrar apenas
    ruído de recompilação (como CZD1-vs-DZDP mostrou) **e** nenhum handler de
    fastboot/partição ganhou verificação, abandonar. Alternativamente, se os CVEs
    se confirmarem corrigidos antes de abril-2026, abandonar imediatamente.

---

### Linha B — XBL / UEFI / caminho Download-Odin

**Classificação: PRIORIDADE ALTA** (em empate com A; A é mais barato, B é mais profundo)

1. **Fronteira:** USB → XBL SEC/UEFI → verificação da cadeia de boot. Fica
   **estritamente abaixo** do ABL, portanto estritamente antes de qualquer decisão
   de unlock.
2. **Primitiva ganha:** execução antes da verificação de assinatura do BL. É a
   primitiva máxima do sistema. KernelSU não dá nada parecido.
3. **Pode afetar:** tudo abaixo, incluindo ABL, DeviceInfo, AVB.
4. **Evidência a favor:**
   - `uefioneui8.5.img` (7,9 MB, raiz do repo) **nunca foi analisado**. Nenhum
     extrato em `decompiled/` o menciona.
   - CVE-2026-24090 (boot flow via entradas de tabela de partição, 7.1) aponta
     para essa camada.
   - `decompiled/abl-inner-fv-protocol-analysis.txt` e
     `uefi-memcardinfo-producer-analysis.txt` mostram que o ecossistema de
     protocolos UEFI do aparelho já foi parcialmente mapeado — há base.
   - Achado anterior não resolvido: `imagefv.img` tem stream LZMA com tamanho
     declarado `0x543008` mas saída terminando em `0x1a37c1` (3,2× menor). O
     descompressor do XBL SEC **não está no corpus**. Isso é uma discrepância
     real sem veredito.
5. **Evidência contra:** nenhuma evidência de bug. É uma lacuna de cobertura, não
   um achado. XBL é historicamente bem auditado pela Qualcomm.
6. **Não coletado:** descompressor XBL SEC; mapa de módulos do `uefioneui8.5.img`;
   handlers do protocolo de download/Odin; `xbl_s` separado do `xbl`.
7. **Experimento:** extrair e enumerar os módulos DXE/PEI de `uefioneui8.5.img` e
   `partitions_extra/xbl.img`, identificar handlers de USB/download e a cadeia de
   verificação de assinatura do BL, e verificar se `abl`/`xbl_config` são
   verificados por chave de fuse (caso em que qualquer bug de parse ainda precisa
   derrotar a assinatura).
8. **Custo:** 3–5 dias só para construir o corpus minimamente analisável.
9. **Probabilidade:** **baixa (~5–12%)**, mas é a única linha com teto alto.
10. **Condição de parada:** se o mapeamento mostrar que o caminho de download
    valida assinatura antes de qualquer parse de input externo **e** que nenhum
    parser de input não confiável roda antes da verificação, abandonar.

---

### Linha C — Parser do trustlet `engmode` (pré-auth)

**Classificação: INVESTIGAR** (era a aposta principal; caiu após auditoria)

1. **Fronteira:** buffer compartilhado QSEECom → parser de token/ESS dentro da TA.
2. **Primitiva ganha que root não dá:** escrita/execução dentro de uma TA, ou
   corrupção do bitmap de modos, ou do estado persistido em RPMB.
3. **Pode afetar:** bitmap de modos (teoricamente), estado RPMB (teoricamente).
   **Não** afeta ABL diretamente — ABL só lê bit 3 via `GetEMBit(3)`, que por sua
   vez depende de estado validado.
4. **Evidência a favor (o único defeito real encontrado):**
   - **BUG-1 — store-before-check + multiplicação sem teto:**
     ```
     0xb23c  cmp   w4, #0x1f5
     0xb240  strh  w4, [x21, #0x1c]   ; ARMAZENA ANTES do branch
     0xb244  b.hs  #0xb7d4            ; só depois rejeita
     ...
     0xa654  ldrh  w11, [x20, #0x1c]  ; relê o valor armazenado
     0xa66c  add   w9, w9, w11, lsl #2 ; count*4, SEM teto
     0xa674  add   w5, w9, #0x2a      ; w5 = comprimento autenticado
     ...
     0x30fc  bl    #0x275c            ; SHA-256(ctx+0x502, w5)
     ```
     `w5` pode chegar a ~`0x40026` (262 KB) contra um `ctx` de `0x352e0`
     (217 KB) → **out-of-bounds read na heap segura**.
   - Agravante: `ctx` é alocado com `calloc` (zeroed), então o over-read lê
     heap vizinha, não memória não mapeada.
5. **Evidência contra (por que é fraco):**
   - É leitura, **não escrita**. O digest resultante é comparado em `0x32e4` e
     descarta. Não há caminho para influenciar o bitmap nem o RPMB.
   - O gatilho exige um token **rejeitado** (é o próprio parse que falha). Não há
     transição de estado: a TA aborta antes de aceitar qualquer coisa.
   - **Correção a `vulnerability-surface-analysis.txt`:** a alegação
     "MODE count cap 0x80; 0x80 entradas × 4 bytes = 512 bytes num bitmap de
     32 bytes" é **falsa**. Verificado em `0xeb90`–`0xebbc`:
     - stride é **2**, não 4 (`0xeba8 add x9,x9,#2`);
     - `0xeba4 and x12,x12,#0x1ff8` limita o offset a `{0,8,16,24}`;
     - há **um único** store (`0xebbc str x8,[x12,x11]`) em `ctx+0x33f70..0x33f8f`
       = exatamente 32 bytes.
     Não há overflow. O `× 4` do relatório anterior vem de `0xa66c`, que é o
     termo de **comprimento autenticado**, não um tamanho de escrita.
   - **TA-1 (buffer RSA) está morta.** Verificado: `sub sp,sp,#0x1a0`;
     canário em `[x29,#-8]` = `sp+0x138`; `memset(sp+0x38, 0, 0x100)` em
     `0x3288` → o buffer termina **exatamente** no canário, zero de folga.
     LR salvo (`sp+0x148`) fica **acima** do canário. Um único `ret` (`0x3218`),
     verificação de canário sempre executada (`0x31e4`→`0x31f4`→`b.ne 0x3470`).
     E as âncoras são **RSA-2048** (modulus `0x101` bytes), então a recuperação
     tem exatamente 256 bytes. Não há gatilho conhecido, e mesmo com uma folha
     RSA-4096 hipotética o overflow bate no canário e aborta.
   - **Fallback de "dev device" não é bypass.** `0xe90c ldrb w8,[x20,#0x11];
     tbnz w8,#2,#0xe9f0`. O comando 20 é protegido por bit1, então `0xa5cc`
     (verificação de assinatura) roda **antes** do handler. O fallback só
     converte "sem token" de erro em sucesso com **lista de modos vazia**.
     Ele reduz modos, não adiciona. É o oposto do que se precisa.
   - **DID não vem do request.** `INIT` (`0x1183c`) lê em `ctx+0x3125a` com tamanho
     `0x2c00` de fonte da própria TA (provisionamento seguro), não do buffer
     QSEECom. Os três usos do literal `0x3030` (`0x8b28`, `0xafd8`, `0xef54`) são
     verificações de **versão** (`"0002"`/`"0004"`), não de classe de DID.
   - **TOCTOU clássico de QSEECom está fechado:** `tz_app_cmd_handler` (`0x24c`)
     copia o request inteiro (`memcpy` de `0x21c7d` bytes em `0x3c4`) para heap
     seguro **antes** de qualquer parse, exige `reqlen == 0x21c7d` e
     `rsplen == 0x20936` exatos, e usa `qsee_is_ns_range` nos dois buffers.
6. **Não coletado:** formato real do token (necessário para provar se o caminho de
   rejeição do BUG-1 chega a `0xa5cc`); se `__stack_chk_guard` (VA `0x136030`,
   acessado por dupla indireção) é randomizado por boot; se comandos 17/18/20/25/27/36
   são alcançáveis a partir de HLOS.
7. **Experimento:** **primeiro** re-derivar o command map (ver §8, erro E-1) —
   o mapa publicado está errado, então o mapa de alcançabilidade pré-auth atual
   não é confiável. **Depois**, montar harness offline (Unicorn/QEMU) do parser de
   token e fuzza valores de fronteira (0, 1, max-1, max, max+1) **sem device**.
8. **Custo:** 4–8 h para o command map; 2–4 dias para o harness.
9. **Probabilidade de primitiva útil:** **baixa (~8–15%)**, e mesmo o melhor caso
   provável é DoS da TA, não unlock.
10. **Condição de parada:** se o command map corrigido mostrar que nenhum comando
    com bit4 no flags é alcançável sem token, **ou** se o harness offline mostrar
    que o caminho de rejeição aborta antes de `0xa5cc`, abandonar. Também
    abandonar se o patch-diff CZD1→DZDP→DZG1 não mostrar nenhuma verificação
    nova no parser (já se sabe que DZDP→DZG1 é idêntico).

**Nota histórica relevante:** entre CZD1 (dez-2025) e DZDP (abr-2026) **uma**
verificação de contagem foi adicionada ao parser de token, identificada pela
string nova `"%s:%d meta.num_of_data is bigger than max (%d)"` (VA `0xf85fd`) em
`em_token_parse_token_info`. Isso prova que **esse parser já teve um bug real de
validação de contagem**. Mas o aparelho (DZDP) **já tem a correção**. Verificado
também que a comparação é **unsigned** (`0xb104 cmp w4,#5` / `0xb108 b.lo`),
apesar do `%d` no format string — a anomalia `%d` vs `%u` é cosmética, não um bug
de sinal. **ALREADY-PATCHED-ON-DEVICE.**

---

### Linha D — Fronteira HLOS → TA (divergência de validação)

**Classificação: PROVÁVELMENTE PERDA DE TEMPO** (já amplamente respondida; negativo sólido)

1. **Fronteira:** Binder AIDL → `emservice` → `libengmode_server.so` →
   `libengmode_tlc.so` → QSEECom.
2. **Primitiva buscada:** divergência de comprimento/enum que produza corrupção ou
   mudança indevida de estado.
3. **Resultado da auditoria:** **a pilha é consistente.**
   - `libengmode_tlc.so` (15 KB, lido inteiro) **não valida nenhum comprimento** —
     é pass-through puro. O buffer QSEECom é alocado por chamada com
     `align64(reqlen+rsplen)+0x40`, então cabe por construção. Não há buffer
     intermediário de tamanho fixo.
   - `libengmode_server.so` fixa `0x21c7d` / `0x20936` exatamente como a TA exige.
   - ESS: `emEssCommand` (`0x10778 cmp w23,#0xc801; b.lt`, op `<0xa`) e o
     `onTransact` legado impõem o mesmo limite. Iguais nas duas camadas.
   - Contagem de modos: servidor `<0x40` (`0xf110`) vs TA `<0x80`. HLOS mais
     estrito — direção segura.
   - `emGetTokenRequest` (`0xf07c`): `count < 0x40` confirmado, **mas** o VLA de
     pilha e o `memset` executam **antes** da checagem (`0xf0fc`/`0xf10c` vs
     `0xf110`). VLA é dimensionado ao próprio `count`, então **não há overflow** —
     só uma alocação de pilha de até 128 KB controlada pelo chamador (DoS).
   - Laço de troca de bytes: o caminho escalar roda `count-1` iterações
     (`0xf478 lsr w8,w9,#1`) então o **último modo nunca é convertido e fica 0**;
     os caminhos vetoriais leem até 14 bytes além do vetor de entrada, mas o VLA
     arredondado absorve e só `count*2` bytes são repassados. **Bug de
     corretude, não de memória.**
   - `emGetModesBit` (`0x11db8`–`0x11dd0`): copia para fora com comprimento
     **vindo da TA** (`ldr w2,[x8]` em `rsp+0x14132`) sem clamp, contra um vetor
     de 32 bytes. O comprimento vem do **trustlet**, não do chamador root.
     Robustez TA→HLOS, não primitiva de ataque.
   - `EngineeringModeHandler::callerCheck` (`0xb68c`, `mov w0,wzr; ret`) tem
     **zero call sites**. É código morto. O peso que `findings.md` claim 12 dá a
     ele como "bypass de allowlist" está superestimado.
4. **Evidência contra a linha:** todas as verificações HLOS ≥ TA. Nenhuma
   divergência explorável encontrada.
5. **Não coletado:** `.te` policy de `emservice`/`hal_engmode_default`;
   desserialização Bn (`vendor.samsung.hardware.security.engmode-service` é
   stripped).
6. **Experimento:** nenhum de alto valor. Se quiser fechar de vez: confirmar via
   Bn se vetores curtos (<15/6/8 bytes) são aceitos nos campos de tamanho fixo
   (`0xf3ec`, `0xf410`, `0xf438`) — é OOB read de poucos bytes, baixo valor.
7. **Custo:** ~4 h para fechar formalmente.
8. **Probabilidade:** **muito baixa (<5%)**.
9. **Condição de parada:** já atingida na prática. Encerrar depois de documentar
   o resultado negativo.

---

### Linha E — Movimentação lateral em Secure World

**Classificação: INTERESSANTE MAS INDIRETA** com probabilidade efetiva muito baixa

1. **Fronteira:** TA comprometida → TA `engmode` / estado RPMB dela.
2. **Primitiva buscada:** leitura/escrita arbitrária dentro de outra TA, ou acesso
   à partição RPMB do `engmode`.
3. **Análise de lateralidade (explícita, não hand-waving):**
   - Cada TA em QTEE moderno tem espaço de endereçamento isolado (tabelas por-TA,
     reforçadas por stage-2/xPU). TA↔TA só via `qsee_open_session` num UUID
     registrado. Controlar a TA-A **não** dá a memória da TA-B.
   - Armazenamento seguro é **namespacepor TA**. `qsee_stor_open_partition` para a
     partição `"engmode"` resolve contra a **identidade da TA chamadora**. Uma TA
     comprometida não consegue nomear nem abrir a partição RPMB do `engmode`.
     Esse é o bloqueio duro, e é arquitetural.
   - `tz.mbn` (o kernel QSEE) é **byte-idêntico** em toda a janela — nenhuma
     correção de core evidenciada aqui.
   - **CVE-2026-25276 / 25277 / CVE-2025-59604** (Secure Processor / StrongBox,
     jun-2026, críticos): o dispositivo os registra (`IKeyMintDevice/strongbox`,
     `vendor.spcom.load.sp_keymaster=1`), mas StrongBox roda no **SPU**, um
     microprocessador **fisicamente separado** do QTEE. O `S:C` do CVSS significa
     escape SPU→HLOS, não SPU→QTEE. Não há ponte.
   - **CVE-2026-24080** (TA de biometria, ago-2026) — **SM-S928B não está na lista
     de afetados**.
   - **CVE-2026-24083** (`securemsm-kernel` IOCTL) — não se aplica a este SoC; e
     mesmo se aplicasse, é bug de driver HLOS (root já tem).
   - Nenhum CVE no intervalo nomeia `engmode`, `vaultkeeper`, `bksecapp`,
     `tz_kg`, `hdcp`, `hermes`, `rtts`, `mpos`, `khdm` ou `drk`.
4. **Evidência contra:** todas as TAs idênticas entre abril e julho de 2026 →
   **nenhuma janela de patch-diff**. Sem par pré/pós, só sobra fuzzing cego, que é
   o oposto da estratégia pedida.
5. **Não coletado:** firmware SPU (`sp_keymaster`, `spss` — vêm de
   `/vendor/firmware`, não de tar de BL); conteúdo do boletim Qualcomm de
   julho-2026 (página primária não renderizou).
6. **Experimento:** coletar firmware SPU e diffá-lo, **apenas** se aparecer um par
   pré/pós. Caso contrário, não fuzzar cegamente.
7. **Custo:** alto (semanas) para probabilidade baixa.
8. **Probabilidade de chegar ao estado do `engmode` a partir de outra TA:**
   **muito baixa (<5%)** mesmo assumindo RCE na TA de origem.
9. **Condição de parada:** enquanto nenhuma TA do corpus mudar entre duas builds,
   esta linha fica em banho-maria. Reativar só com um par pré/pós real.

---

### Linha F — OEM-lock HAL

**Classificação: JÁ MORTA PELA EVIDÊNCIA**

1. **Fronteira:** nenhuma. É a resposta: **não há HAL de OEM lock neste aparelho.**
2. **Primitiva:** nenhuma. Mesmo que existisse, `PersistentDataBlockLock` só
   reflete política de UI/HLOS.
3. **Evidência (nova, desta revisão):**
   - `device_extra/lshal-full.txt` (lista completa de serviços HIDL binderizados,
     113 linhas): **zero** ocorrências de `oem`.
   - `device_extra/vintf_manifests/` (60 arquivos de manifest VINTF): `grep -ri oem`
   retorna **nada**. Não existe `android.hardware.oemlock.xml` nem
   `android.hardware.oemlock@1.0.xml`. HALs AIDL de vendor **declaram** VINTF.
   - `device_extra/vendor-bin.txt` e `system-bin.txt`: **zero** `oem`.
   - `device_extra/ps-context-full.txt`: nenhum processo oemlock.
   - A única ocorrência em todo o corpus é
     `oem_lock: [android.service.oemlock.IOemLockService]` — o serviço Java.
   - Conclusão: `VendorLockHidl` **ausente**; `VendorLockAidl` **ausente**;
     backend ativo = **`PersistentDataBlockLock`**, cujo
     `isOemUnlockAllowedByCarrier()` é o inverso da restrição `no_oem_unlock` do
     usuário do sistema.
4. **Por que não resolve:** nada nesse caminho escreve em `devinfo` nem influencia
   a decisão ABL/AVB. `SetUnlocked` (`0x424cc`) continua sendo o único escritor de
   `+0x0d`, e só é alcançado pelo bit 3 do EM.
5. **Experimento:** nenhum necessário. A coleta mínima pedida **já foi feita** e
   respondeu.
6. **Custo:** zero. **Probabilidade:** zero. **Condição de parada:** atingida.

---

### Linha G — `devinfo` (edição direta e parser)

**Classificação: JÁ MORTA PELA EVIDÊNCIA**

- Edição direta: morta por `findings.md` e reforçada aqui — `SetUnlocked` é o
  único escritor e é alimentado por `GetEMBit(3)`.
- **Parser (novo):** `DeviceInfoInit` (`0x425ec`) faz `mov w2,#0xcd0` e lê exatamente
  `0xcd0` bytes para um buffer fixo. **Nenhum campo de offset ou comprimento é lido
  do conteúdo de `devinfo`.** Estrutura plana, sem parser. Não é superfície.
- O caminho de erro `MemCardInfo` (`0x93f0`) só **preserva** um `1` pré-existente;
  não cria um. E não há como criar o pré-existente.
- **Abandonar.**

---

### Linha H — UFSDxe (kioxia debug-info)

**Classificação: INTERESSANTE MAS INDIRETA**

- `0x145a8`–`0x145dc`: `str w11,[x26,x10,lsl #2]` com `x10` = byte sem checagem,
  `x26` = tabela de 256 entradas × 4 bytes = 1024 bytes. Índice máximo `0xFF` →
  offset `0x3FC` → **dentro da tabela**. Escrita in-table, não OOB.
- Requer **injeção de resposta UFS**, ou seja, hardware ou acesso ao controlador
  UFS. Root em HLOS não dá isso.
- Consumidor downstream (`0x14628`, `0x14648`) usa os valores para seleção de
  comando UFS; efeito não derivável estaticamente.
- **Probabilidade: muito baixa. Custo: alto (hardware).** Manter congelada.

---

### Linha I — ESS / `commandForESS`

**Classificação: PROVÁVELMENTE PERDA DE TEMPO**

- Parser TA exige versão `01`, 11 tokens não vazios + componente vazio final,
  SHA-256 do corpo comparado byte a byte, comprimento de cert vs decodificado.
  Decodificação termina em `em_ess_encrypt_message` para **criptografar a saída**;
  não é raiz de confiança de validação.
- Reassembly `0,5,<seq>`/`FFF` é em **Java** (`EngModesCmdHelper`) e está limitado
  a 51200 bytes em `emEssCommand` (`0x10778`).
- A autoridade emissora não está no corpus e não é derivável.
- **Abandonar** salvo obtenção de uma captura do serviço externo.

---

## 5. Top 5 experimentos read-only de maior retorno

| # | Experimento | O que resolve | Custo | Pré-requisito |
|---|---|---|---|---|
| 1 | **Extrair inner FV do `abl.elf` DZG1 e diff ancorado por string/função vs DZDP** | Se CVE-2026-24088/24090/24085-24092 estão corrigidos no DZG1 e **o que** mudou. Único par pré/pós real na árvore. | 1–2 d | `scripts/extract_linuxloader.py` aplicado ao DZG1; **não** diff byte-level da imagem inteira (ruído ~30%) |
| 2 | **Mapear os módulos de `uefioneui8.5.img` + `xbl.img` e localizar o handler de download/Odin e a verificação de assinatura do BL** | Se existe parser de input não confiável rodando antes da verificação de assinatura | 3–5 d | extrator de FV; corpus XBL SEC |
| 3 | **Re-derivar o command map da TA a partir da tabela `0xf5083` (dispatch `0x5020`) e refazer o mapa de alcançabilidade pré-auth** | Corrige `findings.md` claim 7 e diz se BUG-1 é alcançável. Barato e destrava a decisão sobre a linha C. | 4–8 h | nada — só capstone |
| 4 | **Mapear todas as entradas pré-AVB que o ABL consome e classificar quais são cobertas por AVB** | Define a superfície real de input root-controlável antes do AVB (`devinfo`/`persistent`/`frp`/`secdata`/`steady` vs `boot`/`vbmeta`) | 1 d | grafo de chamadas do LinuxLoader |
| 5 | **Harness offline (Unicorn/QEMU) do parser de token da TA + fuzz de fronteira** | Testa BUG-1 e o parser TLV sem tocar no device e sem mudar estado | 2–4 d | formato do token (ainda inferido) |

**Não fazer:** executar tx 11 (`makeTokenReq`). Ele popula cache de nonce na TA —
é mudança de estado, mesmo que não persista em RPMB. Está fora do escopo
read-only acordado.

---

## 6. Artefatos faltantes

Priorizados por quanto destravariam.

| Artefato | Para quê | Bloqueia |
|---|---|---|
| Inner FV do `abl.elf` **DZG1** | patch-diff do cluster CVE-2026-2408x | Linha A (prioridade) |
| `xbl_s` / descompressor XBL SEC | resolver a discrepância LZMA de `imagefv` (`0x543008` vs `0x1a37c1`) | Linha B |
| Mapa de módulos de `uefioneui8.5.img` (7,9 MB, nunca analisado) | handlers de download/Odin, cadeia de verificação | Linha B |
| Firmware SPU (`sp_keymaster`, `spss`, de `/vendor/firmware`) | diff de CVE-2026-25276/25277 | Linha E |
| Formato do token `engmode` (especificação) | prover/refutar alcançabilidade do BUG-1 | Linha C |
| Boletim Qualcomm **julho-2026** (página primária) | fechar a janela de CVEs | Linhas A/B/E |
| `.te` policy de `emservice`, `hal_engmode_default` | afirmar com certeza o que root alcança | Linha D |
| `boot.img`, `init_boot.img`, `vendor_boot.img` | análise de parse de boot image pelo ABL | Linha A |
| `frp`, `steady` (imagens) | mapa de input pré-AVB não verificado | Linha A |

**Já coletado e suficiente:** tudo o que responde a linha F (OEM-lock HAL) e a
linha G (parser de `devinfo`).

---

## 7. Hipóteses que devem ser abandonadas

| Hipótese | Por que morreu |
|---|---|
| **OEM-lock HAL (AIDL/HIDL) como caminho até o ABL** | Não existe HAL de OEM lock no aparelho (lshal sem `oem`, nenhum manifest VINTF, nenhum binário). Backend é PDB = puro HLOS. |
| **Edição direta de `devinfo+0x0d`** | `SetUnlocked` é o único escritor e é alimentado por `GetEMBit(3)`. |
| **Parser de `devinfo` como superfície** | Leitura fixa de `0xcd0` bytes, estrutura plana, nenhum offset/comprimento vindo do conteúdo. |
| **Overflow do bitmap de modos (512 bytes em 32)** | Falso. Stride 2 (`0xeba8`) + máscara `0x1ff8` (`0xeba4`). Um único store em 32 bytes. |
| **Overflow da recuperação RSA (TA-1)** | Âncoras RSA-2048; buffer termina exatamente no canário (`0x38+0x100 = 0x138`); canário sempre verificado; LR acima dele. |
| **Fallback "dev device" como bypass de assinatura** | Comando 20 é bit1 → `0xa5cc` roda antes. Fallback devolve lista **vazia** de modos. |
| **DID controlável pelo request** | DID vem de provisionamento da TA (`ctx+0x3125a`, `0x2c00`); os `0x3030` são verificações de versão. |
| **TOCTOU de QSEECom no request** | Request copiado inteiro (`memcpy` `0x21c7d` em `0x3c4`) antes de qualquer parse; comprimentos fixos. |
| **`callerCheck` como bypass de allowlist** | Código morto: zero call sites. |
| **`libengmode15.so` na cadeia de runtime** | Já morta em `findings.md`; reforçada (não é `DT_NEEDED` nem mapeada). |
| **Divergência HLOS→TA** | Pilha consistente; HLOS sempre ≥ TA em rigor. |
| **`num_of_data` do parser de token** | Bug real, mas **corrigido no aparelho** (DZDP já tem a checagem; ausente só no CZD1). |

---

## 8. Possíveis erros ou pontos fracos da pesquisa existente

Esta é a seção mais desconfortável. Cada item tem evidência verificável.

### E-1 — `scripts/ta_audit.py`: o COMMAND_MAP é hardcoded e está errado

`ta_audit.py:213` imprime:

```
"COMMAND_MAP recovered from the range-checked branch tables in the dispatcher:"
```

Mas as linhas 214–236 são uma **lista literal fixa no código**. Nada é derivado do
binário. Pior: o conteúdo está errado.

**Verificado.** A entrada real é `tz_app_cmd_handler` em **VA `0x24c`** (`0x24c sub
sp,sp,#0x50`, e sua primeira chamada de log usa `__func__ == "tz_app_cmd_handler"`).
A função `0x49b0` que o relatório chama de dispatcher contém **três** jump tables:

| tabela | VA | dispatch | função |
|---|---|---|---|
| 1 | `0xf503a` (37 B) | `0x49c4`–`0x49d8` | **qual linha de log imprimir** |
| 2 | `0xf505f` (36 B) | `0x4d9c`–`0x4db0` | classe de flags de requisito |
| 3 | `0xf5083` (37 B) | `0x5014`–`0x5020` | **o handler de verdade** |

O relatório decodificou a **tabela 1** e a tratou como dispatcher. A tabela 1 não
despacha: cada entrada loga e cai em `0x4bd4`.

Decodificando a tabela 3 (`72 75 8c 8f 8f 8f 8f 8f 8f 8f 9a 00 ae b1 8f b4 00 00 8f
b7 ba 8f bd c4 cc 00 00 00 00 00 00 00 cf d2 d5 00 7a`, base `0x502c`, `cmd = idx+1`):

| cmd | bloco | handler real | relatório anterior |
|---|---|---|---|
| 11 | `0x5294` | `0x52dc bl 0x13940` | `0x13940` ✓ |
| 12 | `0x502c` | `0x5030 bl 0x14cec` | ✓ |
| **13** | `0x52e4` | `0x52e8 bl 0x8900` | relatório atribui `0x8900` ao **16** ✗ |
| **14** | `0x52f0` | `0x52f4 bl 0x14aa0` | não listado ✗ |
| 15 | `0x5268` | rejeita | — |
| **16** | `0x52fc` | `0x5300 bl 0xe248` | relatório diz `0x8900` ✗ |
| **17, 18** | `0x502c` | ESS `0x14cec` | **omitidos** ✗ |
| 19 | `0x5268` | rejeita | — |
| **20** | `0x5308` | `0x530c bl 0xe81c` | relatório diz `0xe248` ✗ |
| 21 | `0x5314` | `0x5318 bl 0xea8c` | ✓ |
| 22 | `0x5268` | rejeita | — |
| 23/24/25 | `0x5320`/`0x533c`/`0x535c` | `0x14128`/`0xecb0`/`0x1183c` | ✓ |
| 26–32 | `0x502c` | ESS | ✓ |
| 33/34/35 | `0x5368`/`0x5374`/`0x5380` | `0xf8c4`/`0xfa24`/`0xfcd0` | ✓ |
| 36 | `0x502c` | ESS | ✓ |
| **37** | `0x5214` | **nenhum handler** — zera 0x20 bytes em `ctx+0x33e5c` e retorna sucesso | "special dispatcher block" ✗ |

**Impacto:** `findings.md` claim 7 ("Dispatcher at VA 0x49b0 with branch tables to
INIT/INSTALL_TOKEN/GET_MODES_BIT/TOKEN_REQUEST/ESS 26-32") tem proveniência falsa e
dois alvos errados. Qualquer conclusão que nomeie handler por command ID a partir de
`ta-command-storage-evidence.txt` precisa ser re-derivada — **incluindo o mapa de
alcançabilidade pré-auth**. Isso é pré-requisito para a linha C.

### E-2 — `decompiled/bootloader-dzdp-vs-dzg1-diff.txt` transformou "não medido" em "verificado"

A tabela diz `engmode.mbn <-> ../partitions/em.img  NO_BASELINE`. A seção
INTERPRETATION diz: *"So is every other TA (tz, vaultkeeper, tz_kg, **engmode**,
hyp, ...)"* — ou seja, apresentou ausência de medição como resultado positivo de
identidade.

Reexecutado corretamente (lz4.frame em todos os 30 membros; comparação só de
PT_LOAD), o resultado é: **engmode DZG1 é de fato idêntico a `em.img`.** A
conclusão por acaso estava certa, mas o método não a sustentava. Um leitor que
confiasse no relatório estaria certo por acidente.

Causa-raiz: o fluxo exigia um membro DZG1 pré-extraído em `partitions_extra/`.
Existia para keymint (`keymint-dzg1-jul2026.mbn`), nunca foi gerado para engmode.
Não era problema de lz4.

**Achado colateral:** `partitions/em-czd1.img` é byte-idêntico ao `engmode.mbn` do
CZD1. Uma baseline CZD1 estava no repo, sem uso.

### E-3 — `vulnerability-surface-analysis.txt` superestimou dois candidatos

- **UFS-1** foi descrito como "1020-byte OOB write" numa revisão e corrigido para
  in-table na própria seção 4.2 — mas a tabela de ranking (§9) ainda lista
  "PRIMITIVE_CONFIRMED" com confiança High. É uma escrita **dentro** de uma tabela
  de 1024 bytes, com índice máximo `0xFF` → offset `0x3FC`. Não é OOB.
- **"0x80 × 4 bytes num bitmap de 32 bytes"** (§3.1, nota 3) é falso — ver E-5.

### E-4 — `findings.md`: hashes de âncora "não verificáveis" estão verificáveis

Ver §2, P7. Os dois hashes de `original-research.md` são exatamente os slots 0 e 2.

### E-5 — `findings.md` claim 8/9 e a "anomalia RSA-4096"

A seção "What is still unknown" mantém em aberto "se um leaf RSA-4096 é aceito pela
política atual do S24". Isso agora tem resposta parcial: as **âncoras** são
RSA-2048 (modulus `0x101` bytes, verificado por DER walk). Um leaf RSA-4096 tem
SPKI de 550 bytes e não casa com nenhuma âncora de 294 bytes. Combinado com a
geometria da pilha (buffer encostado no canário), TA-1 não tem gatilho conhecido.
Pode ser marcado como **morto**, não "desconhecido".

### E-6 — `scripts/dex_audit.py`: falha de parse indistinguível de "não é o pacote"

```python
def apk_package(archive: Path) -> str:
    if archive.suffix.lower() != ".apk":
        return ""
    try:
        return APK(str(archive), testzip=False).get_package() or ""
    except Exception:
        return ""
```

Se o androguard falhar ao parsear um APK, o resultado é `""` — idêntico a "não é o
pacote procurado". Um `NO_MATCH_IN_COVERED_ARTIFACTS` pode ser na verdade
"falha de parse". Isso afeta `findings.md` claim 20 (HLOS/KMX), já marcada como
"Partial". Há **13** `except Exception` largos em 11 scripts
(`dex_audit.py:458,647`, `tlc_analysis.py`, `server_analysis.py`, `pltmap.py`,
`extract_dxe_fv.py`, `dxe_fv_analysis.py`, `elftools_helpers.py`,
`_resolve_ufsdxe_base.py`, `elf_decode.py`, `ta_review.py`).

### E-7 — Conclusões que dependem de um único caminho de CFG

`findings.md` claim 5 ("EM bit 3 alimenta `SetUnlocked` antes do AVB") e toda a
análise em `abl-devinfo-bypass-analysis.txt` repousam sobre um recorte de CFG de
`0x9240` a `0x96f8`. O próprio relatório já admite `EM_SYNC_DOMINATES_AVB_BLOCK=False`.
O valor dessa linha é **preservação** de estado, não criação — e não há criador.
Marcar como confirmado-mas-irrelevante, não como lead.

### E-8 — Divergência entre relatório manual e saída automatizada

`findings.md` §"Trustlet" diz que `GET_MODES_BIT` "caps the mode count at `0x80`",
o que está certo, mas atribui isso ao command 21 sem notar que o comando 21 é um
dos poucos mapeados corretamente. Já `ta-command-storage-evidence.txt` erra 16 e 20.
Ou seja: **o relatório manual e o script discordam e ninguém os reconciliou.**

---

## 9. Plano de patch-diff

**Princípio:** diff de bugs conhecidos > fuzzing cego. E diff sem par pré/pós não
existe — então o primeiro passo é sempre estabelecer o par.

### 9.1 Estado atual da baseline (medido, não inferido)

Comparação por conteúdo de PT_LOAD (padding de partição excluído por construção).

| Imagem | DZDP (abr-2026, device) | DZG1 (jul-2026) | CZD1 (dez-2025) | Veredito |
|---|---|---|---|---|
| `engmode` | — | **idêntico** | diferente | sem janela abr→jul |
| `keymint` | — | idêntico | idêntico | sem janela |
| `tz`, `tz_kg`, `tz_iccc`, `tz_hdm` | — | idêntico | diferente (menos `tz_iccc`) | sem janela |
| `vaultkeeper` | — | idêntico | diferente | sem janela |
| `hyp`, `storsec`, `bksecapp`, `uefi_sec`, `shrm`, `cpucp`, `aop`, `qupv3fw`, `imagefv` | — | idêntico | — | sem janela |
| **`devcfg`** | `2079af49…` | `1212d8df…` | `d24a0c2b…` | **MUDOU** — ~23,5 KB em 14 regiões, todo em blob de config/fuse (`version`, `max_version`, `tlm_total_gp`, `OEM_ese_spi_block…`, `/configs`) |
| **`abl`** | `7df5e15b…` | `e875b1c2…` | `b99eda5b…` | **MUDOU** — alvo principal |

Âncoras RSA: 4 SPKIs, idênticos em CZD1, DZDP e DZG1 (4 módulos distintos, hashes
de módulo estáveis). **Samsung não rotacionou o conjunto de âncoras.**

### 9.2 Metodologia

1. **Nunca** diffar imagem inteira de `abl.elf` — ele embrulha um FV comprimido.
   Byte-diff dá ~30% de churn mesmo entre builds quase idênticas, e ~49% no
   inner-FV. Ambos os números são artefato. Usar diff ancorado por string/função
   (como `scripts/abl_audit_czd1.py` já faz).
2. Para TAs: comparar só PT_LOAD. Para `em.img`, comparar **só PT_LOAD** — o
   arquivo inteiro difere (`d3ae9558…` vs `ac9e4116…`) apenas em metadados fora
   dos segmentos: campo de versão anti-rollback (`05`→`06`) e a cadeia de
   certificados do signer (`C=KR`, `emailAddress=m.sec.key@samsung.com`,
   "Cert for Official ECC TA"). Código idêntico.
3. Mudança de string é o sinal mais barato. A string nova
   `"meta.num_of_data is bigger than max (%d)"` foi exatamente assim que se
   detectou a única correção funcional do parser entre CZD1 e DZDP.
4. **Rotina:** a cada novo BL tar de S928B, extrair, comparar PT_LOAD por imagem,
   e se algo mudou, fazer diff de strings primeiro, depois de instruções.

### 9.3 Janela coberta e lacunas

- Coberto: dez-2025 (CZD1) → abr-2026 (DZDP/device) → jul-2026 (DZG1).
- **Lacuna: boletim Qualcomm de julho-2026.** Página primária não renderiza; só há
   um agregador não corroborado citando `CVE-2026-30001`–`CVE-2026-30045`.
   **Tratar como não-mapeado, não como vazio.**
- **Lacuna: ASB 2026-05…08.** `source.android.com/docs/security/bulletin/2026-06-01`
   dá 404; a AOSP reestruturou. Usar boletins Qualcomm como fonte primária.
- **Lacuna: SPU/StrongBox.** Firmware não vem em tar de BL. Sem par pré/pós,
   CVE-2026-25276/25277 não são diffáveis.

### 9.4 Próximos BLs a obter

Qualquer build S928B posterior a julho-2026, mais alguma build **entre** abril e
julho de 2026 se existir (fecharia a janela do cluster CVE-2026-2408x).

---

## 10. Próximo passo recomendado

**Fazer o experimento 1: extrair o inner FV do `abl.elf` do DZG1 e diffar contra
o DZDP com ancoragem por string/função.**

Razão objetiva:
- É o **único** par pré/pós-correção real na árvore.
- É a **única** fronteira onde a primitiva buscada (execução/escrita antes do AVB)
  entrega o objetivo sem precisar derrotar isolamento de Secure World — que é
  arquitetural e não tem janela de patch.
- Custo baixo (1–2 dias), e o resultado é binário e decisório: ou aparece uma
  verificação nova num handler de partição/fastboot, ou é ruído de recompilação.
- Se der negativo, **a linha A morre** e sobra apenas a linha B (XBL), que é mais
  cara e mais profunda. É melhor saber isso em 2 dias do que em 2 meses.

**Não** começar pela linha C (parser da TA). Ela depende do command map corrigido
(E-1) e, corrigido, o teto de valor é DoS.

**Sequência sugerida:** experimento 1 → (se positivo) análise manual do handler →
(em paralelo, baixo custo) experimento 3 para corrigir o command map e fechar a
linha C formalmente → (se 1 der negativo) experimento 2, XBL.

---

## 11. Tabela final

| Rank | Target | Primitiva buscada | Acesso existente | Primitiva faltante | Evidência | Prob. | Custo | Condição de parada |
|---|---|---|---|---|---|---|---|---|
| **1** | **ABL pré-AVB** (patch-diff CVE-2026-24088/24090/24085-24092; parsers de partição não verificada) | Execução/escrita antes de `avb_slot_verify`; `SetUnlocked(1)` com persistência | Root HLOS; par DZDP↔DZG1 medido | Entregar input controlado ao ABL com BL travado (USB ou partição não-AVB) | `abl` muda abr→jul (PT_LOAD `7df5e15b…`→`e875b1c2…`); CVE-2026-24088 publicado, 8.2; `DeviceInfoInit` lê fixo `0xcd0` | **15–25%** | 1–2 d (diff), 3–5 d (análise) | Diff do inner FV mostra só ruído de recompilação **e** nenhum handler de fastboot/partição ganhou verificação; ou CVEs confirmados corrigidos antes de abr-2026 |
| **2** | **XBL / UEFI / Download-Odin** (`uefioneui8.5.img`, `xbl.img`, `imagefv`) | Execução antes da verificação de assinatura do BL | Root HLOS; corpus parcial de protocolos UEFI | Descompressor XBL SEC; handlers de download/Odin; mapa de módulos | `uefioneui8.5.img` (7,9 MB) nunca analisado; discrepância LZMA `0x543008` vs `0x1a37c1` sem veredito; CVE-2026-24090 | **5–12%** | 3–5 d | Caminho de download valida assinatura antes de qualquer parse de input externo |
| **3** | **Parser do trustlet `engmode` (pré-auth)** | Escrita/execução na TA; corrupção do bitmap de modos ou do estado RPMB | Root alcança o transporte (tx 3/5/7/22 provadas) | Um bug de **escrita** pré-auth — nenhum encontrado | BUG-1 real mas OOB **read**/DoS (`0xb240` store-before-check, `0xa66c` sem teto); TOCTOU fechado; fallbacks mortos | **8–15%** (melhor caso = DoS) | 4–8 h (mapa) + 2–4 d (harness) | Command map corrigido mostra que nenhum comando bit4 é alcançável sem token; ou harness mostra abort antes de `0xa5cc` |
| **4** | **Secure World lateral** (keymint/vaultkeeper/tz → engmode) | Acesso à partição RPMB do `engmode` ou memória de outra TA | Nenhum par pré/pós | Uma TA vulnerável **com** rota de lateralidade | Todas as TAs idênticas abr→jul; `tz.mbn` idêntico; RPMB namespacepor TA; SPU fisicamente isolado do QTEE | **<5%** | semanas | Permanecer congelada enquanto nenhuma TA mudar entre builds; reativar só com par pré/pós |
| **5** | **UFSDxe (kioxia debug-info)** | Escrita indexada → corrupção de estado de comando UFS | Nenhum (requer injeção de resposta UFS) | Acesso ao controlador UFS / hardware | `0x145d8 str w11,[x26,x10,lsl #2]`, mas índice máx `0xFF` → offset `0x3FC`, **dentro** da tabela de 1024 B | **<5%** | alto (hardware) | Efeito downstream (`0x14628`/`0x14648`) mostrar que os valores não afetam seleção de comando |
| **6** | **Fronteira HLOS→TA** | Divergência de comprimento/enum → corrupção | Root chama tudo | Uma divergência real — não há | `libengmode_tlc.so` é pass-through sem validação; HLOS sempre ≥ TA; ESS limitado igual nas duas camadas | **<5%** | ~4 h | Já atingida. Encerrar após documentar o negativo |
| **7** | **ESS / `commandForESS`** | Forjar request aceito pela autoridade externa | Root monta envelope | A autoridade emissora (fora do corpus) | Parser TA exige 11 tokens + SHA-256 + len de cert; cert só **cifra a saída** | **~0%** | — | Obter captura do serviço externo, ou abandonar |
| **8** | **OEM-lock HAL** | Chegar ao estado consumido pelo ABL | — | — | **Não existe HAL**: lshal sem `oem`, nenhum manifest VINTF, nenhum binário. Backend = PDB, puro HLOS | **0%** | 0 | **Morta** |
| **9** | **`devinfo` (edição direta e parser)** | Escrever `IsUnlocked=1` | Root escreve a partição | Um escritor que não passe por `GetEMBit(3)` | `SetUnlocked 0x424cc` é o único escritor; `DeviceInfoInit` lê fixo `0xcd0`, estrutura plana | **0%** | 0 | **Morta** |
| **10** | **Criptografia do token** | Forjar token modo 3 | — | Chave privada da Samsung | RSA-2048 sobre SHA-256, MODE na região assinada, âncoras não rotacionadas desde dez-2025 | **~0%** | — | **Morta** |

---

## Apêndice A — Verificações byte-level feitas nesta revisão

Todas executadas contra `partitions/em.img` e `decompiled/linuxloader-oneui8.pe`
com capstone; reproduzíveis.

| Item | Local | Resultado |
|---|---|---|
| Geometria das âncoras RSA | VA `0xf3cca`, DER walk | `SEQUENCE(0x122)`, modulus `len=0x101` → **2048 bits**, exp `010001` |
| Hash da âncora slot 0 | `sha256(0x126 B @ 0xf3cca)` | `42edf9dd5623f3149bceb84e9ab085e4c919e8691a4501af9c58bab16ab91ec6` = hash do doc original |
| Hash da âncora slot 2 | `sha256(0x126 B @ 0xf3f16)` | `8ed537b2f076791f7d93d14c1e1bc28d15151045a1615330549844ab0311cca4` = hash do doc original |
| Store-before-check | `0xb23c`/`0xb240`/`0xb244` | `cmp w4,#0x1f5` → `strh w4,[x21,#0x1c]` → `b.hs`. **Confirmado** |
| Multiplicação sem teto | `0xa654`/`0xa66c`/`0xa674` | `ldrh w11,[x20,#0x1c]`; `add w9,w9,w11,lsl #2`; `add w5,w9,#0x2a`. Sem comparação entre eles. **Confirmado** |
| Laço do bitmap | `0xeb90`–`0xebc0` | stride `2` (`0xeba8`); `and x12,x12,#0x1ff8` (`0xeba4`); store único `0xebbc`, base `x11=0x33f70`. **Relatório anterior errado** |
| Frame do verificador | `0x3070`, `0x3288`, `0x31e4`, `0x3218` | `sub sp,sp,#0x1a0`; canário `[x29,#-8]`=`sp+0x138`; `memset(sp+0x38,0,0x100)`; LR em `sp+0x148`; `ret` único. **Zero folga antes do canário** |
| Entrada da TA | `0x24c` | `tz_app_cmd_handler`; `qsee_is_ns_range` ×2; `reqlen==0x21c7d`, `rsplen==0x20936`; `memcpy` único do request |
| Tabela de handlers | `0xf5083`, dispatch `0x5014`–`0x5020` | 37 entradas; ESS = {12,17,18,26–32,36}; 15/19/22 rejeitam; 37 sem handler |
| Checagem `num_of_data` | `0xb100`–`0xb108` | `ldur w4,[x29,#-0x18]`; `cmp w4,#5`; **`b.lo`** → unsigned. `%d` no log é cosmético |
| Escritor de `IsUnlocked` | `0x42524` | `strb w19,[x1,#0xd]` — único no ABL |
| `DeviceInfoInit` | `0x4260c` | `mov w2,#0xcd0` — leitura de tamanho fixo, sem campos de offset do conteúdo |

## Apêndice B — O que **não** foi feito (escopo)

Nenhum comando mutante foi executado. Nenhum `installToken`, `removeToken`,
comando de fuse, `AT+FRPUNLCK`, escrita de partição, escrita de `devinfo` ou leitura
de RPMB. Nenhum artefato original foi alterado. Nenhum payload foi produzido.
`makeTokenReq` (tx 11) foi deliberadamente **não** executado por popular cache de
nonce na TA. Todo o trabalho é estático ou leitura de arquivos já coletados.
