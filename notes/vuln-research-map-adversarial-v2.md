# Mapa de Vuln Research — revisão adversarial #2 (S24 Ultra, DZDP)

Alvo: SM-S928B (`e3q`), `S928BXXU5DZDP`, Android 16 / One UI 8.5, SPL **2026-04-05**, SoC SM8650.
Root: KernelSU temporário. Bootloader travado durante toda a coleta.
Data: 2026-08-31. Modo: estático + leitura de artefatos. Nada mutante foi executado.
Atualização 31/08 (tarde): o experimento discriminador da Linha A2 foi executado e deu
**negativo** — ver §4 e `decompiled/abl-avb-gate-discriminator.txt`.

Este documento é uma **revisão adversarial** do repo *e* de `notes/vuln-research-map.md`
(2026-08-29). Onde discorda, a discordância vem com offset, instrução e o comando que
reproduz. Níveis: **CONFIRMADO** · **PROVÁVEL** · **POSSÍVEL** · **ESPECULAÇÃO**.

---

## 1. Resumo executivo

**Conclusão honesta: sem uma vulnerabilidade pré-AVB, o objetivo é inalcançável. E a
rota de Secure World está bloqueada arquiteturalmente e sem janela de patch-diff. Então
é pré-AVB ou nada — e o pré-AVB, neste aparelho, está pior do que o mapa anterior dizia.**

Três coisas mudaram em relação ao mapa de 29/08:

1. **A prioridade #1 do mapa anterior está morta.** CVE-2026-24088 (a aposta central,
   15–25%) tem como patch `f08125d8 "QcomModulePkg: Drop GBL related changes"` — a
   remoção do GBL de dentro do ABL. O ABL deste aparelho tem **zero** ocorrência de
   qualquer artefato GBL. O componente vulnerável não está no binário. Cai para
   **JÁ MORTA PELA EVIDÊNCIA (N/A)**.
2. **A cadeia de exploit público também não se aplica.** A injeção de cmdline
   (`fastboot oem set-gpu-preemption 0 androidboot.selinux=permissive`) que a comunidade
   usou depende de handlers fastboot da Qualcomm que **não existem** neste ABL:
   zero ocorrências de `getvar`, `download:`, `flash:`, `flashing`, `oem unlock`,
   `selinux`, `set-gpu-preemption` em todo o corpus ABL extraído.
3. **Sobrou exatamente um CVE de boot-flow com correção real em edk2 — CVE-2026-24090** —
   e ele era *precisamente* o tipo de primitiva pedida: uma estrutura **não assinada e
   gravável por root** (a tabela de partições GPT) decidindo se a verificação de boot
   roda. **O experimento discriminador foi executado em seguida e deu negativo.**
   Detalhe em §4 (Linha A2) e em `decompiled/abl-avb-gate-discriminator.txt`: o ABL
   Samsung **não** possui `Is_VERIFIED_BOOT_2()` nem equivalente (conjunto exaustivo de
   35 literais UTF-16 referenciados por código, nenhum `vbmeta`); `avb_slot_verify` é
   chamado **incondicionalmente** em `0x18f98`; e "Device is unlocked, Skipping boot
   verification" é emitida *depois* da verificação, selecionada por
   `is_device_unlocked` da saída do AVB, não antes dela. **A linha morreu.**
   Efeito colateral útil: a cadeia `avb_slot_verify → read_is_device_unlocked (0x51048)
   → IsUnlocked (0x41ed0) → devinfo+0x0d ← GetEMBit(3)` ficou confirmada ponta a ponta,
   reforçando P1–P4.

   **Consequência: os dois CVEs de boot do boletim Qualcomm jun-2026 que afetam
   SM8650 (24088 e 24090) estão ambos fora de alcance neste aparelho.** A hipótese
   "chegar ao AVB por estrutura de disco não assinada" está fechada para a GPT.

E duas coisas pioraram a qualidade percebida da evidência existente:

4. **A evidência que matava a Linha F (OEM-lock HAL) era metodologicamente inválida.**
   O grep rodou no diretório errado; os manifests `android.hardware.oemlock*.xml`
   existem, mas são **placeholders de 0 bytes**. 11 dos 28 arquivos da raiz de
   `device_extra/` estão vazios, incluindo `vintf-dump.txt`. A coleta falhou
   silenciosamente. **A conclusão sobrevive** — por evidência de runtime melhor
   (`lshal-full.txt` e `service-list-full.txt`), não por VINTF. Mas é o mesmo erro
   (E-2) que o próprio mapa anterior criticou.
5. **O command map da TA publicado está errado de um jeito que importa**, e a versão
   corrigida (§4, linha C) revela **cinco comandos sem requisito de token** que o mapa
   anterior não identificou. Não é um achado de memória — é cobertura.

**Veredito final, sem otimismo (atualizado após o experimento A2):** o caminho realista
é extremamente improvável. Os dois CVEs de boot do boletim Qualcomm jun-2026 que afetam
SM8650 — as únicas portas com mecanismo de falha publicado — estão ambos fora de
alcance neste aparelho. O que resta é pesquisa original, sem nenhuma vulnerabilidade
conhecida como ponto de partida: UEFI variables primeiro (barata, 1–2 d), XBL/Odin
depois (cara, 3–5 d só de corpus). Probabilidade agregada de chegar ao unlock:
**single-digit %**. Se a motivação for o unlock em si, o custo esperado não fecha.

---

## 2. O que a pesquisa já provou

Tratado como estabelecido. Tudo que foi re-verificado nesta passagem está marcado ✔.

| # | Fato | Base | Re-verificado aqui |
|---|---|---|---|
| P1 | `IsUnlocked` lê `0x170e28+0x0d`; callback AVB em `0x51048` chama `0x41ed0` (`ldrb w3,[x19,#0xe35]`) | ABL PE | ✔ |
| P2 | `SetUnlocked` (`0x42524`, `strb w19,[x1,#0xd]`) é o único escritor de `+0x0d` | varredura de todos os `strb ...,#0xd` do `.text` | ✔ |
| P3 | `DeviceInfoInit` (`0x425ec`) lê **fixo** `0xcd0` bytes (`0x4260c mov w2,#0xcd0`); nenhum offset/comprimento vem do conteúdo | ABL PE | ✔ |
| P4 | Política OEM/FRP do One UI 7 removida: `0xa141c mov w0,wzr` | ABL PE | ✔ |
| P5 | Token: `ENG`/`MODE`/`VALI`/`INTE`; MODE na região assinada; RSA-2048 sobre SHA-256; 4 âncoras SPKI fixas e não rotacionadas CZD1→DZDP→DZG1 | TA + mapa anterior | ✔ (hash das âncoras confere com o doc original) |
| P6 | Estado EM em RPMB (AES-GCM + `qsee_kdf`) | imports `qsee_stor_*` | ✔ |
| P7 | `tz_app_cmd_handler` (VA `0x24c`): `calloc(1,0x352e0)`, `calloc(0x21c7d)` + `memcpy` único, `qsee_is_ns_range` ×2, comprimentos exatos `0x21c7d`/`0x20936` | TA | ✔ TOCTOU fechado |
| P8 | BUG-1: store-before-check em `0xb23c/0xb240/0xb244`; multiplicação sem teto em `0xa654/0xa66c/0xa674` | TA | ✔ confirmado |
| P9 | Bitmap de modos: stride 2 (`0xeba8`), `and x12,x12,#0x1ff8` (`0xeba4`), store único (`0xebbc`), offset máx 24 + 8 B = 32 B exatos | TA | ✔ sem OOB |
| P10 | `num_of_data`: `0xb100 cmp w4,#5` / `0xb108 b.lo` → comparação **unsigned** | TA | ✔ |
| P11 | Todas as TAs idênticas entre o dump de abr-2026 e o DZG1 de jul-2026; só `devcfg` e `abl` mudam | `bootloader-dzdp-vs-dzg1-diff.txt` | não re-verificado nesta passagem (ver §8, E-9) |
| P12 | Boletim Qualcomm **julho-2026**: filtrando Boot/HLOS/Secure Processor/Trusted Application/bootloader/partition/secure storage/trustlet → só CVE-2026-21383, e **SM8650 não está na lista de afetados** | fonte primária | ✔ novo |

---

## 3. Fronteiras que ainda importam

Ordenadas por valor decrescente. O que mudou vs. o mapa anterior está em **negrito**.

**F-1. Tabela de partições (GPT) → decisão de verificado-boot (pré-AVB).**
A GPT é não assinada, é parseada antes de `avb_slot_verify`, e é gravável por root
(SELinux permitting). Tinha a melhor razão payoff/custo do mapa.
**Fechada em 31/08:** o ABL não usa presença de partição para decidir se verifica
(35 literais UTF-16, nenhum `vbmeta`; `0x18f98` incondicional). Ver §4 Linha A2.

**F-2. UEFI variables (`uefivarstore`) → ABL (pré-AVB).**
Superfície pré-AVB clássica. `partitions_extra/uefivarstore.img` foi coletado e
**nunca aparece em nenhum extrato de `decompiled/`**. Buraco de cobertura puro.
(Nova.)

**F-3. ABL / LinuxLoader (pré-AVB, entradas não cobertas por AVB).**
`devinfo` (parser morto), `persistent`, `frp`, `secdata`, `steady`, GPT, DTBO,
bootconfig de recovery. Continua sendo a única fronteira onde a primitiva entrega
direto o objetivo — mas as duas portas públicas conhecidas (24088/24090) estão
fechadas ou em dúvida.

**F-4. XBL / Download-Odin.**
Estritamente abaixo do ABL. Teto altíssimo, custo altíssimo, **zero** evidência de bug.
`uefioneui8.5.img` (5 MB na raiz do repo) nunca foi analisado.

**F-5. Trustlet `engmode` (pré-auth).**
Importa porque é o guardião do estado. A auditoria (mapa anterior + esta) não achou
primitiva de **escrita** pré-auth. Reabre parcialmente porque o command map corrigido
mostra handlers alcançáveis sem token (§4, linha C).

**F-6. Secure World lateral.** Bloqueada (namespace de RPMB por TA) e **sem janela de
patch-diff** no intervalo coberto. SPU/StrongBox é a exceção: provavelmente vulnerável
e presente, mas sem rota até o objetivo.

**F-7. HLOS→TA.** Auditada, consistente. Fechada.

---

## 4. Ranking das superfícies de ataque

---

### Linha A1 — CVE-2026-24088 (GBL dentro do ABL)

**Classificação: JÁ MORTA PELA EVIDÊNCIA (N/A para este aparelho)**
*(o mapa anterior: PRIORIDADE ALTA, 15–25%)*

1. **Fronteira:** input não confiável → código ABL que decide o estado de unlock.
2. **Primitiva:** escrita não autenticada de partição → carregar bootloader customizado.
3. **Afetaria:** ABL inteiro, DeviceInfo, AVB. Sim — se existisse.
4. **Evidência a favor:** boletim Qualcomm junho-2026; `Snapdragon 8 Gen 3 Mobile
   Platform` e `SM8650Q` explicitamente na lista de afetados; CVSS 8.2, `S:C`;
   reportado 2026-01-18, OEMs notificados 2026-03-02, publicado 2026-06-01 — o
   aparelho (SPL 2026-04-05) é anterior.
5. **Evidência contra — decisiva, e é nova:**
   - O único patch listado no boletim é
     `f08125d8 QcomModulePkg: Drop GBL related changes`
     (`git.codelinaro.org/clo/la/abl/tianocore/edk2`). Mensagem: *"All GBL changes are
     now part of OSS UEFI. This reverts commit d93f155a, 6259d5e4, 38faa371."*
     28 inclusões, **1672 exclusões**, removendo `Library/gbl/GblAvbProtocol.c`,
     `GblOsConfigurationProtocol.c`, `DtFixupProtocol.c`, `EFIGblAvbProtocol.h`,
     `EFIGblOsConfigurationProtocol.h`, `EFIDtFixup.h`. **O "conserto" é remover o GBL.**
   - Varredura do corpus ABL — `linuxloader-oneui8.pe`, `abl-inner-oneui8.fv.bin`,
     `abl-main.pe`, `odin-oneui8.pe` e os 109 módulos `dxe_modules/*.efi`:
     `gbl`=0, `GBL`=0, `GblAvb`=0, `GblOsConfiguration`=0, `DtFixup`=0, `dtfixup`=0.
   - Conclusão: **o componente vulnerável não está no binário.** O S24 usa LinuxLoader
     UEFI clássico, não GBL.
6. **Não coletado:** nada relevante. A pergunta está respondida.
7. **Experimento:** nenhum. Refazer só se aparecer um ABL com GBL.
8. **Custo:** 0.
9. **Probabilidade de primitiva útil:** **~0%.**
10. **Condição de parada:** atingida.

**Impacto no mapa anterior:** a linha que consumiria 1–2 dias (e era o "próximo passo
recomendado") não produziria nada. Redirecionar esse tempo para A2 e B2.

---

### Linha A2 — CVE-2026-24090: `Is_VERIFIED_BOOT_2()` consultando a GPT em runtime

**Classificação: JÁ MORTA PELA EVIDÊNCIA (N/A)** — experimento executado em 31/08, negativo

> **Resultado do experimento.** Evidência completa em
> `decompiled/abl-avb-gate-discriminator.txt`. Resumo:
> - Conjunto **exaustivo** de literais UTF-16 referenciados por código no
>   LinuxLoader: **35 entradas**. Nomes de partição presentes: `user_dtbo`,
>   `recoveryfs`, `recovery`, `boot_a`, `boot_b`, `init_boot`, `super`, `abl_x`,
>   `system`, `swap_a`, `EDL`, `vendor_boot`, `modem`, `ImageFv`, `misc`, `boot`,
>   `emac`, `debug`, `sysfont2x`. **Nenhum `vbmeta`, `vbmeta_a`, `vbmeta_system`
>   ou `dtbo`.**
> - `avb_slot_verify` (`0x18f98`) é chamado **incondicionalmente**. O único teste
>   anterior é `0x18e08`, cuja falha vai para log de erro — não existe caminho que
>   pule a verificação.
> - `"Device is unlocked, Skipping boot verification"` não é um gate: é emitida em
>   `0x16390` **depois** de `0x18f98` retornar, quando `[x19+0x438] == 2`.
> - O único escritor capaz de produzir `2` é `0x159f4`, vindo de
>   `ldrb w8,[x20]` — o bool `is_device_unlocked` do `AvbSlotVerifyData`. Os outros
>   sete escritores (`0x14988`, `0x14b30`, `0x15024`, `0x1505c`, `0x15220`,
>   `0x15540`, `0x168c8`) fixam `3` (erro).
> - Cadeia confirmada: `0x18f98` → `read_is_device_unlocked` (`0x51048`) →
>   `IsUnlocked` (`0x41ed0`) → `devinfo+0x0d` ← `GetEMBit(3)`.

1. **Fronteira:** GPT (estrutura **não assinada**, gravável por root) → decisão de
   rodar ou não a verificação AVB 2.0. Atravessa "input não confiável" → "código que
   decide se verifica", **estritamente antes** de `avb_slot_verify`.
2. **Primitiva ganha que KernelSU não dá:** desligar o verified boot com uma escrita de
   partição. KernelSU é pós-boot, pós-AVB, volátil. Isso é persistente e pré-AVB.
3. **Afetaria:** a decisão AVB inteira (sim). Não toca a TA `engmode` nem o RPMB, e
   **não precisa** — contornar a verificação é suficiente para bootar imagem não
   assinada, que é o objetivo prático.
4. **Evidência a favor:**
   - Dois commits de correção listados no boletim, ambos em
     `QcomModulePkg/Library/avb/VerifiedBoot.c`:
     `b746f76e8ab52c60fc18460900bb2982301522f8` e
     `07665c08352d0051a627d5b42ae0ad1487f29afc`, ambos
     *"edk2: Set VB2 status at compile time"*.
   - Mensagem do commit, literal: *"This change aviods the risk of verified boot being
     disabled by attacker who gains the ability to modify the GPT partition table."*
   - Código vulnerável (removido pelo patch):
     ```c
     BOOLEAN Is_VERIFIED_BOOT_2 (VOID) {
       GetPartitionCount (&PtnCount);
       PtnIdx_a = GetPartitionIndex ((CHAR16 *)L"vbmeta_a");
       if (PtnIdx_a < PtnCount && PtnIdx_a != INVALID_PTN) return TRUE;
       else { PtnIdx = GetPartitionIndex ((CHAR16 *)L"vbmeta");
              if (PtnIdx < PtnCount && PtnIdx != INVALID_PTN) return TRUE; }
       return FALSE;                       // <- AVB 2.0 inteiro desligado
     }
     ```
   - `Snapdragon 8 Gen 3 Mobile Platform` e `SM8650Q` na lista de afetados.
   - O aparelho (SPL 2026-04-05) é anterior à notificação a OEMs (2026-03-02).
5. **Evidência contra:**
   - **Zero ocorrências de `vbmeta_a` em UTF-16** em todo o corpus ABL
     (`linuxloader-oneui8.pe`, `abl-inner-oneui8.fv.bin`, `abl-main.pe`, 109 módulos
     `dxe_modules/*.efi`). **Zero de `vbmeta` em UTF-16** também. Como
     `GetPartitionIndex()` em edk2 recebe `CHAR16*`, o literal teria de estar lá.
   - As 38 ocorrências ASCII de `vbmeta` no LinuxLoader são strings de log:
     `"Loading vbmeta struct from partition '`, `"VB2: Found SecurityLevel from vbmeta
     (override)"`, `"Error verifying vbmeta image: invalid vbmeta header"`,
     `"assert fail: vbmeta_num_read <= vbmeta_size"`.
   - A política AVB da Samsung em `0x140dc` é custom (`ldrb w8,[x0,#1]; cbnz
     w8,#0x14270`), sem sonda de GPT visível no topo.
   - **Confirmado pelo experimento.** O fork de edk2 da Samsung **divergiu antes de o
     probe entrar**: não há `Is_VERIFIED_BOOT_2()` nem equivalente.
6. **Não coletado:** nada. A pergunta está respondida — a condição de parada foi atingida.
7. **Experimento:** executado em 31/08. Negativo. Ver quadro no topo desta seção.
8. **Custo:** 0 (já pago: 2 h, 100% offline).
9. **Probabilidade de primitiva útil:** **~0%.** Duas observações independentes
   concordam: ausência exaustiva de literais CHAR16 `vbmeta`, e ausência de qualquer
   teste de partição antes de `0x18f98`.
10. **Condição de parada:** **atingida.** Nenhum literal UTF-16 de nome de partição
    alcança a decisão de verificação. A ideia de chegar ao AVB pela GPT está fechada.

**Nota de segurança:** o experimento confirmatório empírico (escrever a GPT e remover
`vbmeta`) **não foi executado e não é necessário** — a ausência do código que reage a
essa condição já resolve a pergunta estaticamente. Isso é bom: a alternativa era
mutante e com risco real de brick.

---

### Linha B2 — UEFI variables → ABL (pré-AVB)

**Classificação: PRIORIDADE ALTA** (nunca tocado; superfície clássica; custo baixo)

1. **Fronteira:** armazenamento de variáveis UEFI (lido por ABL e por `uefisecapp`)
   → decisões de boot. Roda antes e independente do AVB.
2. **Primitiva:** influenciar uma decisão pré-AVB (estado de lock, slot, política de
   verificação) sem assinatura.
3. **Afetaria:** potencialmente a decisão AVB e o `IsUnlocked`.
4. **Evidência a favor:**
   - `partitions_extra/uefivarstore.img` **existe e não aparece em nenhum extrato** de
     `decompiled/`. Nunca analisado.
   - `partitions/uefisecapp.img` (TA de UEFI vars / VaultKeeper) existe; o mapa anterior
     só diz que "não gerencia tokens engmode" — o que é verdade e é irrelevante aqui.
   - `decompiled/VaultKeeper-V1-ndk-imports.txt` e `vaultkeeper-V1-ndk-imports.txt`
     existem, e `vendor.samsung.hardware.security.vaultkeeper.ISehVaultKeeper/default`
     está vivo em runtime. VaultKeeper é exatamente o mecanismo Samsung de dados
     autenticados persistidos via UEFI vars.
   - `uefi-memcardinfo-producer-analysis.txt` (67 KB) e
     `abl-inner-fv-protocol-analysis.txt` (31 KB) mostram que o ecossistema de
     protocolos UEFI do aparelho já foi parcialmente mapeado — há base para andar rápido.
5. **Evidência contra:** nenhuma evidência de bug. É lacuna de cobertura, não achado.
   Variáveis Samsung são tipicamente autenticadas; as não autenticadas podem existir e
   ser irrelevantes.
6. **Não coletado:** parse de `uefivarstore.img`; inventário de GUIDs de variáveis; o
   consumidor ABL de cada variável; `init-rc-TAs.txt` já lista serviços relevantes.
7. **Experimento:** parsear `uefivarstore.img`, enumerar nomes/GUIDs de variáveis e
   tamanhos, e cruzar com writers em HLOS (`VaultKeeperService`, `ISehVaultKeeper`) e
   readers no ABL (`GetVariable`/`GetNextVariableName` no inner FV). Classificar cada
   variável como autenticada ou não.
8. **Custo:** 1–2 d.
9. **Probabilidade:** **8–15%.**
10. **Condição de parada:** se todas as variáveis que o ABL consulta antes do AVB forem
    autenticadas (ou se o ABL não consultar nenhuma antes do AVB), abandonar.

---

### Linha C — Parser do trustlet `engmode` (pré-auth)

**Classificação: INVESTIGAR** (caiu; reabre parcialmente pelo command map corrigido)

1. **Fronteira:** buffer QSEECom → parser de request/token dentro da TA.
2. **Primitiva buscada:** escrita/execução na TA, corrupção do bitmap de modos ou do
   estado em RPMB.
3. **Afetaria:** bitmap de modos (teoricamente), RPMB (teoricamente). **Não** afeta o
   ABL diretamente.
4. **Evidência — o que esta revisão corrigiu e acrescentou:**

   **(a) Command map re-derivado (CONFIRMADO, substitui o publicado).**
   `tz_app_cmd_handler` em VA `0x24c` → `0x4978` (dispatcher real). Três jump tables:

   | tabela | VA | base | papel |
   |---|---|---|---|
   | T1 | `0xf503a` (37 B) | `0x49e4` | **só escolhe a string de log** |
   | T2 | `0xf505f` (36 B) | `0x4dbc` | **flags de requisito** (`orr` por comando) |
   | T3 | `0xf5083` (37 B) | `0x502c` | **o handler** |

   Dispatch T3: `0x5000 sub w8,w4,#1; cmp w8,#0x24; b.hi 0x5268` → comandos 1..37.
   Dispatch T2: `0x4d90 sub w8,w4,#1; cmp w8,#0x23; b.hi 0x4df8` → comandos 1..36.

   | cmd | handler | flags de requisito | | cmd | handler | flags |
   |---|---|---|---|---|---|---|
   | 1 | `0xd118` | 2 | | 20 | `0xe81c` | 0x12 |
   | 2 | `0xd830` | 2 | | 21 | `0xea8c` | 2 |
   | 3 | `0xce04` | 2 | | 22 | rejeita | 2 |
   | 4–10 | rejeita | 0 | | 23 | `0x14128` | 0x22 |
   | **11** | `0x13940` | **0** | | 24 | `0xecb0` | 0x22 |
   | **12** | ESS `0x14cec` | **0** | | 25 | `0x1183c` | 0x16 |
   | 13 | `0x8900` | 4 | | 26 | ESS | 0x10c |
   | 14 | `0x14aa0` | 0xc | | 27 | ESS | 0x12 |
   | 15 | rejeita | 0 | | **28** | ESS | **0** |
   | **16** | `0xe248` | **0** | | 29 | ESS | 0xc |
   | 17,18 | ESS | 0x12 | | 30 | ESS | 0x10e |
   | 19 | rejeita | 0 | | **31** | ESS | **0** |
   | | | | | 32 | ESS | 4 |
   | | | | | 33/34/35 | `0xf8c4`/`0xfa24`/`0xfcd0` | 0x10e/2/2 |
   | | | | | 36 | ESS | 0x12 |
   | | | | | 37 | sem handler | 2 |

   **Diferenças vs. o mapa anterior:** cmd 13→`0x8900` (não 16); cmd 14→`0x14aa0`
   (não listado); cmd 16→`0xe248` (o mapa atribuía `0xe248` ao 20); cmd 20→`0xe81c`
   (é o que contém o fallback de dev device em `0xe90c`); cmds 17 e 18 → ESS (omitidos).

   **(b) Cinco comandos não exigem token (NOVO).**
   Comandos 11, 12, 16, 28, 31 têm flags de requisito = 0. O gate de assinatura
   (`bl 0xa5cc` em `0x4e68`) só é alcançado quando o **bit 1** está setado
   (`0x4e34 tbnz w8,#1,#0x4ed0` → `0x4ed0` exige `[ctx+8]` bit0 → `0x4e50 tbz
   w8,#1,#0x4ffc`). Sem bit1, o comando vai direto para o handler.
   Com destaque para o **cmd 16 → `0xe248`**: frame de pilha de `0x640` bytes,
   `memset(sp,0,0x634)`, `calloc(1,0x604)`, checagens `ctx+0x19` bit2 / `ctx+0x0d` bit3,
   e `bl 0x86d4(ctx+0x3125a, buf, 0x604)`. **Não foi identificado nesta passagem** — é o
   próximo alvo de leitura.
   `a5cc` continua protegendo os comandos que importam (21 = GET_MODES_BIT, 20 = GET_MODES).

   **(c) Os flags vêm do request, mas só por OR (CONFIRMADO — fecha "state machine
   confusion" no dispatcher).**
   `ctx+0x18` é preenchido em `0x5b18` a partir de `parsed+0x20`, que vem do buffer
   QSEECom. Mas T2 faz `ldr x8,[x21]; orr x8,x8,#const; str x8,[x21]` — **OR monotônico**.
   Um atacante **adiciona** bits, nunca limpa. Não há como desarmar o requisito de
   token. Design acidentalmente seguro.

   **(d) O parser de request é bounds-checked (CONFIRMADO — mata "parser differential"
   no topo da pilha).**
   `0x5390` copia campos com o helper `0x9b24(dst, dst_field_size, src, src_len=0x21c7d,
   &offset, n)`:
   ```
   0x9b4c ldr w4,[x4]      ; offset
   0x9b50 add w5,w4,w5     ; offset + n
   0x9b54 cmp w5,w3        ; vs src_len (0x21c7d)
   0x9b58 b.ls  #0x9b98    ; senão erro
   0x9b98 cmp w19,w1       ; n vs dst_field_size
   0x9b9c b.ls  #0x9bec    ; senão erro
   0x9bec memcpy; 0x9c00 *offset += n
   ```
   Todos os `n` observados são constantes de compile-time. **Nenhum campo de
   comprimento vem do request.** O acumulador é 32 bits contra `src_len` de 0x21c7d,
   então não wraparound.
   (Nota de completude: o struct parseado tem `0x21ca0` bytes; com o flag `+0x610` bit0
   entram `0x11000` bytes em `+0x630` → `0x11630`; com bit5, `0x2c00` em `+0x1f09c` →
   `0x21c9c`. Ambos cabem, com folga de 4 bytes no segundo caso. Apertado, mas correto.)

   **(e) BUG-1 continua sendo o único defeito real, e é leitura.**
   Store-before-check (`0xb23c`/`0xb240`/`0xb244`) e multiplicação sem teto
   (`0xa654`/`0xa66c`/`0xa674`) confirmados. O digest resultante é comparado em `0x32e4`
   e descartado. Não há caminho até o bitmap nem até o RPMB.

   **(f) Correção ao mapa anterior sobre o cmd 37.** Não é "zera 0x20 bytes e retorna
   sucesso" sem mais. Ele exige flags bit3 limpo, `[ctx+8]` bit5 setado, flags bit0xa
   limpo, `[ctx+8]` bit0x15 setado; chama `0x96fc(ctx+0x3125a, 0x2c00)` — que é um
   **teste "tudo zero?"** (retorna 0 se todos os bytes forem zero, `0xf0f00001` caso
   contrário), **não** um memset; o resultado é descartado; então zera 0x20 bytes em
   `ctx+0x33e5c` e retorna 0. Comando de limpeza de identidade, bem protegido. Sem valor.

5. **Evidência contra a linha como um todo:** nenhuma primitiva de **escrita** pré-auth
   encontrada; o único defeito é OOB read num caminho que já está sendo rejeitado.
6. **Não coletado:** identidade do handler `0xe248` (cmd 16); formato real do token;
   alcançabilidade de 13/14/17/18/25/27/29/30/32/33 por HLOS.
7. **Experimento:** (i) 2–4 h — identificar `0xe248` e `0x8900`/`0x14aa0`;
   (ii) 2–4 d — harness offline (Unicorn/QEMU) do parser de token, fuzz de fronteira
   (0, 1, max-1, max, max+1) em `count` e nos campos de `+0x610`.
8. **Custo:** 4–8 h (identificação) + 2–4 d (harness).
9. **Probabilidade de primitiva útil:** **8–15%**, e o melhor caso provável continua
   sendo DoS da TA, não unlock.
10. **Condição de parada:** se `0xe248` for um getter sem efeito de estado **e** o
    harness mostrar que BUG-1 aborta antes de `0xa5cc`, abandonar.

---

### Linha D — Fronteira HLOS → TA (divergência de validação)

**Classificação: PROVÁVELMENTE PERDA DE TEMPO**

Mantém-se o negativo do mapa anterior (`libengmode_tlc.so` é pass-through sem validação;
o buffer QSEECom é dimensionado por construção; ESS limitado igual nas duas camadas;
`<0x40` no servidor vs `<0x80` na TA = HLOS mais estrito; `callerCheck` é código morto).
**Reforçado aqui:** a camada mais baixa do lado TA (`0x9b24`) valida os dois lados de
cada cópia, então a "divergência de interpretação entre Binder e QSEE" que a pergunta
do usuário procura foi explicitamente procurada e **não existe** no caminho principal.

- **Custo para fechar formalmente:** ~4 h.
- **Probabilidade:** **<5%.**
- **Condição de parada:** atingida. Documentar e encerrar.

---

### Linha E1 — Movimentação lateral em Secure World (QTEE)

**Classificação: INTERESSANTE MAS INDIRETA**

Inalterada: armazenamento seguro é namespacepor TA; TA↔TA só por UUID registrado;
`tz.mbn` idêntico na janela; nenhuma TA mudou entre abr-2026 e jul-2026 → **sem par
pré/pós → sem patch-diff**; boletim de julho-2026 não tem nada de secure world.

- **Novo nesta revisão:** `storsec.mbn` (`partitions_extra/storsec.img`) é o serviço de
  armazenamento seguro. É o **único** componente cuja confusão de namespace produziria
  exatamente a primitiva que esta linha persegue (ler/escrever a partição RPMB do
  `engmode`). Nunca foi analisado. Se aparecer um par pré/pós para **`storsec`**, esta
  linha sobe para INVESTIGAR.
- **Probabilidade (mesmo assumindo RCE na TA de origem): <5%.** **Custo:** semanas.
- **Condição de parada:** congelada enquanto nenhuma TA mudar entre builds.

---

### Linha E2 — Secure Processor / StrongBox (CVE-2026-25276 / 25277)

**Classificação: INVESTIGAR** (provavelmente vulnerável e presente; sem rota até o objetivo)

1. **Fronteira:** HLOS → SPU (StrongBox KeyMint).
2. **Primitiva:** corrupção de memória dentro do SPU.
3. **Afetaria:** chaves do StrongBox. **Não** afeta `engmode`, RPMB do QTEE, ABL ou a
   decisão de secure boot.
4. **Evidência a favor:**
   - CVE-2026-25276 (CWE-129, *"Memory corruption while using Strongbox due to missing
     bounds check"*) e CVE-2026-25277 (CWE-120, *"...due to buffer overflow"*).
     Ambos **CVSS 8.8, Security Rating Critical**, ambos com
     `Snapdragon 8 Gen 3 Mobile Platform` **e** `SM8650Q` na lista.
   - O aparelho tem SPU ativa: `[glink_spss]` e `[irq/466-glink-native-spss]` em
     `device/processes.txt`; `vendor.spcom.load.sp_keymaster=1`, `sp_nvm=1`,
     `cryptoapp=1`, `asym_cryptoap=1`; `libspcom.so` em `/vendor/lib64`;
     `android.hardware.security.keymint.IKeyMintDevice/strongbox` registrado.
   - SPL 2026-04-05 < publicação 2026-06-01 → muito provavelmente sem correção.
5. **Evidência contra como caminho até o objetivo:** SPU é um processador fisicamente
   separado do QTEE. O `S:C` do CVSS indica escape SPU→HLOS, não SPU→QTEE. **Não há
   ponte conhecida** até o estado do `engmode`.
6. **Não coletado:** firmware do SPU (`/vendor/firmware/spss*`, `sp_keymaster*`) —
   **não vem no tar de BL**. Sem ele não há diff.
7. **Experimento:** coletar `/vendor/firmware/spss*` de duas builds (DZDP e uma
   posterior a jul-2026) e diffar. Só vale se o par existir.
8. **Custo:** baixo para coletar (1 h), alto para analisar.
9. **Probabilidade de chegar ao unlock:** **<3%.** Probabilidade de ser um bug real e
   presente: **média-alta (~50%)** — mas é um bug em outro prédio.
10. **Condição de parada:** se o objetivo for estritamente unlock, abandonar. Se for
    research de secure world, coletar o firmware e diffar — é o único alvo de secure
    world com par pré/pós plausível.

---

### Linha F — OEM-lock HAL

**Classificação: JÁ MORTA PELA EVIDÊNCIA** — mas a evidência do mapa anterior era inválida

1. **Fronteira:** nenhuma. Backend ativo = `PersistentDataBlockLock`, puro HLOS.
2. **Primitiva:** nenhuma. Mesmo que existisse HAL, nada nesse caminho escreve
   `devinfo` nem influencia a decisão ABL/AVB.
3. **O erro do mapa anterior (NOVO, e é grave):**
   - Afirmação: *"`device_extra/vintf_manifests/` (60 arquivos): `grep -ri oem` retorna
     nada. Não existe `android.hardware.oemlock.xml` nem `...@1.0.xml`."*
   - Realidade: os arquivos **existem**, mas em `device_extra/` (raiz), não em
     `vintf_manifests/`: `_vendor_etc_vintf_manifest_android.hardware.oemlock.xml` e
     `_vendor_etc_vintf_manifest_android.hardware.oemlock@1.0.xml`.
   - **Ambos têm 0 bytes.** 11 dos 28 arquivos da raiz de `device_extra/` estão vazios:
     `vintf-dump.txt`, `vintf-manifest.xml`, `manifest_manifest_pineapple.xml`,
     `manifest_manifest_cliffs.xml`, `manifest_iweaver_aidl_v2.xml` e **todos** os
     `_vendor_etc_vintf_manifest_*`.
   - Conclusão: a coleta **falhou silenciosamente** e gerou placeholders. O grep rodou
     no diretório errado e só encontrou os placeholders. É exatamente o erro E-2 que o
     próprio mapa anterior diagnosticou no diff das TAs.
4. **A conclusão sobrevive por evidência melhor, verificada aqui:**
   - `device_extra/lshal-full.txt` (13 KB, não vazio): **0** ocorrências de `oem` →
     sem serviço HIDL oemlock.
   - `device_extra/service-list-full.txt` (33 KB, 500+ entradas): **só**
     `oem_lock: [android.service.oemlock.IOemLockService]`. **Não há**
     `android.hardware.oemlock.IOemLock/default` (AIDL). O mesmo arquivo lista
     `IKeyMintDevice/default`, `IKeyMintDevice/strongbox`,
     `IRemotelyProvisionedComponent/default`, `ISehVaultKeeper/default` → a coleta é
     sensível a HALs AIDL de vendor, então a ausência é um negativo real.
   - `vendor-bin.txt`, `system-bin.txt`: 0 ocorrências de `oem`.
   - `ps-context-full.txt`: nenhum processo oemlock.
   - Em `vendor-lib64.txt`, "oem" só aparece em `liboemaids_vendor.so`,
     `liboemcrypto.so`, `libqape_oem_ext.so`, `libwpa_drv_oem.so` — nada de oemlock.
5. **Ação colateral obrigatória (não é sobre unlock):** refazer a coleta de VINTF.
   `vintf-dump.txt` vazio significa que **nenhuma** conclusão sustentada naquele
   diretório é confiável.
6. **Custo:** 0 para a conclusão; ~1 h para refazer a coleta. **Probabilidade:** 0.

---

### Linha G — `devinfo` (edição direta e parser)

**Classificação: JÁ MORTA PELA EVIDÊNCIA**

- Edição direta: `SetUnlocked` (`0x42524`) é o único escritor de `+0x0d`, alimentado por
  `GetEMBit(3)`. Varredura completa de `strb` para `#0xd`/`#0xe` no `.text` confirma:
  os únicos com a base `0x170e28` são `0x42524`, `0x425a0` e o zeroing em `0x426fc`.
  Os demais (0x1d060…, 0x512d0…) usam registradores de string/stack.
- Parser: `0x4260c mov w2,#0xcd0` — leitura de tamanho fixo. Estrutura plana.
- Caminho de erro `MemCardInfo` só preserva um 1 pré-existente; não cria.
- **Abandonar.**

---

### Linha H — UFSDxe (kioxia debug-info)

**Classificação: INTERESSANTE MAS INDIRETA** (congelada)

Inalterada: `0x145d8 str w11,[x26,x10,lsl #2]` com índice máx `0xFF` → offset `0x3FC`,
**dentro** da tabela de 1024 B. Requer injeção de resposta UFS = hardware. Root não dá.
Manter congelada.

---

### Linha I — ESS / `commandForESS`

**Classificação: PROVÁVELMENTE PERDA DE TEMPO**

Parser TA exige versão `01`, 11 tokens não vazios + componente vazio final, SHA-256,
comprimento de cert vs decodificado. O certificado do envelope **cifra a saída**; não é
raiz de confiança. A autoridade emissora não está no corpus. Abandonar salvo captura do
serviço externo.

---

## 5. Top 5 experimentos read-only de maior retorno

| # | Experimento | O que resolve | Custo | Pré-requisito |
|---|---|---|---|---|
| ~~1~~ | ~~Discriminar CVE-2026-24090 no ABL Samsung~~ | **EXECUTADO EM 31/08 — NEGATIVO.** Sem `Is_VERIFIED_BOOT_2()`; `avb_slot_verify` incondicional | ~~2–4 h~~ | — |
| **1** | **Parsear `partitions_extra/uefivarstore.img`** e cruzar leitores no ABL com escritores em HLOS (VaultKeeper) | Se existe variável UEFI não autenticada consumida antes do AVB. **Última superfície pré-AVB barata que sobrou.** | 1–2 d | extrator de FV/varstore; `uefisecapp.img` |
| **2** | **Identificar os handlers `0xe248` (cmd 16) e `0x8900`/`0x14aa0` (13/14)** | Fecha a questão "existe estado pré-auth na TA?" com o command map correto | 4–8 h | capstone; `em.img` |
| **3** | **Refazer a coleta de VINTF e de `lshal`/`service list`** sem placeholders vazios | Restaura a confiabilidade de tudo que foi concluído a partir de `device_extra/` (não só OEM lock) | ~1 h (device) | `adb shell su -c` |
| **4** | **Mapear as demais entradas pré-AVB do ABL**: `persistent`, `frp`, `secdata`, `steady`, DTBO, bootconfig de recovery | Completar o mapa de input não verificado consumido antes de `0x18f98` | 1–2 d | imagens já coletadas |
| **5** | **Harness offline (Unicorn/QEMU) do parser de token da TA + fuzz de fronteira** | Testa BUG-1 e o parser sem tocar no device | 2–4 d | formato do token (ainda inferido) |

**Não fazer:** escrever a GPT, `installToken`, `removeToken`, comandos de fuse,
`AT+FRPUNLCK`, escrita de partição, leitura de RPMB. Executar a tx 11
(`makeTokenReq`) continua fora do escopo — popula cache de nonce na TA.

---

## 6. Artefatos faltantes

| Artefato | Para quê | Bloqueia | Prioridade |
|---|---|---|---|
| ~~Grafo de chamadas de `GetPartitionIndex`/`GetPartitionCount`~~ | ~~discriminar CVE-2026-24090~~ | ~~A2~~ **resolvido (negativo)** | — |
| Parse de `partitions_extra/uefivarstore.img` | variáveis UEFI pré-AVB | **B2 (topo)** | alta |
| `/vendor/firmware/spss*`, `sp_keymaster*` (duas builds) | diff de CVE-2026-25276/25277 | E2 | média |
| Par pré/pós para `storsec.mbn` e `connsec.img` | confusão de namespace de RPMB | E1 | média |
| Módulos de `uefioneui8.5.img` (5 MB, nunca analisado) + `partitions_extra/xbl.img` | handler de download/Odin, cadeia de verificação | F-4 | média |
| Coleta de VINTF refeita (`vintf-dump.txt` etc. hoje com 0 bytes) | confiabilidade geral | Linha F e derivados | alta (higiene) |
| Imagens `persistent`, `frp`, `secdata`, `steady` analisadas | mapa de input pré-AVB não verificado | F-3 | média |
| `boot.img`, `init_boot.img`, `vendor_boot.img` | parse de boot image pelo ABL | F-3 | baixa |
| Política SELinux (`.te`) de `emservice`, `hal_engmode_default` | afirmar o que root alcança | Linha D (fechar) | baixa |
| Firmware S928B posterior a jul-2026 (ago/set-2026) | reabrir a janela de patch-diff | todas | média |

---

## 7. Hipóteses que devem ser abandonadas

| Hipótese | Por que morreu |
|---|---|
| **CVE-2026-24088 como caminho** | Patch = `f08125d8 "Drop GBL related changes"`; 0 ocorrências de GBL no ABL. Componente ausente. |
| **CVE-2026-24090 / GPT → desligar AVB** | **Experimento 31/08, negativo.** Conjunto exaustivo de 35 literais UTF-16 sem nenhum `vbmeta`; `avb_slot_verify` (`0x18f98`) chamado incondicionalmente; "Skipping boot verification" é emitida depois da verificação, não antes. |
| **Chegar ao AVB por estrutura de disco não assinada (via GPT)** | Idem acima. A família está fechada para a GPT; permanece aberta só para UEFI variables. |
| **Cadeia pública fastboot `set-gpu-preemption` → `selinux=permissive`** | 0 ocorrências de `set-gpu-preemption`, `selinux`, `getvar`, `flash:`, `download:`, `flashing`, `oem unlock` no corpus ABL. Handler fastboot não está no ABL Samsung. |
| **OEM-lock HAL (AIDL/HIDL)** | Sem serviço AIDL no `service list`, sem HIDL no `lshal`, sem binário. Backend = PDB, puro HLOS. |
| **Edição direta de `devinfo+0x0d`** | `0x42524` é o único escritor, alimentado por `GetEMBit(3)`. |
| **Parser de `devinfo`** | `0x4260c mov w2,#0xcd0`; estrutura plana; nenhum offset/comprimento do conteúdo. |
| **Overflow do bitmap de modos** | stride 2, máscara `0x1ff8`, offset máx 24, store de 8 B → 32 B exatos. |
| **Overflow da recuperação RSA (TA-1)** | Âncoras RSA-2048; buffer encostado no canário. |
| **Fallback "dev device" como bypass** | cmd 20 tem bit1 → `0xa5cc` roda antes. Fallback devolve lista vazia. |
| **Confusão de state machine nos flags de requisito da TA** | T2 faz OR monotônico (`0x4e2c`→`0x4e30`). Atacante adiciona bits, nunca limpa. |
| **Parser differential no request QSEECom** | Helper `0x9b24` valida `offset+n <= 0x21c7d` **e** `n <= dst_field_size`; todos os `n` são constantes. |
| **TOCTOU de QSEECom** | Request copiado inteiro antes de qualquer parse; comprimentos exatos. |
| **`callerCheck` como bypass de allowlist** | Código morto, zero call sites. |
| **`num_of_data` do parser de token** | Bug real, mas já corrigido no aparelho (DZDP tem a checagem; ausente só no CZD1). |
| **Secure World lateral → `engmode`** | Namespace de RPMB por TA; nenhuma TA mudou abr→jul-2026; sem par pré/pós. |

---

## 8. Possíveis erros ou pontos fracos da pesquisa existente

### E-1 — `ta_audit.py:213-236`: COMMAND_MAP hardcoded **e** errado
As linhas 214–236 são uma lista literal no código. O texto acima diz "recovered from the
range-checked branch tables". Nada é derivado do binário. Re-derivado aqui (§4, linha C):
erra os comandos 13, 14, 16, 20 e omite 17/18. O mapa anterior (E-1) corrigiu 13, 14, 17,
18 e 20, mas atribuiu `0xe248` ao comando 20 — é o 16. **Qualquer conclusão que nomeie
handler por command ID a partir de `ta-command-storage-evidence.txt` precisa ser
re-derivada.** Isso inclui o mapa de alcançabilidade pré-auth.

### E-2 — `device_extra/`: 11 de 28 arquivos com 0 bytes, e a coleta não falha
`vintf-dump.txt`, `vintf-manifest.xml`, `manifest_manifest_pineapple.xml`,
`manifest_manifest_cliffs.xml`, `manifest_iweaver_aidl_v2.xml` e todos os 6
`_vendor_etc_vintf_manifest_*` (incluindo os dois de `oemlock`) têm **0 bytes**.
O coletor não emite erro. **Impacto:** qualquer `NO_MATCH`/ausência derivada desses
arquivos é "não medido", não "não existe". O mapa anterior cometeu exatamente esse erro
na Linha F — chegou à conclusão certa por acidente.

### E-3 — `bootloader-dzdp-vs-dzg1-diff.txt`: "não medido" apresentado como "verificado"
A tabela diz `engmode.mbn <-> ../partitions/em.img  NO_BASELINE`; a seção
INTERPRETATION afirma *"So is every other TA (tz, vaultkeeper, tz_kg, **engmode**, ...)"*.
Apresentou ausência de medição como resultado positivo de identidade. O mapa anterior
(E-2) diz ter re-executado corretamente e confirmado identidade; **isto não foi
re-verificado nesta passagem** (o zip do DZG1 tem só 2 entradas e `lz4` não está
instalado no ambiente). Recomenda-se re-executar e registrar o comando antes de tratar
P11 como CONFIRMADO.

### E-4 — `dex_audit.py:apk_package()`: falha de parse indistinguível de "não é o pacote"
`except Exception: return ""` — idêntico a "não é o pacote procurado". Um
`NO_MATCH_IN_COVERED_ARTIFACTS` pode ser falha de parse. Há 13 `except Exception` largos
em 11 scripts. Afeta `findings.md` claim 20 (HLOS/KMX), já marcada "Partial".

### E-5 — `findings.md` claim 5 depende de um único recorte de CFG
`EM_SYNC_DOMINATES_AVB_BLOCK=False` está no próprio relatório. O valor é preservação de
estado, não criação. Marcar como confirmado-mas-irrelevante, não como lead.

### E-6 — Relatório manual e saída automatizada divergem sem reconciliação
`findings.md` §Trustlet atribui `GET_MODES` ao comando 20 com handler `0xe248`;
`ta-command-storage-evidence.txt` também erra 16 e 20. Ninguém reconciliou. Feito aqui.

### E-7 — `findings.md`: hashes de âncora "não verificáveis" estão verificáveis
Correção do mapa anterior, confirmada: os dois hashes de `original-research.md` são
exatamente os slots 0 e 2 (`0xf3cca`, `0xf3f16`). O item em "Things that went nowhere"
deve ser removido.

### E-8 — A anomalia RSA-4096 pode ser marcada como morta
Âncoras são RSA-2048 (modulus `0x101` bytes). Combinado com a geometria da pilha
(buffer encostado no canário), TA-1 não tem gatilho. Não é "desconhecido".

### E-9 — Lacuna de janela temporal
O corpus cobre CZD1 (dez-2025) → DZDP (abr-2026) → DZG1 (jul-2026). Hoje é 31/08/2026.
**Não há build de ago/Set-2026 no repo.** Cada mês sem nova build é um mês de correções
de secure world invisíveis para o patch-diff.

---

## 9. Plano de patch-diff

**Princípio:** diff de bug conhecido > fuzzing cego. Sem par pré/pós não existe diff.

### 9.1 Cobertura atual (boletins Qualcomm, fonte primária)

| Boletim | Relevante para SM8650 | Aplicável a este aparelho? |
|---|---|---|
| **Jun-2026** | CVE-2026-24088 (Boot, 8.2), CVE-2026-24090 (HLOS/boot-flow, 7.1), CVE-2026-25276/25277 (Secure Processor, 8.8, Critical) | 24088: **não** (componente GBL ausente). 24090: **não** (experimento 31/08: sem `Is_VERIFIED_BOOT_2`, verificação incondicional). 25276/25277: **provavelmente sim**, mas sem rota até o objetivo e sem par pré/pós. |
| **Jul-2026** | Nada. 11 CVEs; filtro por Boot/HLOS/Secure Processor/TA/bootloader/partition/secure storage/trustlet → só CVE-2026-21383, e **SM8650 não está na lista** | nenhum |
| ASB 2026-05…08 | `source.android.com` reestruturado; usar boletins Qualcomm como fonte primária | — |
| Samsung SMR | Não mapeado no repo | lacuna |

### 9.2 Metodologia

1. **Nunca** diffar imagem inteira de `abl.elf` — embrulha FV comprimido; ~30% de churn
   é artefato. Usar diff ancorado por string/função.
2. Para TAs: comparar **só PT_LOAD**. Para `em.img`: o arquivo inteiro difere apenas em
   metadados fora dos segmentos (versão anti-rollback `05`→`06` e cadeia de certificados
   do signer). Código idêntico.
3. **Mudança de string é o sinal mais barato.** Foi assim que se achou a única correção
   funcional do parser entre CZD1 e DZDP (`"meta.num_of_data is bigger than max (%d)"`).
4. **Quando existir CVE com commit upstream** (caso de 24088/24090), diffar contra o
   commit, **não** contra outra build Samsung. É mais barato e mais preciso.
5. **Rotina mensal:** a cada novo BL tar de S928B → extrair → comparar PT_LOAD por
   imagem → strings primeiro, instruções depois.

### 9.3 Lacunas

- **Nenhuma TA mudou abr→jul-2026** → sem janela de patch-diff em secure world. Isso é
  um resultado, e é negativo.
- **Firmware SPU não vem no tar de BL** → sem par, CVE-2026-25276/25277 não são
  diffáveis hoje.
- **Sem build de ago/Set-2026** → janela temporal fechada em julho.

---

## 10. Próximo passo recomendado

**O experimento 1 foi executado e deu negativo (31/08).** O próximo passo é o
**experimento 2: parsear `partitions_extra/uefivarstore.img`** e cruzar leitores no ABL
com escritores em HLOS (VaultKeeper).

Razão objetiva:
- Com 24088 e 24090 fora de alcance, **UEFI variables é a última superfície pré-AVB
  barata que sobrou**. É a única estrutura não assinada que o ABL consulta antes de
  `0x18f98` e que ninguém analisou.
- `uefivarstore.img` e `uefisecapp.img` **já estão no repo**. Não exige device, não
  exige coleta, não exige operação mutante.
- O discriminador de 24090 provou que a metodologia funciona: resolver literais por
  `adrp`/`add`, montar o mapa consumidor → decisão. O mesmo serve para variáveis UEFI.
- Se der negativo, o mapa fica sem nenhuma linha pré-AVB barata, e a decisão passa a
  ser só sobre quanto tempo vale investir em XBL/Odin (F-4), que é caro.

**Sequência sugerida:**
1. ~~Experimento 1 (A2)~~ → **feito, negativo.**
2. **Experimento 2 — UEFI variables (1–2 d).** Topo do mapa agora.
3. Em paralelo, refazer a coleta de VINTF (~1 h de device): é higiene e destrava a
   confiabilidade de `device_extra/`.
4. Experimento 3 (4–8 h) para fechar formalmente a Linha C com o command map correto.
5. Só então considerar F-4 (XBL/Odin): 3–5 d só para construir o corpus, probabilidade
   5–12%.

**Não** começar por: extrair inner FV do DZG1 para diffar 24088 (morto), diffar 24090
(morto), OEM-lock HAL (morto), parser de `devinfo` (morto), HLOS→TA (fechado).

**Leitura honesta do estado do mapa:** depois de 24088 e 24090, não sobrou nenhuma
linha com mecanismo de falha conhecido e publicado. O que resta é pesquisa original —
UEFI variables primeiro (barata), XBL/Odin depois (cara). A probabilidade agregada de
chegar ao unlock está em single-digit %.

---

## 11. Tabela final

| Rank | Target | Primitiva buscada | Acesso existente | Primitiva faltante | Evidência | Prob. | Custo | Condição de parada |
|---|---|---|---|---|---|---|---|---|
| **1** | **UEFI variables (`uefivarstore`) → ABL** | Decisão pré-AVB influenciada por dado não autenticado | Root HLOS; `uefivarstore.img` e `uefisecapp.img` coletados | Parse do varstore + mapa leitor/escritor | Artefato coletado e **nunca analisado**; VaultKeeper vivo; última superfície pré-AVB barata | **8–15%** | 1–2 d | Todas as variáveis consultadas antes do AVB são autenticadas, ou nenhuma é consultada |
| **2** | **Parser do trustlet `engmode` (pré-auth)** | Escrita/execução na TA; corrupção do bitmap ou do RPMB | Root alcança o transporte (tx 3/5/7/22); cmds 11/12/16/28/31 **sem** requisito de token | Um bug de **escrita** pré-auth — nenhum encontrado | BUG-1 é OOB **read**; `0x9b24` bounds-checked nos dois lados; flags por OR monotônico; TOCTOU fechado; handler `0xe248` (cmd 16) não identificado | **8–15%** (teto = DoS) | 4–8 h (mapa) + 2–4 d (harness) | `0xe248` for getter puro **e** harness mostrar abort antes de `0xa5cc` |
| **3** | **XBL / UEFI / Download-Odin** | Execução antes da verificação de assinatura do BL | Root HLOS; protocolos UEFI parcialmente mapeados | Descompressor XBL SEC; handlers de download; mapa de módulos | `uefioneui8.5.img` (5 MB) nunca analisado; discrepância LZMA `0x543008` vs `0x1a37c1` sem veredito | **5–12%** | 3–5 d (corpus) | Caminho de download valida assinatura antes de qualquer parse de input externo |
| **4** | **Secure Processor / StrongBox** (CVE-2026-25276/25277) | Corrupção de memória no SPU | SPU ativa (`glink_spss`, `sp_keymaster=1`, `IKeyMintDevice/strongbox`) | Firmware SPU (`/vendor/firmware/spss*`) de duas builds | Ambos Critical 8.8, SM8650 afetado, SPL anterior à publicação; mas SPU é separado do QTEE e `S:C` = escape para HLOS | **<3%** até unlock | 1 h (coletar) + alto (analisar) | Se o objetivo for estritamente unlock, abandonar |
| **5** | **Secure World lateral** (storsec/keymint/vk → engmode) | Acesso à partição RPMB do `engmode` | Nenhum par pré/pós | Uma TA vulnerável **com** rota de lateralidade | Nenhuma TA mudou abr→jul-2026; `tz.mbn` idêntico; namespace de RPMB por TA | **<5%** | semanas | Congelada enquanto nenhuma TA mudar entre builds |
| **6** | **UFSDxe (kioxia debug-info)** | Escrita indexada → corrupção de comando UFS | Nenhum (requer injeção de resposta UFS) | Acesso ao controlador UFS | `0x145d8 str w11,[x26,x10,lsl #2]`, mas índice máx `0xFF` → offset `0x3FC`, **dentro** da tabela | **<5%** | alto (hardware) | Efeito downstream mostrar que os valores não afetam seleção de comando |
| **7** | **Fronteira HLOS → TA** | Divergência de comprimento/enum → corrupção | Root chama tudo | Uma divergência real — não há | `libengmode_tlc.so` pass-through; `0x9b24` valida os dois lados; HLOS sempre ≥ TA | **<5%** | ~4 h | Atingida. Documentar e encerrar |
| **8** | **ESS / `commandForESS`** | Forjar request aceito pela autoridade externa | Root monta envelope | A autoridade emissora | Parser TA exige 11 tokens + SHA-256 + len de cert; cert só cifra a saída | **~0%** | — | Obter captura do serviço externo, ou abandonar |
| **9** | **CVE-2026-24090 (GPT → decisão AVB)** | Desligar verified boot escrevendo a GPT | — | O código que reage à condição | **Experimento 31/08 negativo**: 35 literais UTF-16 sem `vbmeta`; `0x18f98` incondicional; "Skipping boot verification" emitida depois da verificação | **~0%** | 0 | **Morta (N/A)** |
| **10** | **CVE-2026-24088 (GBL no ABL)** | Escrita não autenticada → bootloader customizado | — | O componente vulnerável | Patch = `f08125d8 "Drop GBL related changes"` (−1672 linhas); **0 ocorrências de GBL no corpus ABL** | **~0%** | 0 | **Morto (N/A)** |
| **11** | **OEM-lock HAL** | Chegar ao estado consumido pelo ABL | — | — | Sem serviço AIDL em `service list`, sem HIDL em `lshal`, sem binário. Backend = PDB, puro HLOS | **0%** | 0 | **Morta** |
| **12** | **`devinfo` (edição direta e parser)** | Escrever `IsUnlocked=1` | Root escreve a partição | Escritor que não passe por `GetEMBit(3)` | `0x42524` único escritor; `0x4260c mov w2,#0xcd0`, estrutura plana | **0%** | 0 | **Morta** |
| **13** | **Criptografia do token** | Forjar token modo 3 | — | Chave privada da Samsung | RSA-2048 sobre SHA-256; MODE na região assinada; âncoras não rotacionadas desde dez-2025 | **~0%** | — | **Morta** |

---

## Apêndice A — Verificações byte-level feitas nesta revisão

Todas reproduzíveis contra `partitions/em.img` e `decompiled/linuxloader-oneui8.pe`
com capstone 5.0.7.

| Item | Local | Resultado |
|---|---|---|
| Entrada da TA | `0x24c` | `tz_app_cmd_handler`; `calloc(1,0x352e0)` a `0x2b4`; `calloc(0x21c7d)` a `0x3bc`; `memcpy` a `0x3d4`; `cmp w23,#0x21c7d` a `0x39c`; `cmp w21,#0x20936` a `0x3b0` |
| Jump table 1 | `0xf503a`, base `0x49e4` | 37 bytes; todos os blocos montam log e caem em `0x4bc4`. **Não despacha handler** |
| Jump table 2 | `0xf505f`, base `0x4dbc` | 36 bytes; flags de requisito (`orr` com constante por comando) |
| Jump table 3 | `0xf5083`, base `0x502c` | 37 bytes; **dispatcher real** (`0x5000 cmp w8,#0x24`) |
| Gate de assinatura | `0x4e34`, `0x4ed0`, `0x4e50`, `0x4e68` | bit1 → `0x4ed0` (exige `[ctx+8]` bit0) → `0x4e50`; `tbz w8,#1,#0x4ffc` pula `0xa5cc` |
| Parser de request | `0x5390` | `calloc(1,0x21ca0)`; campos copiados por `0x9b24`; mode array = 128 × `uint16` em `+0x2ba..0x3ba` |
| Helper de cópia | `0x9b24` | `0x9b54 cmp w5,w3` (offset+n vs `src_len`); `0x9b98 cmp w19,w1` (n vs `dst_field_size`); `memcpy` a `0x9bf4` |
| Flags ← request | `0x5b00`–`0x5b18` | `ctx[0]=parsed[0]`; `ctx+8/0x10/0x18/0x20 = parsed+0x10/0x18/0x20/0x28` |
| Cmd 37 | `0x5214` | gates bits 3/0xa e `[ctx+8]` bits 5/0x15; `0x96fc` = teste "tudo zero?" (**não** memset); zera 0x20 em `ctx+0x33e5c` |
| BUG-1a | `0xb23c`/`0xb240`/`0xb244` | `cmp w4,#0x1f5` → `strh w4,[x21,#0x1c]` → `b.hs 0xb7d4` |
| BUG-1b | `0xa654`/`0xa66c`/`0xa674` | `ldrh w11,[x20,#0x1c]`; `add w9,w9,w11,lsl#2`; `add w5,w9,#0x2a` |
| Bitmap | `0xeb90`–`0xebbc` | stride 2; `and x12,x12,#0x1ff8`; store único; `cmp w8,#0x100` |
| `num_of_data` | `0xb100`/`0xb108` | `cmp w4,#5`; `b.lo` → unsigned |
| Escritor de `IsUnlocked` | `0x42524` | `strb w19,[x1,#0xd]`; varredura de todos os `strb #0xd/#0xe` confirma unicidade |
| `DeviceInfoInit` | `0x4260c` | `mov w2,#0xcd0` |
| Política OEM | `0xa141c` | `mov w0,wzr` |
| `IsUnlocked` | `0x41ed0` | `ldrb w3,[x19,#0xe35]`; chamado por `0x51060` |
| Corpus ABL × GBL | 113 arquivos | `gbl`/`GBL`/`GblAvb`/`GblOsConfiguration`/`DtFixup` = **0** |
| Corpus ABL × fastboot | 113 arquivos | `getvar`/`download:`/`flash:`/`flashing`/`oem unlock`/`selinux`/`set-gpu-preemption` = **0** |
| Corpus ABL × vbmeta UTF-16 | 113 arquivos | `vbmeta`/`vbmeta_a`/`vbmeta_system` = **0** (38 ocorrências ASCII, todas de log) |
| Conjunto exaustivo de literais UTF-16 do LinuxLoader | 35 entradas | Resolvido por todos os pares `adrp`+`add` (janela 13). Nomes: `boot`, `boot_a`, `boot_b`, `init_boot`, `vendor_boot`, `super`, `system`, `modem`, `xbl`→(`abl`,`abl_x`), `misc`, `recovery`, `recoveryfs`, `user_dtbo`, `swap_a`, `EDL`, `ImageFv`, `emac`, `debug`, `sysfont2x`. **Nenhum `vbmeta`.** |
| Chamada de verificação AVB | `0x15990 bl #0x18f98` | **Incondicional.** Único teste prévio é `0x18e08`, cuja falha vai para log de erro |
| Variável de estado da decisão | `[x19+0x438]` | 8 escritores: 7 fixam `3` (erro); só `0x159f4` pode produzir `2`, via `ldrb w8,[x20]` (`is_device_unlocked`) |
| Branch "Skipping boot verification" | `0x16390`, string em `0xb61b6` | Selecionado por `[x19+0x438]==2`, **depois** de `0x18f98` retornar. Não é gate. |
| Cadeia confirmada | `0x18f98` → `0x51048` → `0x41ed0` → `devinfo+0x0d` ← `GetEMBit(3)` | Ponta a ponta, reforça P1–P4 |
| `device_extra/` | 28 arquivos | **11 com 0 bytes**, incluindo `vintf-dump.txt` e os dois `oemlock` manifests |
| Runtime × oemlock | `lshal-full.txt`, `service-list-full.txt`, `vendor-bin.txt`, `system-bin.txt`, `ps-context-full.txt` | sem HIDL, sem AIDL, sem binário, sem processo. Só `oem_lock` (Java) |

## Apêndice B — O que **não** foi feito (escopo)

Nenhum comando mutante foi executado. Nenhum `installToken`, `removeToken`, comando de
fuse, `AT+FRPUNLCK`, escrita de partição, escrita de GPT, escrita de `devinfo` ou leitura
de RPMB. Nenhum artefato original foi alterado. Nenhum payload foi produzido.
`makeTokenReq` (tx 11) foi deliberadamente **não** executado por popular cache de nonce
na TA. Todo o trabalho é estático ou leitura de arquivos já coletados, mais consulta a
fontes públicas (boletins Qualcomm, commits CodeLinaro, CVE records).
