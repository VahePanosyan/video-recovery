# `sd-video-recovery` — Windows CLI վիդեո վերականգնման գործիք

## Ամփոփում

Ստեղծել բաց կոդով MIT լիցենզավորված Rust CLI՝ camera/GoPro/drone SD քարտերից ջնջված կամ quick-format-ից հետո մնացած MP4/MOV վիդեոները վերականգնելու համար։

- Windows 10/11 x64, FAT32 և exFAT։
- Աղբյուրը միայն ֆիզիկական SD քարտ է, output-ը՝ պարտադիր ուրիշ սկավառակ։
- Երկու փուլ՝ filesystem metadata recovery, հետո ամբողջական raw carving։
- English/Armenian CLI և documentation։
- Source-ը միշտ read-only է, telemetry/network access չկա։
- Raw NAND, ֆիզիկապես վնասված քարտեր, filesystem repair և automatic video repair-ը v1-ից դուրս են։

## Իրականացման կառուցվածք

- Ստեղծել Rust binary + library կառուցվածք՝ `Cargo.toml`, `src/`, `tests/`, MIT license և ECC-ի կարճ հղումով `AGENTS.md`։
- Windows device layer-ը `windows` crate-ով բացում է միայն `\\.\PhysicalDriveN`՝ `GENERIC_READ`, `OPEN_EXISTING`, առանց որևէ write-capable handle-ի։ Geometry-ն ու սարքի տեսակը վերցնել `IOCTL_DISK_GET_DRIVE_GEOMETRY_EX` և `IOCTL_STORAGE_QUERY_PROPERTY`-ով։ [Microsoft CreateFile docs](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea), [disk geometry docs](https://learn.microsoft.com/windows/win32/api/winioctl/ni-winioctl-ioctl_disk_get_drive_geometry_ex)։
- Թույլատրել SD/MMC/USB reader-ները, արգելել Windows system disk-ը։ Fixed նշվող USB reader-ի համար պահանջել `--allow-fixed` և ձեռքով disk-ID հաստատում։
- Output volume-ի physical extent-ը համեմատել source disk-ի հետ և նույն սկավառակի դեպքում կանգնել։ Գրել timestamp-ով նոր session folder-ում, `create_new` semantics-ով, երբեք չվերագրել գոյություն ունեցող ֆայլ։
- Parse անել MBR/GPT-ը checked arithmetic-ով։ FAT32/exFAT raw կառուցվածքների համար օգտագործել pinned MIT `hadris-fat-raw 0.3.0`-ի միայն codec/parser շերտը, ոչ write API-ները։ exFAT recovery-ն հաշվի է առնում InUse bit-ը, Allocation Bitmap-ը, stream entry-ն և NoFatChain-ը՝ ըստ [Microsoft exFAT specification](https://learn.microsoft.com/en-us/windows/win32/fileio/exfat-specification)։
- Filesystem փուլում վերականգնել ջնջված directory entry-ները, պահպանված FAT chain-ով նաև ֆիզիկապես fragmented ֆայլերը, իսկ կորած chain-ի դեպքում փորձել միայն անվտանգ contiguous extent։
- Deep փուլում մեկ sequential pass-ով փնտրել MP4/MOV `ftyp`, `mdat`, `moov`, `moof` box-երը։ Box parser-ը աջակցում է 32/64-bit size-երին, սահմանափակում է nesting/box count-ը և մերժում overflow կամ disk boundary-ից դուրս չափերը։
- Նույն source extent-ից metadata և carving candidate-ները deduplicate անել՝ filesystem արդյունքին առաջնահերթություն տալով։
- Extraction-ը գրել `.part` ֆայլի մեջ, ավարտից հետո atomic rename անել։ Persistent read error-ի դեպքում մեկ sector-level retry-ից հետո դադարեցնել և report-ում պահել offset-ը՝ վնասվող քարտը անվերջ չկարդալու համար։
- Ctrl+C-ի դեպքում ջնջել միայն ընթացիկ `.part`-ը, պահել արդեն ավարտված ֆայլերն ու interrupted report-ը։ Checkpoint/resume չի լինելու. հաջորդ run-ը նոր session է սկսում։
- Quick validation-ը պարտադիր external `ffprobe`-ով է։ `--full-verify`-ը պահանջում է նաև `ffmpeg` և ամբողջ video stream-ը decode է անում։ Գործիքները կանչել ուղիղ argv-ով, ոչ shell command-ով։

## CLI և report contract

```text
sd-video-recovery list [--lang en|hy] [--json]

sd-video-recovery doctor
  [--ffprobe-path FILE]
  [--ffmpeg-path FILE]
  [--lang en|hy]

sd-video-recovery recover
  --disk N
  --output DIRECTORY
  [--mode all|filesystem|deep]
  [--ffprobe-path FILE]
  [--ffmpeg-path FILE]
  [--full-verify]
  [--allow-fixed]
  [--lang en|hy]
```

- `recover`-ը մինչև սկան ցույց է տալիս model, size, bus, partitions և պահանջում է մուտքագրել ընտրված disk ID-ն։
- Լեզվի default-ը Windows locale-ից է, անհայտ locale-ի դեպքում՝ English։
- Session output՝ `validated/`, `partial/`, `report.json`, `summary.txt`։
- `report.json`-ը կունենա `report_version: 1`, masked device identity, scan config/timing, filesystem, candidate extents, recovery method, original/recovered անուններ, confidence, validation status և error reason։
- Status-ներ՝ `validated`, `partial`, `rejected`, `io_error`; confidence՝ `high`, `medium`, `low`։
- Exit codes՝ `0` ավարտված scan, `2` սխալ arguments, `3` safety/preflight failure, `4` source I/O failure, `5` ffprobe/ffmpeg failure, `130` interruption։
- v1-ում Rust library API-ն public stability promise չի ստանում. stable interfaces-ը CLI-ն ու versioned JSON report-ն են։

## Ստուգումներ և ընդունման չափանիշներ

- TDD unit tests՝ MBR/GPT, FAT32/exFAT entries և MP4 box parser-ի valid, truncated, oversized, cyclic ու overflow input-ների համար։
- Property/fuzz tests՝ arbitrary bytes-ը երբեք panic, out-of-bounds read կամ անվերահսկելի allocation չառաջացնի։
- Synthetic disk integration tests՝ FAT32/exFAT deleted contiguous file, պահպանված fragmented chain, quick-format raw carve, duplicate candidate և same-disk output refusal։
- Validator tests՝ missing ffprobe, malformed JSON, timeout, valid video stream, no-video file և optional full-decode failure։
- Manual sacrificial SD QA՝ known MP4/MOV-ների SHA-256 baseline, delete և առանձին quick-format փորձեր, recovery դեպի ուրիշ drive, hash/ffprobe/full-decode համեմատություն։ Ցանկացած format քայլից առաջ նորից հաստատել physical disk ID-ն։
- CI՝ `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test`, առնվազն 80% line coverage, `cargo audit`, `cargo deny check` և Windows x64 release build։
- Release zip-ը պարունակում է միայն մեր executable-ը, English/Armenian README-ները, license/notices և SHA-256 checksum. FFmpeg/ffprobe binary չի bundle արվում։

Պարտադիր ընդունման արդյունքներ՝

- Source device-ի վրա ոչ մի write API չի կանչվում։
- Metadata ունեցող deleted FAT32/exFAT test files-ը վերականգնվում են byte-identical։
- Quick-formatted քարտի contiguous MP4/MOV-ը գտնվում և ffprobe-ով ճանաչվում է։
- Կորած cluster mapping-ով fragmented ֆայլը չի ներկայացվում որպես լիարժեք validated։
- Նույն physical disk-ի վրա output-ը մերժվում է մինչև scan-ը։
- Corrupt input-ը տալիս է վերահսկվող error/report, ոչ crash։
- English և Armenian բոլոր user-facing հաղորդագրությունները հասանելի են։

## Ենթադրություններ և սահմաններ

- Առաջին release-ը միայն Windows 10/11 x64 և մինչև 2 TB FAT32/exFAT SD քարտերի համար է։
- MP4/MOV classic և fragmented ISO-BMFF container-ները աջակցվում են այնքանով, որքանով տվյալները և allocation metadata-ն պահպանվել են։
- Metadata կորցրած, ֆիզիկապես fragmented classic MP4-ի cluster order-ը v1-ը heuristic-ով չի գուշակի։
- `ffprobe` պարտադիր external dependency է, իսկ ամբողջական decode-ի համար նաև `ffmpeg` է պետք։
- Իրական SD-ի destructive test-ը կատարվում է միայն հատուկ test քարտի վրա, ոչ օգտատիրոջ միակ օրինակի։
