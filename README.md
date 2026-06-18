# osu-introspect

runtime introspection framework for osu!lazer's native anticheat module (`AuthNative.so`).

## build

```
cmake -B build
cmake --build build
```

## usage

```
LD_PRELOAD=./build/src/libosu_ac_introspect.so osu-lazer
```

logs to stderr by default. set `OSU_INTROSPECT_LOG=/tmp/trace.jsonl` for file output.

## env vars

| var                           | values                   | effect                    |
| ----------------------------- | ------------------------ | ------------------------- |
| `OSU_INTROSPECT_LOG`          | path                     | log output location       |
| `OSU_INTROSPECT_MODE`         | `summary`, `verbose`     | output detail level       |
| `OSU_INTROSPECT_CAPTURE`      | `none`, `hashes`, `full` | data capture level        |
| `OSU_INTROSPECT_SPOOF_TRACER` | `1`                      | spoof TracerPid to 0      |
| `OSU_INTROSPECT_DEVIRT`       | `1`                      | enable vm memory scanning |

## devirt

```
sudo ./build/devirt/osu_ac_ptrace <pid> --trace-state --max-steps 5000 > trace.jsonl
```

miasm deobfuscation on captured traces:

```
python3 devirt/miasm_deobfuscate.py ./AuthNative.so ./trace.jsonl > lifted.txt
```

bytecode lifter for the managed monitor regions:

```
python3 devirt/vm_lifter.py ./AuthNative.so
```
