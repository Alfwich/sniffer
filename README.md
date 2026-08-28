# Sniffer

Sniffer is a Windows command-line memory scanner and editor, inspired by tools such as ArtMoney. It attaches to every running process with a given executable name, searches their readable memory for a value, and keeps the matching addresses in a working set that can be filtered, inspected, edited, or continuously rewritten.

The project is written in C++ and uses the Windows process and memory APIs directly. Memory-region scans are split into chunks and distributed across worker threads.

> [!WARNING]
> Sniffer reads and writes the memory of other processes. Use it only with software you own or are authorized to inspect. Writing an invalid value can corrupt data or crash the target process.

## Features

- Search process memory for signed and unsigned integers, floating-point values, and strings.
- Restrict searches by value type and comparison predicate.
- Filter an existing result set after the target value changes.
- List, pick, remove, clear, and undo changes to search results.
- Replace every address in the current result set.
- Continuously rewrite selected addresses to keep a value fixed.
- Maintain multiple named search contexts in one interactive session.
- Scan all running processes that share the requested executable name.
- Use multiple scan worker threads and display basic scan/profile information.

Supported value types are `i8`, `i32`, `i64`, `u8`, `u32`, `u64`, `f32`, `f64`, and `str`. Supported predicates are `eq`, `ne`, `lt`, and `gt`.

## Requirements

- Windows
- Visual Studio 2022 with the **Desktop development with C++** workload
- MSVC v143 toolset and a Windows 10/11 SDK

Administrator privileges may be required to access the target process. Processes protected by Windows or anti-tamper software may remain inaccessible.

## Build

Open a Visual Studio 2022 Developer Command Prompt in the repository and run:

```bat
build-x64-release.bat
```

This builds the full solution in `Release|x64`. The main executable is written to:

```text
x64\Release\sniffer.exe
```

You can also open `sniffer.sln` in Visual Studio and build the desired configuration there.

## Quick start

The included `test-target` program exposes a collection of known values in memory, making it useful for trying Sniffer without attaching to another application.

1. Build the solution.
2. Start `x64\Release\test-target.exe` and leave it running.
3. In a second elevated terminal, start Sniffer:

   ```bat
   x64\Release\sniffer.exe interactive -pname "test-target.exe"
   ```

4. Search for the target's 32-bit integer value:

   ```text
   find 13371337 type i32
   ```

5. Replace every matching value:

   ```text
   set 42
   ```

The target program refreshes its display once per second, so the changed value should be visible immediately.

## Interactive commands

Start an interactive session with:

```bat
sniffer.exe interactive -pname "PROCESS_NAME.exe"
```

Values containing spaces must be quoted. Command options inside the interactive prompt are written without leading dashes.

| Command | Purpose |
| --- | --- |
| `find VALUE [type TYPE] [pred PRED]` | Start a new scan and replace the current context's results. The default predicate is `eq`. |
| `filter [VALUE] [type TYPE] [pred PRED]` | Reread and narrow the current results. If `VALUE` is omitted, the previous search value is used. |
| `list [OFFSET]` | Show up to 20 results and their current values. |
| `set VALUE` | Write `VALUE` once to every current result. |
| `pick INDEX` | Keep only one result. |
| `pick START:END` | Keep an inclusive range of results. |
| `remove INDEX` | Remove one result. Alias: `rm`. |
| `remove START:END` | Remove an inclusive range of results. |
| `undo` | Swap the current result set with the last committed result set. |
| `clear` | Remove all results from the current context. |
| `repeat VALUE` | Continuously write `VALUE` to all current results. |
| `repeat VALUE id INDEX` | Continuously write `VALUE` to one result. |
| `repeat list` | List active continuous writes. |
| `repeat remove INDEX` | Remove one continuous write. |
| `repeat clear` | Stop all continuous writes. |
| `context NAME` | Switch to a named result context, creating it when necessary. Alias: `ctx`. |
| `context list` | List contexts. |
| `context clone NAME` | Clone the current results into a new context and switch to it. |
| `context remove NAME` | Delete a context. The `global` context cannot be deleted. |
| `load PROCESS_NAME.exe` | Switch to another running executable name. |
| `threads COUNT` | Change the scan worker count. Alias: `j`. See the current limitation below. |
| `profile` | Toggle timing output for scan phases. |
| `info` | Show the target executable, matching process IDs, scanned memory, and worker count. |
| `help` or `?` | Show interactive help. |
| `quit`, `exit`, or `q` | End the session. |

When no type is supplied, a numeric search considers the wider numeric representations that can hold the value. Specify `i8`, `u8`, or `str` explicitly when searching for byte-sized values or text.

### Typical narrowing workflow

Suppose a value in the target starts at `100`, changes to `75`, and then changes to `60`:

```text
find 100 type i32
filter 75 type i32
filter 60 type i32
list
set 999
```

Named contexts let you keep unrelated searches alive at the same time:

```text
context health
find 100 type i32
context ammo
find 30 type i32
context health
list
```

## Tests

Build the solution, then run:

```bat
x64\Release\tests.exe
```

The tests exercise numeric and string searches, memory-region chunk boundaries, argument parsing, contexts, result selection/removal, undo, replacement, and continuous replacement.

## Project layout

| Path | Description |
| --- | --- |
| `libsniffer/` | Static library containing scanning, filtering, replacement, command parsing, and Windows memory access. |
| `sniffer/` | Console application and interactive loop. |
| `tests/` | Integration-style tests against a controlled in-process memory buffer. |
| `test-target/` | Standalone process with known values for manual testing. |
| `sniffer.sln` | Visual Studio solution containing all four projects. |

## Current limitations

- Windows-only; process discovery and memory access use Win32 APIs.
- There is no graphical interface.
- Search results and named contexts are kept in memory for the current session; persistence is not implemented.
- String replacement writes the replacement bytes in place and does not resize the target allocation.
- Exact floating-point comparisons can be sensitive to representation and rounding.
- The interactive `threads` command currently clamps positive values to one; the initial worker count still defaults to the system processor count.
- The legacy one-shot command-line actions are incomplete; interactive mode is the supported workflow.
- The project currently has no packaged release or installer.

## How it works

For each process matching `-pname`, Sniffer enumerates non-free memory regions, divides large regions into smaller records, and copies accessible bytes with `ReadProcessMemory`. Worker threads scan those copies for the requested representations and store each match as a `(type, process ID, address)` record. Later filters reread only those recorded addresses, while `set` and `repeat` update them with `WriteProcessMemory`.
