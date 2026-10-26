---
icon: typo3
cover: ../.gitbook/assets/PHP 8.5.7 RCE Security Research Banner.png
coverY: 0
coverHeight: 325
---

# RCE In PHP

<figure><img src="../.gitbook/assets/image (549).png" alt=""><figcaption></figcaption></figure>

## Why I looked at this chain

When we talk about PHP security, most people think about SQL injection, unsafe deserialisation, file inclusion, or a bad upload handler. Those issues are usually visible at the application layer. This research claim is different: it describes a chain through PHP internals, where the application-level operation looks ordinary but native code may end up using an object property in a way that its type does not allow.

The chain I investigated brings together four areas of PHP that do very different jobs:

* **SPL / `ArrayIterator`**  gives arrays and objects an iterator-style interface.
* **Streams / `StreamBucket`** moves chunks of data through stream filters.
* **SOAP / `SoapClient`** makes structured calls to another service and processes HTTP response headers.
* **Zend Engine hash tables and function dispatch** store PHP arrays and route calls to internal functions.

None of these components is designed to execute shell commands as part of normal operation. The reported problem is the way several assumptions can interact after an internal object is pushed into an invalid state.

The easiest way to understand it is to follow the data, not just the names of the functions. A property is changed through an indirect path; a later native path assumes that property contains a string; stream processing is used to observe memory; the SOAP cookie handler is then used as a later write primitive; and the final claim is that a corrupted engine dispatch path reaches `system()`.

I am deliberately separating **what the local files show** from **what still needs remote validation**. That distinction matters in a memory-corruption report because a working local proof and a reliable remote exploit are not the same result.

## The short version

In simple words, the report describes this sequence:

1. Put an internal PHP object into a state its normal API is not supposed to create.
2. Reach native stream code that expects a `StreamBucket` data field to be a string, even though the reported mutation has changed the value's type.
3. Use stream-filter allocations and marker strings to observe memory and locate controlled data in the test process.
4. Make the `SoapClient` cookie storage path operate on a forged table rather than a valid cookie array.
5. Send a SOAP HTTP response containing a numeric cookie name so the cookie code takes the integer-key hash update path.
6. The proof of concept claims that this write corrupts an internal function-dispatch hook, after which a later internal call reaches `zif_system()`.

The key point is that a numeric cookie name is not, on its own, an RCE. A numeric-looking string being treated as an integer array key is normal PHP behaviour. In this chain, that behaviour is being used after the cookie table has allegedly been corrupted. The unsafe state is what changes the meaning of an otherwise ordinary hash update.

## The PHP components, explained without assuming you know the internals

<figure><img src="../.gitbook/assets/image (554).png" alt=""><figcaption></figcaption></figure>

### 1. SPL and `ArrayIterator`

The Standard PHP Library (SPL) contains common data structures and helper classes. `ArrayIterator` lets PHP code iterate over an array or an object using array-like syntax. It is useful when existing code expects something it can loop over or address using offsets.

<figure><img src="../.gitbook/assets/SPL and ArrayIterator Security Diagram.png" alt=""><figcaption></figcaption></figure>

A normal example looks like this:

```php
$data = ['region' => 'Mumbai', 'active' => true];
$iterator = new ArrayIterator($data);

echo $iterator['region']; // Mumbai
```

That is ordinary application behaviour. The concern in this report is not that using an `ArrayIterator` is automatically unsafe. The concern is an indirect assignment when the iterator wraps an object, followed by applying that path to special internal objects whose properties have assumptions enforced by native C code.

The submitted proof of concept has a helper shaped like this:

```php
function corrupt_property(object $object, string $property, mixed $value): void {
    $it = new ArrayIterator($object);
    $it[$property] = $value;
}
```

In everyday language, the helper says: “Wrap this object in an iterator, then assign a value using array syntax.” The PoC uses that path to try to change properties such as the `data` field on a `StreamBucket` and the cookie-storage field on a `SoapClient`.

Why is that interesting? Internal classes often rely on a property containing a specific kind of value. A native implementation might assume that a field is a string, resource, or valid object. If a mutation path lets a different type slip through, the native code still needs to validate the value at the exact point where it uses it.

**Security lesson:** a property declared or intended to hold one type is not safe merely because one earlier operation checked a different property on the same object. Each value used by native code needs the correct type and lifetime guarantees.

### 2. PHP streams, filters, and buckets

<figure><img src="../.gitbook/assets/image (616).png" alt=""><figcaption></figcaption></figure>

A PHP stream gives code a common way to read and write data. The stream may wrap a file, socket, temporary memory buffer, or another supported stream wrapper. A stream filter transforms data as it moves through that stream.

A filter can be useful for operations such as encoding, decoding, compression, or other transformations. It processes chunks rather than needing the entire data set at once. PHP represents those chunks using stream buckets. In PHP 8.4 and later, `stream_bucket_new()` returns a `StreamBucket` instance; see the [official function reference](https://www.php.net/manual/en/function.stream-bucket-new.php).

A simplified mental model is:

```
input stream -> bucket -> filter -> transformed bucket -> output stream
```

The bucket has data and metadata that must agree with each other. If the data field is a PHP string, native code can use the string's length and bytes according to the string representation. If that field is actually an integer or some other value but native code reads it as though it were a string pointer, the program is no longer operating on valid type information.

That kind of mistake is called **type confusion**. It is particularly serious in native code because a PHP value is represented internally by a tagged value (`zval`). The tag tells the engine whether the value is a string, integer, array, object, resource, and so on. Reading a value through the wrong representation can make bits that represent an ordinary PHP value look like an address.

The report's alleged root cause is that the native bucket-attachment path checks the `bucket` resource, but then uses the separate `data` property as string data without first establishing that `data` is actually a valid string. A valid bucket resource and a valid string field are two different checks; one cannot stand in for the other.

I want to emphasise the wording here: this is the root cause described by the submitted report. A maintainer-level confirmation requires checking the precise PHP 8.5.7 source and the corresponding patch or reproducer.

### 3. SOAP and `SoapClient`

<figure><img src="../.gitbook/assets/image (633).png" alt=""><figcaption></figcaption></figure>

SOAP is a message protocol used by services that exchange structured XML requests and responses. In real systems, it still appears in payments, insurance, logistics, enterprise resource planning, older government systems, and other business integrations.

For example, a PHP application might ask a shipping service for the latest parcel status. The request goes to the shipping provider, and the provider returns a SOAP response. In PHP, code can use `SoapClient` to make the request and process the reply.

HTTP response headers are part of that exchange. One header can be `Set-Cookie`, which asks the client to store a cookie for future calls. A normal cookie might have a name such as `session_key` and a value such as `abc123`. PHP's SOAP HTTP code parses the response's cookie name and value and stores them in the client's cookie table.

The report uses this routine response-processing feature as a later step in the chain. It claims that the cookie table reference has already been put into an invalid state. After that, a cookie header with a numeric name causes the storage code to take a different hash-table update path.

That distinction is important. **The presence of SOAP is not enough to make a target vulnerable.** The application must reach the relevant processing path, and the response processed by the client must be controllable in the way the report requires. A correctly configured HTTPS connection prevents a simple network observer from silently changing the response, although a compromised service, a malicious endpoint, a trusted-but-compromised proxy, or broken TLS validation can change the assumptions.

### 4. Zend Engine arrays and `HashTable`

<figure><img src="../.gitbook/assets/image (634).png" alt=""><figcaption></figcaption></figure>

PHP arrays are more flexible than lists in many other languages: a single array can have string keys and integer keys. Internally, PHP uses Zend Engine hash-table structures to store these entries.

The `zend_symtable_update()` helper accepts a string key, checks whether that string represents a numeric key according to PHP's rules, and then selects either a string-key update or an integer-index update. That is expected behaviour. For example, normal application code can intentionally use both `'username'` and `42` as keys in an array.

The supplied report focuses on this decision because its forged cookie-table scenario depends on the numeric path. A normal hash update expects a valid `HashTable` with valid metadata and storage. If the table pointer or its internal fields were corrupted earlier, the same update code may now write to an unintended location.

A good way to think about it is this: a calculator can correctly add two numbers but still produce a harmful result if the memory holding its inputs has already been overwritten. The hash update is not necessarily the first bug. It is the later operation that the report claims turns the earlier corrupted state into a useful write.

Reference for the implementation: [`zend_hash.h`](https://github.com/php/php-src/blob/master/Zend/zend_hash.h). For a real audit, open the tag that matches the tested binary rather than assuming that `master` has the same implementation as a released version.

### 5. Internal function dispatch and `system()`

PHP can call built-in functions implemented in C. In the engine, the function implementation for `system()` is commonly referred to as `zif_system`. The engine also has an internal execution path for calls to internal functions, including an internal dispatch hook referred to in the report as `zend_execute_internal`.

The supplied PoC claims to overwrite that dispatch path so that a later internal function call reaches `zif_system()` instead of following the normal path. That would turn a memory-corruption condition into command execution inside the PHP process.

This is a very specific final step, not a general property of PHP function calls. It depends on the precise binary layout, address calculations, and overwritten state in the tested build. The proof transcript's absolute addresses are process-specific and should not be copied into a general tutorial as though they were stable values.

## The reported chain as a diagram

The diagram below captures the claimed dependency between the stages. It is intentionally a root-cause diagram, not a recipe for building the memory layout.

<figure><img src="../.gitbook/assets/image (576).png" alt=""><figcaption></figcaption></figure>

The diagram is the hypothesis tested by the submitted proof artifacts. It should not be read as saying each stage is guaranteed on every PHP build, or that a remote attacker automatically controls the SOAP response.

## Walking through the submitted `rpoc.php`

The proof of concept is long because it is doing much more than sending an HTTP request. It tries to shape the local process memory, locate controlled allocations, and make the SOAP cookie path act on a forged structure. The helper functions are easier to understand when grouped by their purpose.

## Build-specific constants and object mutation helpers

Near the top of the file, the PoC defines offsets and small constants for the expected build. Those offsets are not part of PHP's stable public API. They are tied to the exact binary and memory layout used by the author of the PoC; they should be re-derived and confirmed for each build in a controlled debugger session.

The `corrupt_property()` helper uses the `ArrayIterator` behaviour described above. The `corrupt_streambucket()` helper creates a `StreamBucket` instance without taking the normal constructor path, sets the resource-related field, then passes the data field through the mutation helper.

That setup attempts to create an object whose fields no longer agree with the invariants expected by stream internals. It does not, by itself, prove memory disclosure or code execution. It only creates the state that later native operations are expected to mishandle.

## Marker allocations and the fake table blob

The helper named `fake_hashtable_blob()` produces bytes intended to resemble part of a Zend hash-table layout and appends a unique marker. The PoC creates many such allocations and keeps them referenced so that the garbage collector does not free them during the experiment.

Why include a marker? Memory corruption can be difficult to reason about by looking at raw bytes. A unique marker lets the test look for one of the specially created allocations in data returned by a later operation. If the marker is found at a particular offset, the PoC uses that observation to calculate where the related allocation may be located in the test process.

This is a heap-layout experiment, not a generic feature of stream filters. Allocation order, allocator behaviour, architecture, compiler, binary, and PHP version can all affect whether the observed layout is repeatable.

To avoid turning this blog into a drop-in memory-steering guide, I am not reproducing the exact fake-structure fields, offsets, or pointer arithmetic from the supplied exploit. Those values are implementation-specific, and publishing the fully wired layout alongside the command-execution trigger would make the post directly reusable as an RCE payload.

## Running a custom stream filter

The `run_filter()` helper opens a temporary PHP stream, attaches a named filter in write mode, writes a small input, flushes it, rewinds the stream, and reads the result. This is the plumbing that causes a registered user-space filter to execute in a controlled local test.

The PoC registers two custom filter classes:

* **`FakeHashFilter`** prepares the allocations and bucket objects used by the reported leak stage. It creates a large victim bucket, a set of marker-bearing allocations, and a carrier bucket. It then uses the property-mutation path and passes the result to the output brigade.
* **`OverreadFilter`** builds a second bucket whose data field is assigned a value derived from the earlier result. Its role is to attempt the reported out-of-bounds or invalid-memory read and return bytes that can be searched for the marker.

The `filter()` method is part of PHP's custom stream-filter interface. It receives input buckets, updates the consumed-byte count, and emits output buckets. The fact that the PoC has control over these filter classes lets it arrange operations and allocations in a repeatable sequence. The claimed bug is still in the native handling of the invalid field—not in the general idea of writing a stream filter.

## Marker search and process mappings

The helper `marker_offset()` searches the returned data for a marker with the current run's unique tag. It returns the marker, its position in the buffer, and a small identifier taken from the marker.

The functions that inspect `/proc/self/maps` and `/proc/self/mem` serve a different purpose. They attempt to identify the PHP executable's mapped base address and inspect memory ranges readable by the current process. This assumes a Linux-like environment and permissions that allow the process to inspect its own mappings and memory file.

The base-address calculation is there because position-independent executables can be loaded at different virtual addresses from one run to another. The PoC needs runtime addresses for its particular build rather than assuming that a function always lives at the same absolute address.

These checks are also an important limitation. They are not portable to every operating system, PHP SAPI, container configuration, or hardened deployment. A failure to read process memory or a difference in binary layout can stop the PoC before it reaches the SOAP stage.

## Choosing a compatible hash-table layout

The `select_hash_mask()` helper scans candidate slots in writable mappings and looks for a value that matches the layout constraints expected by the fake table. Its purpose is to find a table configuration compatible with the address the exploit is trying to target.

This is not normal PHP application logic. It is memory-layout manipulation specific to the supplied PoC. The exact mask, slot selection, and indices are deliberately not expanded into a reusable step-by-step recipe here. For debugging or patch review, the important high-level observation is that the exploit depends on being able to build a table whose metadata causes a later update to land at the intended location.

## The local HTTP server and SOAP response

The file includes a small HTTP server that listens on the loopback interface. The SOAP client in the test sends a request to that local server, and the server returns an XML SOAP response with a `Set-Cookie` header.

The cookie name is generated by the PoC based on its build-specific calculations. The numeric name matters because the SOAP cookie handler stores the cookie through a function that converts numeric-looking string keys into integer indexes. In a normal application that is just array-key handling. In this test, the cookie is intended to be processed after the cookie table reference has been manipulated.

The server listens on `127.0.0.1`. That proves only that the PoC can provide a crafted response to its own local `SoapClient` under the test conditions. It does not show how an attacker would gain control over a real application's remote SOAP endpoint, DNS, proxy, or TLS configuration.

## Reaching the reported trigger

In the main section, the PoC checks that the SOAP extension is present, calculates build-specific addresses, registers the filters, runs the marker/leak stages, starts the local server, and creates a `SoapClient` that points to that server. It then applies the property-mutation path to the client's cookie storage and invokes a SOAP call to make the response header be processed.

After the cookie-processing stage returns, the PoC makes an internal function call as a trigger. The reported final outcome is that this later call enters `zif_system()` due to the earlier dispatch corruption and creates a marker file.

I am describing the purpose and order of these stages, but not reproducing the exact pointer targets, numeric cookie value, full fake-table construction, or final shell-command trigger. Those pieces together would make this a directly reusable critical RCE proof of concept rather than a source-level explanation.

## What the validation wrapper proves

The supplied `scripts/validate.sh` is a small wrapper. It expects a PHP binary path, runs the proof-of-concept script without loading the normal `php.ini`, saves the program output to a log, extracts the marker path from that output, and checks that the file exists and contains the expected marker content.

The wrapper's logic is effectively:

1. Fail early if a PHP binary was not provided.
2. Create the evidence directory if needed.
3. Run the local PoC and save its output.
4. Read the output to find the expected marker path.
5. Fail if that file was not created or its contents do not match.

One small point worth knowing: `php -n` tells the CLI not to load the normal `php.ini`; it does not necessarily mean that every extension is absent. The PoC checks for `SoapClient`, so the PHP binary still needs SOAP support available in the tested build.

The supplied log ends with these relevant lines:

```
overwrite_returned
marker_check=present
marker_content=PHP857_RCE
```

The meaningful outcome is that the marker was present with the expected content. The output also records process-specific addresses and other intermediate values for debugging. Those details may explain one run, but they are not stable values for every process and should not be copied into a generic exploit tutorial.

## What the GDB trace adds

The supplied debugger transcript is useful because it provides a second source of evidence beyond the PHP script's own output.

The first stack records a write flowing through the Zend hash-table update path and the SOAP HTTP response handler. In the supplied trace, the relevant path includes `zend_hash_index_update()`, `zend_symtable_update()`, `make_http_soap_request()`, and the `SoapClient` request path. That is consistent with the report's claim that a numeric cookie header reaches the integer-key update operation.

A later part of the debugger transcript records execution inside `zif_system()` and shows the PHP VM's function-call handler on the stack. The marker check then records the marker content.

Put simply:

* **The PHP log** says the expected marker appeared.
* **The debugger trace** says the observed native call path reached the claimed function.
* **Together**, those are stronger local evidence than a print statement alone.

They still don't independently establish every remote precondition. A debugger replay on one build cannot prove that a third-party SOAP integration is remotely controllable or that the exact technique works on other PHP builds and operating systems.

## A realistic business example and what must be true for it to matter

<figure><img src="../.gitbook/assets/image (635).png" alt=""><figcaption></figcaption></figure>

Imagine an order-management app that calls a logistics provider through SOAP. When a customer opens the tracking page, the app asks the provider for the parcel status. The PHP worker receives an XML response and some HTTP headers, including possibly a cookie.

If the reported chain is valid for the deployment, the critical question is whether an attacker can cause the PHP worker to process a response they control. This could be possible if the actual endpoint is compromised, if the application is configured to trust an attacker-controlled service, or if a proxy/TLS setup permits response tampering. It should not be assumed merely because an application calls a SOAP service.

For a properly configured HTTPS service, passive network access is not normally enough to rewrite the response. DNS poisoning alone should not bypass correctly verified TLS certificates. A realistic assessment must check the actual endpoint, hostname validation, proxy settings, certificate verification, and whether redirects or user-controlled service locations can change where the client connects.

If arbitrary command execution occurs inside a production PHP worker, the operating-system identity of that worker defines the first level of impact. Depending on its permissions, an attacker may be able to read application source, configuration files, database credentials, API tokens, session files, or mounted data. They may also run processes or modify files available to that account. A constrained container and a dedicated low-privilege account reduce the blast radius but do not make a confirmed code-execution issue acceptable.

## Why this is not “just a numeric cookie bug”

It is tempting to focus on the numeric `Set-Cookie` name because it is easy to see in the debugger trace. But it is only one stage of the reported chain.

The numeric-key path is a normal part of PHP's array semantics. If the hash table is valid, using an integer key is expected. The security concern described here requires the earlier memory-corruption stages to have changed the cookie storage reference or table metadata so that an otherwise valid update operates on invalid state.

That is why a fix assessment needs to consider the full chain, not just reject cookie names that look numeric. Input filtering may break one proof-of-concept path, but it would not repair an internal property invariant violation or an unsafe native dereference. The robust fix needs to validate the native value at the point of use and prevent internal objects from reaching inconsistent states.

## What to check before calling the finding remotely exploitable

For this class of report, I would keep a checklist beside the evidence:

1. **Affected build:** exact PHP version, commit or release tarball, SAPI, OS, architecture, compiler options, and enabled extensions.
2. **Native root cause:** exact source lines in the tested release, expected type and lifetime of the field, and the patch or assertion that changes the behaviour.
3. **Repeatability:** fresh runs, allocator variations, ASLR enabled, and results on a second build where relevant.
4. **SOAP reachability:** proof that the application processes a response influenced by the assumed attacker, rather than only a locally controlled loopback response.
5. **Impact:** the privilege boundary of the PHP worker and the actual filesystem/network access available to it.
6. **Vendor status:** acknowledgement or advisory status, patch status by supported branch, and whether downstream vendors have backported a fix.

If any of these is not established, say so directly in the report. That is not weakening the research. It tells maintainers exactly what has been proven and what still needs work.

## Defensive checks for PHP application owners

The advice below is general defence-in-depth. It is not a substitute for a PHP patch if maintainers confirm the reported native issue.

### Inventory PHP runtimes and SOAP usage

Capture the runtime version and active configuration on each host:

```bash
php -v
php --ini
php -m | grep -Ei '^(soap|spl)$'
php --ri soap
```

These commands are read-only. Remember that the CLI runtime can differ from PHP-FPM, Apache `mod_php`, or another web SAPI. Confirm the version and loaded extensions for the actual service process, not only your shell.

Search the application code for SOAP clients and calls:

```bash
rg -n 'new\s+SoapClient|->__soapCall\s*\(' . --glob '*.php'
```

Then review where each endpoint comes from, whether callers can influence it, and how TLS validation and proxies are configured.

### Reduce the blast radius

* Run PHP as a dedicated low-privilege OS account.
* Keep application code read-only to the web worker wherever possible.
* Do not expose secrets to the worker that it does not need.
* Restrict outbound network access to the services the application actually uses.
* Isolate services with containers or other OS controls, while remembering that isolation does not repair the underlying memory-safety issue.
* Alert on unexpected child processes, unexpected writes in application directories, and suspicious outbound connections from PHP workers.

### Upgrade based on the correct advisory

Do not pick a version based only on the fact that it is newer than 8.5.7. As of 26 October 2026, the PHP archive lists newer releases—including PHP 8.5.12, 8.4.27, 8.3.36, and 8.2.35—for other critical security advisories. That is important operational information, but it is not evidence that this specific StreamBucket/SOAP chain is fixed. Use the actual advisory or patch for this finding and verify the package offered by your OS or hosting vendor.

If the maintainers confirm that the chain is not fixed yet, ask them for the recommended mitigation for the exact affected paths. Disabling SOAP can be a temporary option only where the application does not need it; do not imply that generic WAF rules can reliably fix native memory corruption.

## Severity: report claim versus confirmed result

The supplied advisory assigns a CVSS 3.1 score of 10.0 and describes a no-authentication, remote-response scenario. That score depends on the remote attack path actually meeting those assumptions. The local evidence supports the claim that the tested process reached the marker-writing outcome, but it is not sufficient on its own to independently confirm network attack vector, privileges required, user interaction, or scope change for every deployment.

For publication, use one of these formulations depending on the evidence you can independently demonstrate:

* **Conservative:** “The supplied PoC demonstrates local command execution on the tested PHP 8.5.7 build; remote reachability depends on controlling the response consumed by the SOAP client.”
* **Stronger, only after validation:** “An attacker able to control the SOAP response processed by the affected build can reach the demonstrated chain under the listed preconditions.”
* **Do not claim without confirmation:** “Every PHP 8.5.7 server is remotely exploitable without authentication.”

The last sentence goes beyond what the local loopback test alone proves.

## Conclusion

This research is interesting because it connects multiple internal assumptions rather than relying on one obvious application-level bug. `ArrayIterator` supplies the reported property-mutation path; `StreamBucket` is where the type expectation is alleged to break; custom stream filters and marker allocations are used to observe memory in the local process; SOAP cookie processing supplies a later update operation; and the GDB trace records the reported path into `zif_system()`.

The defensive lesson is straightforward: native code must validate the actual value it dereferences, including its type and lifetime. Checking a separate resource field does not make a different property a valid string. A hash-table update must also be operating on a valid table. And a local proof of code execution should be reported separately from remote exploitability until the application-level response-control precondition has been demonstrated.

The other lesson is about reporting quality. A strong vulnerability write-up shows which evidence supports each claim, provides exact build information, states the limitations, and distinguishes a researcher’s report from a vendor-confirmed advisory. That makes the finding easier for maintainers to reproduce and harder to misunderstand.

## References

* [PHP source repository](https://github.com/php/php-src)
* [PHP security advisories](https://github.com/php/php-src/security/advisories) checked 26 October 2026
* [PHP 2026 news and security archive](https://www.php.net/archive/2026.php) current releases and separate advisories
* [PHP 8.5.7 release announcement](https://www.php.net/releases/8_5_7.php)
* [`SoapClient` manual](https://www.php.net/manual/en/class.soapclient.php)
* [`stream_bucket_new()` manual](https://www.php.net/manual/en/function.stream-bucket-new.php)
* [Zend hash-table helpers (`zend_hash.h`)](https://github.com/php/php-src/blob/master/Zend/zend_hash.h)
* [SPL array implementation (`spl_array.c`)](https://github.com/php/php-src/blob/master/ext/spl/spl_array.c)
* [SOAP HTTP implementation (`php_http.c`)](https://github.com/php/php-src/blob/master/ext/soap/php_http.c)
* Research artifact identifiers supplied by the author: `rpoc.php`, `validate.sh`, `local-validation.txt`, and `gdb-proof.txt`.
