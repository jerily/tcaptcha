# tcaptcha

PNG CAPTCHA challenges for Tcl 8.6 and Tcl 9, using FlightAware's `tclgd`,
`twebserver` for cryptographic randomness, and Tink for keyed verification.
Images use built-in glyphs, so no font files are required. Length and inclusion
of letters are configurable; the default is six letters and digits.

## API

```tcl
package require tcaptcha 0.1.0

# Use a persistent host-owned HMAC_SHA256 keyset, registered in each worker.
# Include the tenant, purpose and browser session in this context.
set context [list my-site registration $sessionId]
set challenge [::tcaptcha::create -mac $macHandle -context $context -ttl 300 -length 6 -letters true]

set png [dict get $challenge png]
set state [dict get $challenge state]
# Store state on the server, in the browser's session. Send only png to the user.

set valid [::tcaptcha::verify $macHandle $context $state $submittedAnswer]
```

`create` returns `png` (binary PNG bytes, 240 × 80 with the default length) and `state` (a dictionary
with a random `id`, an `expires` timestamp, and a keyed `tag`). It never returns
the answer. `-mac` and a nonempty `-context` are required. `-ttl` defaults to 300
seconds and accepts 1–3600 seconds. `-length` defaults to 6 and accepts 4–12
characters; the image width is `24 + 36 * length` pixels, with a height of 80.
`-letters` is a boolean, defaulting to true: use the alphabet
`23456789ABCDEFGHJKLMNPQRSTUVWXYZ`. Set it to false for digits only (`0123456789`).
Short numeric challenges have fewer possible answers; enforce attempt limits.

`verify` returns a boolean. It ignores surrounding whitespace and letter case,
checks expiry, and verifies the answer and challenge metadata with Tink's MAC
verification. Wrong answers, expired or malformed state, and changes to the
context or authenticated metadata fail verification. Operational errors, such
as an invalid host key handle, remain errors.

The host owns persistence and must atomically consume a challenge when it is
used, enforce attempt limits, protect forms with CSRF checks, and bind the state
to the correct browser session. `verify` alone does not consume state. Store it
in shared persistent storage when requests can reach different workers. Never
send the state or key to the client. The image has no embedded textual answer.

`::tcaptcha::image TEXT` renders 4–12 uppercase supported characters without
creating a verification state. It accepts digits 0–9 and the letters above.
It is useful for previews; normal challenges should use `create`.

This is a basic image CAPTCHA, not proof that a request came from a human.
It has no audio alternative and cannot be solved using a screen reader alone;
hosts should provide an accessible registration alternative when enabling it.

## Build and example

Install the native dependencies with ttrek using the updated registry:

```sh
# In a separate, empty directory:
mkdir -p /tmp/tcaptcha-deps
cd /tmp/tcaptcha-deps
ttrek init -y
ttrek install -y tclgd tink-tcl twebserver
```

From this checkout, with `/tmp/tcaptcha-deps/ttrek-venv/local/lib` on
`TCLLIBPATH` (and its shared libraries on the loader search path):

```sh
cmake -S . -B build -DBUILD_TESTING=OFF -DCMAKE_INSTALL_PREFIX=/path/to/prefix
cmake --install build
tclsh9.1 examples/demo.tcl captcha.png 6 true
# Eight digits only:
tclsh9.1 examples/demo.tcl digits.png 8 false
```

The example writes an image, prompts for its characters, and verifies the
answer. It generates a temporary key for that standalone demonstration only.
A web application must retain its key across workers and restarts.

Run tests with the native dependencies available:

```sh
tclsh9.1 tests/all.tcl
# or, with dependencies compiled for Tcl 8.6:
tclsh8.6 tests/all.tcl
```

Tests cover real PNG generation and decoding, valid answers, context and key
binding, expiry and tampering, malformed input, unique identifiers, and cleanup
of image commands, configurable lengths, and numeric-only challenges. The companion `web-user` tests cover the persistent,
single-use registration flow.

## License

MIT; see [LICENSE](LICENSE).
