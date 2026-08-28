#!/bin/sh
# The MedSign test gate.
#
# Called from Directory.Build.targets as part of building MedSign.Api, so that a
# failing suite fails the build -- which is what actually stops dotnet watch from
# (re)starting the backend.
#
# Usage: test-gate.sh <path to the built MedSign.Tests assembly>
#
# The assembly is run directly rather than through `dotnet test`, because the
# xUnit console runner accepts -result-ctrf (the JSON report the coach dashboard
# reads) and the .NET 10 `dotnet test` front end will not pass that flag through.

set -u
assembly="$1"
status="${MEDSIGN_STATUS_DIR:-/status}"
log=$(mktemp)

# Skipped entirely when the status directory is not mounted, so the gate still
# works outside the workshop container.
write_state() {
    [ -d "$status" ] || return 0
    printf '{ "state": "%s" }\n' "$1" > "$status/state.json" 2>/dev/null || true
}

write_state running

if [ -d "$status" ]; then
    # Written under a temporary name and moved into place, so the dashboard can
    # never fetch a half-written report.
    ctrf="$status/.results.tmp"
else
    ctrf=$(mktemp)
fi

dotnet exec "$assembly" -result-ctrf "$ctrf" -noColor > "$log" 2>&1
code=$?

if [ -d "$status" ] && [ -s "$ctrf" ]; then
    mv -f "$ctrf" "$status/results.json" 2>/dev/null || true
fi
rm -f "$ctrf" 2>/dev/null || true

# Where to write the human report.
#
# Not through MSBuild. dotnet watch builds at quiet verbosity, which drops every
# high-importance Message, and an Error carrying the report instead gets each of
# its lines prefixed with "Directory.Build.targets(87,5): error :" -- unreadable
# exactly when it matters most. PID 1 owns the container's stdout, so writing
# there puts the report in `docker compose up` output verbatim. Anywhere else,
# fall back to our own stdout.
console=/proc/1/fd/1
[ -w "$console" ] || console=/dev/stdout

if [ "$code" -ne 0 ]; then
    write_state failed
    {
        echo
        echo "  ================================================================"
        echo "   TESTS FAILED - the backend will NOT start"
        echo "  ================================================================"
        echo
        # xUnit already names the test, the assertion that broke, and the file
        # and line. The frame just makes it impossible to scroll past.
        sed 's/^/  /' "$log"
        echo
        echo "  ----------------------------------------------------------------"
        echo "   Fix the tests above and save. The backend restarts by itself."
        echo "   The dashboard at http://localhost:4300 shows the same thing."
        echo "  ----------------------------------------------------------------"
        echo
    } > "$console" 2>/dev/null
else
    write_state passed
    # One line, so a passing run is visible without being noise. "Skipped" here
    # means an exercise nobody has started yet, which is worth seeing.
    grep -E "Total: [0-9]+" "$log" | sed 's/^ *//; s/^/  MedSign tests: /' > "$console" 2>/dev/null
fi

rm -f "$log"
exit "$code"
