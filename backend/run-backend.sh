#!/usr/bin/env bash
# Starts the Participant Backend under `dotnet watch`, and keeps it there.
#
# This runs as PID 1 in the backend container. It exists because of one specific
# failure that is otherwise invisible.
#
# dotnet watch's polling file watcher (polling is not optional here: inotify
# events do not cross a Docker Desktop bind mount from a Windows host) dies with
#
#   Unhandled exception. System.ArgumentException:
#   An item with the same key has already been added. Key: /src/...
#
# if a file appears inside the watched tree while it happens to be enumerating
# it. That is a readdir quirk of the bind mount, not of the code. The damage is
# out of all proportion to the cause: killing the watcher does NOT kill the app
# it already started, so the backend keeps answering on :5000 and looks
# perfectly healthy while silently ignoring every save from then on, test gate
# included. A participant would spend the rest of the workshop editing code that
# is never compiled.
#
# So: remove the known trigger, and survive the unknown ones.

set -u

STATUS_DIR="${MEDSIGN_STATUS_DIR:-/status}"
PROJECT=MedSign.Api/MedSign.Api.csproj

cd /src || exit 1

# Everything from here reaches both the compose log and the dashboard's build.log.
if [ -d "$STATUS_DIR" ]; then
    exec > >(tee "$STATUS_DIR/build.log") 2>&1
else
    exec 2>&1
fi

# Trigger removal: the app writes its JWT signing key into the watched tree on
# first run, which is a brand new directory entry appearing under the watcher's
# feet. Creating it here, before the watcher starts looking, takes that away.
# The app truncates and rewrites this file rather than replacing it, so it never
# creates a second entry later.
[ -e MedSign.Api/.env ] || : > MedSign.Api/.env

# Restore once, up front. The test gate builds MedSign.Tests through an MSBuild
# task, which does not restore, and dotnet watch only knows about MedSign.Api
# and the projects it references.
dotnet restore MedSign.slnx || exit 1

# Then build once, before anything is watching.
#
# This is the second half of the trigger removal. A build writes a handful of
# generated files (AssemblyInfo.cs, GlobalUsings.g.cs and friends) into an
# artifacts folder beside the projects, and no amount of ArtifactsPath
# redirection reaches the evaluation that puts them there. They are only ever
# *created* once and rewritten thereafter, so doing it now, with no watcher
# running, means the watcher only ever sees a tree that has stopped growing.
#
# It also gives the dashboard a first result before the app is up, and leaves
# the first save with nothing to compile but the change itself. Failures are not
# fatal here: the watch loop below reports them properly.
dotnet build MedSign.slnx --no-restore || true

shutting_down=0
stop() {
    shutting_down=1
    reap
    exit 0
}
trap stop TERM INT

# Takes down anything the dead watcher left running. Without this the orphan
# still holds port 5000 and the fresh watcher cannot bind.
reap() {
    pkill -f 'MedSign.Api/debug/MedSign.Api' 2>/dev/null
    pkill -f 'dotnet run --project MedSign.Api' 2>/dev/null
    sleep 1
}

while true; do
    dotnet watch run --project "$PROJECT" --no-launch-profile --no-hot-reload
    [ "$shutting_down" = 1 ] && exit 0

    echo
    echo "  ================================================================"
    echo "   The file watcher stopped. Restarting it."
    echo "   Saves made in the last few seconds may not have been picked up;"
    echo "   save again if the dashboard does not catch up."
    echo "  ================================================================"
    echo

    reap
done
