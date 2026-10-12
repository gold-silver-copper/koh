#!/bin/sh
# koh's oracle: koh at the working tree beside koh at a commit, compared on what the user's
# terminal would show. See testing/oracle/README.md.
#
#   testing/oracle.sh [REF] [ARGS...]   against REF (the merge base with the upstream default branch by default)
#   testing/oracle.sh --plants          show the oracle finds each bug in testing/oracle/plants/
#   testing/oracle.sh --replay FILE     run one saved case against the default REF
#
# ARGS go to the driver: --cases N, --seed S, --no-recordings, --replay FILE, --save DIR.
set -eu

root=$(git rev-parse --show-toplevel)
cd "$root"
oracle=testing/oracle
target=$oracle/target

# Build the side and the driver at the working tree.
build_tree() {
    cargo build --locked --quiet --release --manifest-path "$oracle/Cargo.toml"
}

# Build the side at commit $1 into $target/sides/$2 ($1 by default); prints the binary's path. The side's source
# is copied into a worktree of the commit, beside that commit's koh, with that commit's lockfile,
# so the commit's koh builds with the dependencies it was committed with.
build_side_at() {
    sha=$1
    out=${2:-$1}
    tree=$target/trees/$sha
    # A cached target directory can hold the tree's directory without its worktree.
    if [ ! -f "$tree/.git" ] || [ ! -f "$tree/Cargo.toml" ]; then
        rm -rf "$tree"
        git worktree prune
        mkdir -p "$target/trees"
        git worktree add --quiet --detach "$tree" "$sha"
    fi
    mkdir -p "$tree/$oracle"
    cp "$oracle/Cargo.toml" "$tree/$oracle/"
    rm -rf "$tree/$oracle/side" "$tree/$oracle/driver"
    cp -R "$oracle/side" "$oracle/driver" "$tree/$oracle/"
    # Use this commit's harness lockfile, which includes the side/driver packages. Copying
    # the root lockfile requires Cargo to rewrite it even when dependency versions agree.
    if ! git -C "$tree" show "HEAD:$oracle/Cargo.lock" >"$tree/$oracle/Cargo.lock"; then
        echo "oracle: baseline has no committed harness lockfile; choose a newer REF" >&2
        return 1
    fi
    cargo build --locked --quiet --release --manifest-path "$tree/$oracle/Cargo.toml" \
        -p koh-oracle-side --target-dir "$target/sides/$out" >&2
    echo "$target/sides/$out/release/koh-oracle-side"
}

default_ref() {
    if upstream=$(git symbolic-ref --quiet refs/remotes/origin/HEAD); then
        git merge-base HEAD "$upstream"
    elif git show-ref --verify --quiet refs/remotes/origin/master; then
        git merge-base HEAD origin/master
    else
        echo "oracle: no upstream default branch; fetch origin or pass an explicit REF" >&2
        return 1
    fi
}

if [ "${1:-}" = "--plants" ]; then
    build_tree
    head=$(git rev-parse HEAD)
    base=$target/release/koh-oracle-side
    # Exercise the code just built, including tracked edits, rather than silently testing HEAD.
    git diff --binary HEAD >"$target/working.patch"
    status=0
    for patch in "$oracle"/plants/*.patch; do
        name=$(basename "$patch" .patch)
        sha=plant-$name
        tree=$target/trees/$sha
        rm -rf "$tree"
        git worktree prune
        git worktree add --quiet --detach "$tree" "$head"
        if [ -s "$target/working.patch" ]; then
            git -C "$tree" apply "$root/$target/working.patch"
        fi
        git -C "$tree" apply "$root/$patch"
        planted=$(build_side_at "$sha" planted)
        printf '%s: ' "$name"
        if "$target/release/koh-oracle" --side "$planted" --base "$base" \
            --save "$target/plants" >"$target/plants-$name.log" 2>&1; then
            echo "NOT FOUND"
            status=1
        elif grep -q '^DIFFERENCE' "$target/plants-$name.log"; then
            found=$(grep -m1 '^DIFFERENCE' "$target/plants-$name.log" | cut -d: -f1)
            shrunk=$(grep -m1 '^shrunk to' "$target/plants-$name.log" | cut -d: -f1)
            echo "found: $found, $shrunk"
        else
            echo "oracle failed without detecting the planted difference" >&2
            cat "$target/plants-$name.log" >&2
            status=1
        fi
        git worktree remove --force "$tree"
    done
    exit $status
fi

case "${1:-}" in
"" | -*) ref=$(default_ref) ;;
*)
    ref=$1
    shift
    ;;
esac
sha=$(git rev-parse --verify "$ref^{commit}")
echo "koh at the working tree beside koh at $(git log -1 --format='%h %s' "$sha")"
build_tree
base=$(build_side_at "$sha")
exec "$target/release/koh-oracle" --side "$target/release/koh-oracle-side" --base "$base" "$@"
