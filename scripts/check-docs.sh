#!/usr/bin/env bash
# check-docs.sh: offline check of the Markdown documentation.
#
# For every tracked *.md file it verifies that each relative link points at an
# existing file or directory, and that each #anchor matches a heading in the
# target Markdown file (GitHub slug rules). External links (http, https,
# mailto) are not fetched. Links inside fenced code blocks and inline code
# are ignored. Exit status 1 lists every broken link.
#
# Usage: scripts/check-docs.sh [file.md ...]   (default: all tracked *.md)
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

if [[ $# -gt 0 ]]; then
	files=("$@")
else
	files=()
	while IFS= read -r f; do files+=("$f"); done < <(git ls-files --cached --others --exclude-standard '*.md' 2>/dev/null || find . -name '*.md' -not -path './.git/*' | sed 's|^\./||')
fi
[[ ${#files[@]} -gt 0 ]] || { echo "check-docs: no Markdown files found" >&2; exit 1; }

# extract prints "H<TAB>slug" for each heading and "L<TAB>line<TAB>target" for
# each link of one Markdown file.
extract() {
	awk '
	function slug(s,   out) {
		s = tolower(s)
		gsub(/`/, "", s)
		# drop link syntax inside headings: [text](url) -> text
		while (match(s, /\[[^]]*\]\([^)]*\)/)) {
			inner = substr(s, RSTART + 1, RLENGTH - 1); sub(/\]\(.*$/, "", inner)
			s = substr(s, 1, RSTART - 1) inner substr(s, RSTART + RLENGTH)
		}
		gsub(/[^a-z0-9 _-]/, "", s)
		gsub(/ /, "-", s)
		return s
	}
	/^[ ]*(```|~~~)/ { fence = !fence; next }
	fence { next }
	/^#+[ \t]/ {
		h = $0; sub(/^#+[ \t]+/, "", h); sub(/[ \t]+#*[ \t]*$/, "", h)
		s = slug(h)
		n = seen[s]++
		print "H\t" (n ? s "-" n : s)
	}
	{
		line = $0
		gsub(/`[^`]*`/, "", line)          # inline code
		# explicit HTML anchors: <a id="x"> / <a name="x">
		tmp = line
		while (match(tmp, /<a (id|name)="[^"]+"/)) {
			a = substr(tmp, RSTART, RLENGTH); sub(/^<a (id|name)="/, "", a); sub(/"$/, "", a)
			print "H\t" a
			tmp = substr(tmp, RSTART + RLENGTH)
		}
		# inline links and images: ](target) or ](target "title")
		while (match(line, /\]\([^) \t]+([ \t]+"[^"]*")?\)/)) {
			t = substr(line, RSTART + 2, RLENGTH - 3)
			sub(/[ \t].*$/, "", t)
			print "L\t" NR "\t" t
			line = substr(line, RSTART + RLENGTH)
		}
		# reference definitions: [name]: target
		if (match($0, /^[ ]*\[[^]]+\]:[ \t]+[^ \t]+/)) {
			t = $0; sub(/^[ ]*\[[^]]+\]:[ \t]+/, "", t); sub(/[ \t].*$/, "", t)
			print "L\t" NR "\t" t
		}
	}' "$1"
}

anchors_of() { # prints the anchors of a Markdown file, one per line
	extract "$1" | awk -F'\t' '$1 == "H" { print $2 }'
}

broken=0
checked=0
for f in "${files[@]}"; do
	[[ -f "$f" ]] || { echo "check-docs: $f: no such file" >&2; broken=$((broken + 1)); continue; }
	dir="$(dirname "$f")"
	while IFS=$'\t' read -r kind line target; do
		[[ "$kind" == L ]] || continue
		case "$target" in
		http://* | https://* | mailto:*) continue ;;
		esac
		checked=$((checked + 1))
		path="${target%%#*}"
		anchor=""
		[[ "$target" == *"#"* ]] && anchor="${target#*#}"
		if [[ -z "$path" ]]; then
			dest="$f"
		elif [[ "$path" == /* ]]; then
			dest="${path#/}"
		else
			dest="$dir/$path"
		fi
		if [[ ! -e "$dest" ]]; then
			echo "$f:$line: broken link: $target (no such file: $dest)"
			broken=$((broken + 1))
			continue
		fi
		if [[ -n "$anchor" ]]; then
			if [[ "$dest" != *.md || -d "$dest" ]]; then
				# anchors into non-Markdown files (e.g. #L10 line links) are not checked
				continue
			fi
			if ! anchors_of "$dest" | grep -qxF -- "$anchor"; then
				echo "$f:$line: broken anchor: $target (no heading #$anchor in $dest)"
				broken=$((broken + 1))
			fi
		fi
	done < <(extract "$f")
done

if [[ $broken -gt 0 ]]; then
	echo "check-docs: $broken broken link(s) in ${#files[@]} file(s)"
	exit 1
fi
echo "check-docs: ${#files[@]} file(s), $checked relative link(s), all OK"
