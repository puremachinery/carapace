#!/usr/bin/env bash
set -euo pipefail

out_dir="${1:-public}"

if ! command -v pandoc >/dev/null 2>&1; then
  echo "Error: pandoc is required (https://pandoc.org/installing.html)" >&2
  exit 1
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"
cookbook_dir="${repo_root}/docs/cookbook"
out_cookbook_dir="${out_dir}/cookbook"

mkdir -p "${out_cookbook_dir}"

render_markdown_page() {
  local src="$1"
  local dst="$2"
  local page_title="$3"
  local description="$4"
  local breadcrumbs="$5"

  local body
  body="$(pandoc --from gfm --to html5 "$src")"

  # Cookbook Markdown stays canonical; convert local .md links to site pages.
  body="$(printf '%s' "$body" | sed -E \
    -e 's|href="README\.md"|href="/carapace/cookbook/"|g' \
    -e 's|href="([^":#]+)\.md"|href="\1.html"|g')"

  {
    cat <<HTML_HEAD
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>${page_title}</title>
    <meta name="description" content="${description}" />
    <meta property="og:title" content="${page_title}" />
    <meta property="og:description" content="${description}" />
    <meta property="og:type" content="website" />
    <meta name="theme-color" content="#0f172a" />
    <link rel="preconnect" href="https://fonts.googleapis.com" />
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
    <link
      href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono&family=Space+Grotesk:wght@400;600;700&display=swap"
      rel="stylesheet"
    />
    <link rel="stylesheet" href="/carapace/styles.css" />
  </head>
  <body>
    <div class="bg-shape bg-shape-one" aria-hidden="true"></div>
    <div class="bg-shape bg-shape-two" aria-hidden="true"></div>

    <header class="site-header">
      <a class="brand" href="/carapace/">Carapace</a>
      <nav class="nav-links" aria-label="Primary">
        <a href="/carapace/">Home</a>
        <a href="/carapace/getting-started.html">Getting Started</a>
        <a href="/carapace/cookbook/">Cookbook</a>
        <a href="https://github.com/puremachinery/carapace">GitHub</a>
      </nav>
    </header>

    <main class="doc-main recipe-main">
HTML_HEAD

    if [ -n "$breadcrumbs" ]; then
      printf '      <p class="breadcrumbs">%s</p>\n' "$breadcrumbs"
    fi

    cat <<'HTML_BODY'
      <article class="panel doc-panel md-content">
HTML_BODY

    printf '%s\n' "$body"

    cat <<'HTML_FOOT'
      </article>
    </main>

    <footer class="site-footer">
      <p>Carapace by PureMachinery.</p>
      <a href="https://github.com/puremachinery/carapace/issues/new/choose">Report an issue</a>
    </footer>
  </body>
</html>
HTML_FOOT
  } >"$dst"
}

render_markdown_page \
  "${cookbook_dir}/README.md" \
  "${out_cookbook_dir}/index.html" \
  "Carapace | Cookbook" \
  "Task-focused Carapace walkthroughs for setup and integrations." \
  ""

while IFS= read -r src; do
  file_name="$(basename "$src")"

  if [[ "$file_name" == "README.md" || "$file_name" == "_template.md" ]]; then
    continue
  fi

  stem="${file_name%.md}"
  heading="$(sed -n 's/^# //p' "$src" | head -n 1)"

  if [ -z "$heading" ]; then
    heading="$stem"
  fi

  render_markdown_page \
    "$src" \
    "${out_cookbook_dir}/${stem}.html" \
    "Carapace Cookbook | ${heading}" \
    "Carapace recipe: ${heading}" \
    "<a href=\"/carapace/cookbook/\">Cookbook</a> / ${heading}"
done < <(find "${cookbook_dir}" -maxdepth 1 -type f -name '*.md' | sort)

echo "Generated cookbook pages in ${out_cookbook_dir}"
