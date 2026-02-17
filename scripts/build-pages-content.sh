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
site_docs_dir="${repo_root}/docs/site"

out_cookbook_dir="${out_dir}/cookbook"
mkdir -p "${out_dir}" "${out_cookbook_dir}"

rewrite_links() {
  local body="$1"
  local kind="$2"

  body="$(printf '%s' "$body" | sed -E \
    -e 's|href="\.\./CONTRIBUTING\.md"|href="https://github.com/puremachinery/carapace/blob/HEAD/CONTRIBUTING.md"|g' \
    -e 's|href="cookbook/README\.md"|href="cookbook/"|g' \
    -e 's|href="cookbook/([^":#]+)\.md"|href="cookbook/\1.html"|g' \
    -e 's|href="\.\./cookbook/README\.md"|href="cookbook/"|g' \
    -e 's|href="\.\./cookbook/([^":#]+)\.md"|href="cookbook/\1.html"|g' \
    -e 's|href="site/([^":#]+)\.md"|href="\1.html"|g')"

  if [[ "$kind" == "cookbook" ]]; then
    body="$(printf '%s' "$body" | sed -E \
      -e 's|href="README\.md"|href="./"|g' \
      -e 's|href="([A-Za-z0-9._-]+)\.md"|href="\1.html"|g')"
  elif [[ "$kind" == "docs" ]]; then
    body="$(printf '%s' "$body" | sed -E \
      -e 's|href="([A-Za-z0-9._-]+)\.md"|href="\1.html"|g')"
  fi

  printf '%s' "$body"
}

render_markdown_page() {
  local src="$1"
  local dst="$2"
  local page_title="$3"
  local description="$4"
  local breadcrumbs="$5"
  local kind="$6"
  local request_cta="$7"
  local rel_prefix="$8"

  if [ ! -f "$src" ]; then
    echo "Error: missing source markdown: $src" >&2
    exit 1
  fi

  local body
  body="$(pandoc --from gfm --to html5 "$src")"
  body="$(rewrite_links "$body" "$kind")"

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
    <link rel="stylesheet" href="${rel_prefix}/styles.css" />
  </head>
  <body>
    <div class="bg-shape bg-shape-one" aria-hidden="true"></div>
    <div class="bg-shape bg-shape-two" aria-hidden="true"></div>

    <header class="site-header">
      <a class="brand" href="${rel_prefix}/">Carapace</a>
      <nav class="nav-links" aria-label="Primary">
        <a href="${rel_prefix}/">Home</a>
        <a href="${rel_prefix}/getting-started.html">Getting Started</a>
        <a href="${rel_prefix}/install.html">Install</a>
        <a href="${rel_prefix}/first-run.html">First Run</a>
        <a href="${rel_prefix}/cookbook/">Cookbook</a>
        <a href="${rel_prefix}/get-unstuck.html">Get Unstuck</a>
        <a href="https://github.com/puremachinery/carapace">GitHub</a>
      </nav>
    </header>

    <main class="doc-main ${kind}-main">
HTML_HEAD

    if [ -n "$breadcrumbs" ]; then
      printf '      <p class="breadcrumbs">%s</p>\n' "$breadcrumbs"
    fi

    cat <<'HTML_BODY'
      <article class="panel doc-panel md-content">
HTML_BODY

    printf '%s\n' "$body"

    cat <<'HTML_MIDDLE'
      </article>
HTML_MIDDLE

    if [[ "$request_cta" == "1" ]]; then
      cat <<'HTML_CTA'
      <section class="panel doc-panel cta-panel" aria-label="Recipe request">
        <h2>Need a recipe for your use case?</h2>
        <p>
          Tell us what outcome you want and we can prioritize a walkthrough.
        </p>
        <p>
          <a class="button button-secondary" href="https://github.com/puremachinery/carapace/issues/new?template=cookbook-recipe-request.yml&title=cookbook%3A+%3Cuse+case%3E">Request a cookbook recipe</a>
        </p>
      </section>
HTML_CTA
    fi

    cat <<'HTML_FOOT'
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
  "${repo_root}/docs/getting-started.md" \
  "${out_dir}/getting-started.html" \
  "Carapace | Getting Started" \
  "Install, first run, and practical operations for Carapace." \
  "" \
  "docs" \
  "0" \
  "."

render_markdown_page \
  "${site_docs_dir}/install.md" \
  "${out_dir}/install.html" \
  "Carapace | Install" \
  "Install Carapace binaries and verify signatures." \
  "<a href=\"./getting-started.html\">Getting Started</a> / Install" \
  "docs" \
  "0" \
  "."

render_markdown_page \
  "${site_docs_dir}/first-run.md" \
  "${out_dir}/first-run.html" \
  "Carapace | First Run" \
  "Run Carapace locally with secure defaults and verify health." \
  "<a href=\"./getting-started.html\">Getting Started</a> / First Run" \
  "docs" \
  "0" \
  "."

render_markdown_page \
  "${site_docs_dir}/get-unstuck.md" \
  "${out_dir}/get-unstuck.html" \
  "Carapace | Get Unstuck" \
  "Troubleshooting checks, logs, and issue-reporting paths for Carapace." \
  "<a href=\"./getting-started.html\">Getting Started</a> / Get Unstuck" \
  "docs" \
  "0" \
  "."

render_markdown_page \
  "${cookbook_dir}/README.md" \
  "${out_cookbook_dir}/index.html" \
  "Carapace | Cookbook" \
  "Task-focused Carapace walkthroughs for setup and integrations." \
  "" \
  "cookbook" \
  "1" \
  ".."

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
    "<a href=\"./\">Cookbook</a> / ${heading}" \
    "cookbook" \
    "1" \
    ".."
done < <(find "${cookbook_dir}" -maxdepth 1 -type f -name '*.md' | sort)

echo "Generated Pages content in ${out_dir}"
