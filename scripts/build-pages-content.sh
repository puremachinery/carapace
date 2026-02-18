#!/usr/bin/env bash
# Generate static website docs pages from Markdown sources.
#
# Usage:
#   scripts/build-pages-content.sh [OUT_DIR]
#
# Arguments:
#   OUT_DIR  Optional output directory for generated files (default: "public").
#
# Dependencies:
#   - pandoc (https://pandoc.org/installing.html)
#
# This script is used by the Pages workflow to render docs/getting-started.md,
# docs/site/*.md, and docs/cookbook/*.md into HTML pages for publishing.
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

html_escape() {
  local value="$1"
  value="${value//&/&amp;}"
  value="${value//</&lt;}"
  value="${value//>/&gt;}"
  value="${value//\"/&quot;}"
  value="${value//\'/&#39;}"
  printf '%s' "$value"
}

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
      -e 's|href="([A-Za-z0-9._/-]+)\.md"|href="\1.html"|g')"
  elif [[ "$kind" == "docs" ]]; then
    body="$(printf '%s' "$body" | sed -E \
      -e 's|href="([A-Za-z0-9._/-]+)\.md"|href="\1.html"|g')"
  fi

  printf '%s' "$body"
}

render_markdown_page() {
  local src="$1"
  local dst="$2"
  local page_title="$3"
  local description="$4"
  local kind="$5"
  local request_cta="$6"
  local rel_prefix="$7"
  local breadcrumb_parent_href="$8"
  local breadcrumb_parent_label="$9"
  local breadcrumb_current_label="${10}"

  if [ ! -f "$src" ]; then
    echo "Error: missing source markdown: $src" >&2
    exit 1
  fi

  local body
  body="$(pandoc --from gfm --to html5 "$src")"
  body="$(rewrite_links "$body" "$kind")"

  local page_title_html description_html rel_prefix_html
  page_title_html="$(html_escape "$page_title")"
  description_html="$(html_escape "$description")"
  rel_prefix_html="$(html_escape "$rel_prefix")"

  {
    cat <<HTML_HEAD
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>${page_title_html}</title>
    <meta name="description" content="${description_html}" />
    <meta property="og:title" content="${page_title_html}" />
    <meta property="og:description" content="${description_html}" />
    <meta property="og:type" content="website" />
    <meta name="theme-color" content="#0f172a" />
    <link rel="preconnect" href="https://fonts.googleapis.com" />
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
    <link
      href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono&family=Space+Grotesk:wght@400;600;700&display=swap"
      rel="stylesheet"
    />
    <link rel="stylesheet" href="${rel_prefix_html}/styles.css" />
  </head>
  <body>
    <div class="bg-shape bg-shape-one" aria-hidden="true"></div>
    <div class="bg-shape bg-shape-two" aria-hidden="true"></div>

    <header class="site-header">
      <a class="brand" href="${rel_prefix_html}/">Carapace</a>
      <nav class="nav-links" aria-label="Primary">
        <a href="${rel_prefix_html}/">Home</a>
        <a href="${rel_prefix_html}/getting-started.html">Getting Started</a>
        <a href="${rel_prefix_html}/install.html">Install</a>
        <a href="${rel_prefix_html}/first-run.html">First Run</a>
        <a href="${rel_prefix_html}/security.html">Security</a>
        <a href="${rel_prefix_html}/ops.html">Ops</a>
        <a href="${rel_prefix_html}/cookbook/">Cookbook</a>
        <a href="${rel_prefix_html}/get-unstuck.html">Get Unstuck</a>
        <a href="https://github.com/puremachinery/carapace">GitHub</a>
      </nav>
    </header>

    <main class="doc-main ${kind}-main">
HTML_HEAD

    if [ -n "$breadcrumb_parent_href" ] && [ -n "$breadcrumb_parent_label" ] && [ -n "$breadcrumb_current_label" ]; then
      local breadcrumb_parent_href_html breadcrumb_parent_label_html breadcrumb_current_label_html
      breadcrumb_parent_href_html="$(html_escape "$breadcrumb_parent_href")"
      breadcrumb_parent_label_html="$(html_escape "$breadcrumb_parent_label")"
      breadcrumb_current_label_html="$(html_escape "$breadcrumb_current_label")"
      printf '      <p class="breadcrumbs"><a href="%s">%s</a> / %s</p>\n' \
        "$breadcrumb_parent_href_html" \
        "$breadcrumb_parent_label_html" \
        "$breadcrumb_current_label_html"
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

render_site_doc_page() {
  local slug="$1"
  local title="$2"
  local description="$3"
  local parent_href="$4"
  local parent_label="$5"

  render_markdown_page \
    "${site_docs_dir}/${slug}.md" \
    "${out_dir}/${slug}.html" \
    "Carapace | ${title}" \
    "${description}" \
    "docs" \
    "0" \
    "." \
    "${parent_href}" \
    "${parent_label}" \
    "${title}"
}

render_markdown_page \
  "${repo_root}/docs/getting-started.md" \
  "${out_dir}/getting-started.html" \
  "Carapace | Getting Started" \
  "Install, first run, and practical operations for Carapace." \
  "docs" \
  "0" \
  "." \
  "" \
  "" \
  ""

render_site_doc_page "install" "Install" \
  "Install Carapace binaries and verify signatures." \
  "./getting-started.html" \
  "Getting Started"
render_site_doc_page "first-run" "First Run" \
  "Run Carapace locally with secure defaults and verify health." \
  "./install.html" \
  "Install"
render_site_doc_page "security" "Security" \
  "Security defaults, trust boundaries, and practical verification checks." \
  "./first-run.html" \
  "First Run"
render_site_doc_page "ops" "Ops" \
  "Day-2 operations: status, logs, backup, update, and recovery." \
  "./security.html" \
  "Security"
render_site_doc_page "get-unstuck" "Get Unstuck" \
  "Troubleshooting checks, logs, and issue-reporting paths for Carapace." \
  "./getting-started.html" \
  "Getting Started"

render_markdown_page \
  "${cookbook_dir}/README.md" \
  "${out_cookbook_dir}/index.html" \
  "Carapace | Cookbook" \
  "Task-focused Carapace walkthroughs for setup and integrations." \
  "cookbook" \
  "1" \
  ".." \
  "" \
  "" \
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
    "cookbook" \
    "1" \
    ".." \
    "./" \
    "Cookbook" \
    "${heading}"
done < <(find "${cookbook_dir}" -maxdepth 1 -type f -name '*.md' | sort)

echo "Generated Pages content in ${out_dir}"
