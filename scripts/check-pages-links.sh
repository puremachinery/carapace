#!/usr/bin/env bash
set -euo pipefail

site_dir="${1:-public}"

if [ ! -d "${site_dir}" ]; then
  echo "Error: site directory '${site_dir}' does not exist" >&2
  exit 1
fi

missing=0

while IFS= read -r -d '' html_file; do
  html_dir="$(dirname "${html_file}")"

  while IFS= read -r href_attr; do
    href="${href_attr#href=\"}"
    href="${href%\"}"

    case "${href}" in
      "" | \#* | http://* | https://* | mailto:* | tel:* | javascript:*)
        continue
        ;;
    esac

    target="${href%%#*}"
    target="${target%%\?*}"

    [ -z "${target}" ] && continue

    if [[ "${target}" == /* ]]; then
      resolved_path="${site_dir}/${target#/}"
    else
      resolved_path="${html_dir}/${target}"
    fi

    if [[ "${target}" == */ ]]; then
      resolved_path="${resolved_path%/}/index.html"
    elif [[ -d "${resolved_path}" ]]; then
      resolved_path="${resolved_path%/}/index.html"
    fi

    if [ ! -e "${resolved_path}" ]; then
      echo "Broken internal link: ${html_file} -> ${href}" >&2
      missing=1
    fi
  done < <(grep -oE 'href="[^"]+"' "${html_file}" || true)
done < <(find "${site_dir}" -type f -name '*.html' -print0)

if [ "${missing}" -ne 0 ]; then
  exit 1
fi

echo "Internal site links validated successfully."
