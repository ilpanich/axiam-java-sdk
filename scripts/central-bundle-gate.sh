#!/usr/bin/env bash
# Central bundle layout gate.
#
# Builds the deployment bundle that central-publishing-maven-plugin would
# upload, and asserts its layout, without uploading it. Every PR job stops at
# `verify`, and only `deploy` stages a bundle, so without this gate a bundle
# Central will refuse is first seen at a release tag. That is how v1.0.0 first
# failed: under Maven 3.10 the staging install leaves a
# `<groupId>/<artifactId>/maven-metadata-local.xml` that plugin 0.11.0 does not
# delete, and Central rejects any bundle with content outside
# `<groupId>/<artifactId>/<version>/` ("content that does NOT have a .pom
# file"). See RELEASING.md.
#
# The upload cannot happen, by two independent means: the plugin is pointed at
# a closed local port (`-DcentralBaseUrl`), and Maven runs with a throwaway
# settings.xml whose `central` credentials are not a token. The deploy is
# therefore EXPECTED to fail, at the upload and nowhere earlier.
#
# Usage: scripts/central-bundle-gate.sh [pom] [extra mvn args...]
#   scripts/central-bundle-gate.sh pom.xml -Dgpg.skip=false -Dgpg.passphrase=""
#   scripts/central-bundle-gate.sh bom/pom.xml

set -euo pipefail

pom="${1:-pom.xml}"
shift || true
dir="$(dirname "${pom}")"
dead_url="http://127.0.0.1:9"

work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

cat > "${work}/settings.xml" <<'EOF'
<settings>
  <servers>
    <server>
      <id>central</id>
      <username>bundle-gate</username>
      <password>not-a-token</password>
    </server>
  </servers>
</settings>
EOF

evaluate() {
  ./mvnw -B -q -f "${pom}" -DforceStdout help:evaluate -Dexpression="$1"
}
group="$(evaluate project.groupId)"
artifact="$(evaluate project.artifactId)"
version="$(evaluate project.version)"
prefix="${group//.//}/${artifact}/${version}/"

log="${work}/deploy.log"
rm -rf "${dir}/target/central-staging" "${dir}/target/central-publishing"
if ./mvnw -B -f "${pom}" -s "${work}/settings.xml" deploy \
    -DskipTests -Djacoco.skip=true -DcentralBaseUrl="${dead_url}" "$@" \
    > "${log}" 2>&1; then
  echo "::error::deploy of ${artifact} succeeded, but its upload target is a closed port"
  exit 1
fi

# Fail closed on a failure that is not the expected one: the override must have
# taken, and the build must have got as far as the upload.
if ! grep -qF "Using Central baseUrl: ${dead_url}" "${log}"; then
  echo "::error::central-publishing-maven-plugin did not take -DcentralBaseUrl=${dead_url}"
  tail -n 40 "${log}"
  exit 1
fi
if ! grep -qF "Going to upload" "${log}"; then
  echo "::error::the ${artifact} build failed before the bundle was built"
  tail -n 40 "${log}"
  exit 1
fi

zip="${dir}/target/central-publishing/central-bundle.zip"
if [ ! -f "${zip}" ]; then
  echo "::error::no bundle at ${zip}"
  exit 1
fi

entries="$(unzip -Z1 "${zip}" | grep -v '/$' || true)"
outside="$(printf '%s\n' "${entries}" | awk -v p="${prefix}" 'index($0, p) != 1')"
status=0
if [ -n "${outside}" ]; then
  echo "::error::the ${artifact} bundle has content outside ${prefix}, which Central rejects"
  printf '%s\n' "${outside}"
  status=1
fi
# A here-string, not a pipe: under pipefail an early-exiting `grep -q` can
# SIGPIPE the writer, and the pipeline then fails whether or not it matched.
if ! grep -qxF "${prefix}${artifact}-${version}.pom" <<< "${entries}"; then
  echo "::error::the ${artifact} bundle has no ${prefix}${artifact}-${version}.pom"
  status=1
fi
[ "${status}" -eq 0 ] || exit 1

echo "OK: ${group}:${artifact}:${version} bundle holds $(wc -l <<< "${entries}" | tr -d ' ') files, all under ${prefix}."
