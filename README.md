# curbside-jwt

Clojure wrapper for [Nimbus JOSE+JWT](https://connect2id.com/products/nimbus-jose-jwt).

## Usage

FIXME

## Releasing to Artifactory

1. Retrieve Artifactory credentials from the eng.json bundle in
   https://github.com/Curbside/secrets
2. Set the environment variables ARTIFACTORY_PASS and ARTIFACTORY_USER.
3. Make sure that pgp-agent has your password cached so that you can sign stuff without being prompted.
4. Make sure you are on the master branch, its remote branch is set to the primary repo (https://github.com/Curbside/curbside-jwt/), and your local branch is up to date.
5. Run `lein release :patch`. Replace `:patch` with `:minor` or `:major` as needed. This determines which of the version numbers will be changed in `project.clj` (the version number format is MAJOR.MINOR.PATCH).

## License

Copyright © 2017 Curbside
