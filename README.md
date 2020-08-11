# curbside-jwt

Clojure wrapper for [Nimbus JOSE+JWT](https://connect2id.com/products/nimbus-jose-jwt).

## Usage

FIXME

## Releasing to Artifactory

1. Export `GITHUB_ACTOR` and `GITHUB_TOKEN` env variables. You can generate a personal `GITHUB_TOKEN` with the `write:packages` permission.
2. Make sure you are on the master branch, its remote branch is set to the primary repo (https://github.com/Curbside/curbside-jwt/), and your local branch is up to date.
3. Run `lein release :patch`. Replace `:patch` with `:minor` or `:major` as needed. This determines which of the version numbers will be changed in `project.clj` (the version number format is MAJOR.MINOR.PATCH).

## License

Copyright © 2020 Curbside
