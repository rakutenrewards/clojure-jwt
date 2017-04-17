# curbside-jwt

Clojure wrapper for [Nimbus JOSE+JWT](https://connect2id.com/products/nimbus-jose-jwt).

## Usage

FIXME

## Releasing to Artifactory

1. Retrieve Artifactory credentials from the ops bundle in
   https://github.com/Curbside/secrets
2. Set the environment variables ARTIFACTORY_PASS and ARTIFACTORY_USER.
3. Update the version of the library in `project.clj`.
4. Run `lein deploy`.
5. Create and push a branch corresponding to the release. For example, if you
   just released version 0.5.0, create a branch `v0.5.0` and push it to the
   upstream repository.

## License

Copyright © 2017 Curbside
