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
5. Create and push a signed tag corresponding to the release. For example, if
   you just released version 0.5.0, do:
   ```
   git tag -s v0.5.0
   git push upstream v0.5.0
   ```
   Read [this](https://git-scm.com/book/en/v2/Git-Tools-Signing-Your-Work) for
   details.

## License

Copyright © 2017 Curbside
