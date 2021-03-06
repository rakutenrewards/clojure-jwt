(ns curbside.jwt
  "High-level tools for encoding and decoding JWTs, while ensuring that their
   claims are verified. Wraps the Nimbus JOSE + JWT library.
   Note: this library supports both keywords and strings in the Clojure
   representation of claims, but prefers keywords. All keyword keys and values
   in an input claim map are converted to strings before passing to Nimbus."
  (:require
   [clj-time.coerce :as time-coerce]
   [clj-time.core :as time-core]
   [clojure.string :as str]
   [clojure.walk :as walk]
   [cheshire.core :as json]
   [curbside.jwt.keys :as k]
   [curbside.jwt.util :as u])
  (:import
   (com.nimbusds.jose JWSHeader Payload JWSObject JWSAlgorithm JWEAlgorithm
                      EncryptionMethod JWEHeader JOSEException JWEObject
                      CompressionAlgorithm)
   (com.nimbusds.jose.crypto MACSigner RSASSASigner ECDSASigner
                             MACVerifier RSASSAVerifier ECDSAVerifier
                             RSAEncrypter AESEncrypter DirectEncrypter
                             ECDHEncrypter RSADecrypter AESDecrypter
                             DirectDecrypter ECDHDecrypter)
   (com.nimbusds.jose.jwk JWK JWKSet RSAKey)
   (com.nimbusds.jose.jwk.source ImmutableJWKSet)
   (com.nimbusds.jwt JWTClaimsSet SignedJWT EncryptedJWT)
   (com.nimbusds.jose.proc JWSVerificationKeySelector JWEDecryptionKeySelector)
   (com.nimbusds.jwt.proc DefaultJWTProcessor DefaultJWTClaimsVerifier)
   (com.fasterxml.jackson.core JsonParseException)
   (com.nimbusds.jose.util Base64URL)
   (java.net URI)))

(defn unsafe-parse-serialized
  "Parses a serialized JWT into its constituent parts between the dots, base64
   decodes them, and returns them as strings or maps depending on whether they
   can be understood without being decrypted, like the parser on jwt.io.
   Performs NO validation! You probably don't need this function."
  [jwt]
  (let [parts (str/split jwt #"\.")
        parse-json-or-nil (fn [x] (try
                                    (json/decode x true)
                                    (catch JsonParseException _ nil)))
        parse-or-const (fn [x] (if-let [parsed (parse-json-or-nil x)]
                                 parsed
                                 x))]
    (map (comp parse-or-const u/base64decode) parts)))

(defn- map->claims-set
  "Converts a Clojure map into a set of claims. Recursively converts all
   keyword keys and values in the map into strings first. This ensures that
   users can pass in either strings or keywords without problems. Otherwise,
   keywords retain the colon at the beginning."
  [claims]
  (let [def-claims {:sub (fn [x y] (.subject x y))
                    :aud (fn [x y] (if (string? y)
                                     (.audience x y)
                                     (.audience x (vec y))))
                    :exp (fn [x y] (.expirationTime x (time-coerce/to-date y)))
                    :iss (fn [x y] (.issuer x y))
                    :iat (fn [x y] (.issueTime x (time-coerce/to-date y)))
                    :jti (fn [x y] (.jwtID x y))
                    :nbf (fn [x y] (.notBeforeTime x (time-coerce/to-date y)))}]
    (u/map->builder-w-defaults
      #(com.nimbusds.jwt.JWTClaimsSet$Builder.)
      #(.build %)
      #(.claim %1 %2 %3)
      def-claims
      claims)))

(defn- numeric-date->date-time
  "JWT uses NumericDate, which is seconds since the epoch. clj-time, however,
  works in milliseconds, so to convert from a NumericDate into a Joda timestamp
  we must first multiply by 1000."
  [s]
  (time-coerce/to-date-time (* s 1000)))

(defn- claims-set->map
  [claims-set]
  (let [claims-map (json/decode (str claims-set) true)]
    (reduce (fn [acc [k pred conv]]
              (if (and (k acc) (pred (k acc)))
                (update acc k conv)
                acc))
            claims-map
            [[:aud string? (comp set vector)]
             [:exp number? numeric-date->date-time]
             [:nbf number? numeric-date->date-time]
             [:iat number? numeric-date->date-time]])))

(defn- mk-signer
  [signing-alg signing-key]
  (case signing-alg
    (:rs256 :rs384 :rs512)
    (RSASSASigner. (k/map->JWK signing-key))
    (:hs256 :hs384 :hs512)
    (MACSigner. (k/map->JWK signing-key))
    (:es256 :es384 :es512)
    (ECDSASigner. (.toECPrivateKey (k/map->JWK signing-key)))))

(def header-builder-fields
  {:apu (fn [obj v] (.agreementPartyUInfo obj (Base64URL. v)))
   :apv (fn [obj v] (.agreementPartyVInfo obj (Base64URL. v)))
   :tag (fn [obj v] (.authTag obj (Base64URL. v)))
   :zip (fn [obj v] (.compressionAlgorithm obj (CompressionAlgorithm. v)))
   :cty (fn [obj v] (.contentType obj v))
   :epk (fn [obj v] (.ephemeralPublicKey obj (u/not-impl! "epk header param")))
   :iv (fn [obj v] (.iv obj (Base64URL. v)))
   :jku (fn [obj v] (.jwkURL obj (URI. v)))
   :kid (fn [obj v] (.keyID obj v))
   :p2c (fn [obj v] (.pbes2Count obj v))
   :p2s (fn [obj v] (.pbes2Salt obj (Base64URL. v)))
   :typ (fn [obj v] (.type obj (u/not-impl! ":typ header param")))
   :x5c (fn [obj v] (.x509CertChain obj
                                    (map #(com.nimbusds.jose.util.Base64. %) v)))
   :x5t#S256 (fn [obj v] (.x509CertSHA256Thumbprint obj (Base64URL. v)))
   :x5t (fn [obj v] (.x509CertURL obj (URI. v)))
   :jwk (fn [obj v] (.jwk obj v))})

(defn mk-encrypt-header
  ([encrypt-alg encrypt-enc]
   (mk-encrypt-header encrypt-alg encrypt-enc {}))
  ([encrypt-alg encrypt-enc addl-header-fields]
   (let [alg-obj (u/mk-encrypt-alg encrypt-alg)
         enc-obj (u/mk-encrypt-enc encrypt-enc)]
     (u/map->builder-w-defaults
       #(com.nimbusds.jose.JWEHeader$Builder. alg-obj enc-obj)
       #(.build %)
       #(.customParam %1 %2 %3)
       header-builder-fields
       addl-header-fields))))

(defn mk-sign-header
  ([signing-alg]
   (mk-sign-header signing-alg {}))
  ([signing-alg addl-header-fields]
   (let [signing-alg-obj (u/mk-signing-alg signing-alg)]
     (u/map->builder-w-defaults
      #(com.nimbusds.jose.JWSHeader$Builder. signing-alg-obj)
      #(.build %)
      #(.customParam %1 %2 %3)
      header-builder-fields
      addl-header-fields))))

(defn sign-jwt
  [{:keys [signing-alg claims signing-key addl-header-fields]}]
  (let [signer (mk-signer signing-alg signing-key)
        header (mk-sign-header signing-alg addl-header-fields)
        claims-set (map->claims-set claims)
        signed-jwt (doto (SignedJWT. header claims-set)
                         (.sign signer))]
    (.serialize signed-jwt)))

(defn- mk-verifier
  [signing-alg unsigning-key]
  (case signing-alg
    (:hs256 :hs384 :hs512) (MACVerifier. (k/map->JWK unsigning-key))
    (:rs256 :rs384 :rs512) (RSASSAVerifier. (k/map->JWK unsigning-key))
    (:es256 :es384 :es512) (ECDSAVerifier. (k/map->JWK unsigning-key))))

(defn- mk-encrypter
  [encrypt-alg key]
  (case encrypt-alg
    (:rsa1-5 :rsa-oaep :rsa-oaep-256)
    (RSAEncrypter. (k/map->JWK key))
    (:a128kw :a192kw :a256kw :a128gcmkw :a192gcmkw :a256gcmkw)
    (AESEncrypter. (k/map->JWK key))
    :dir
    (DirectEncrypter. (k/map->JWK key))
    (:ecdh-es :ecdh-es-a128kw :ecdh-es-a192kw :ecdh-es-a256kw)
    (ECDHEncrypter. (k/map->JWK key))
    ;TODO password-based encryption.
    ;;(:pbes2-hs256-a128kw :pbes2-hs384-a192kw :pbes2-hs512-a256kw)
    ;;(PasswordBasedEncrypter. (k/map->JWK key) salt-len num-iters)
    ))

(defn encrypt-jwt
  [{:keys [encrypt-alg encrypt-enc claims encrypt-key addl-header-fields]
    :as config}]
  (let [encrypter (mk-encrypter encrypt-alg encrypt-key)
        claims-set (map->claims-set claims)
        header (mk-encrypt-header encrypt-alg encrypt-enc addl-header-fields)
        encrypted-jwt (doto (EncryptedJWT. header claims-set)
                            (.encrypt encrypter))]
    (.serialize encrypted-jwt)))

(defn- mk-decrypter
  [encrypt-alg key]
  (case encrypt-alg
    (:rsa1-5 :rsa-oaep :rsa-oaep-256)
    (RSADecrypter. (k/map->JWK key))
    (:a128kw :a192kw :a256kw :a128gcmkw :a192gcmkw :a256gcmkw)
    (AESDecrypter. (k/map->JWK key))
    :dir
    (DirectDecrypter. (k/map->JWK key))
    (:ecdh-es :ecdh-es-a128kw :ecdh-es-a192kw :ecdh-es-a256kw)
    (ECDHDecrypter. (k/map->JWK key))))

(defn expected-claims->verifier
  "Builds a verifier that checks that each claim in expected-claims is set
   accordingly in the actual claims. Any additional claims that are present in
   the JWT are not checked."
  [expected-claims]
  (fn [actual-claims]
    (every? (fn [k] (= (k expected-claims) (k actual-claims)))
            (keys expected-claims))))

(defn- make-verifier [verifier]
  (proxy [DefaultJWTClaimsVerifier] []
    (verify [claims]
            (proxy-super verify claims)
            (let [result (verifier (claims-set->map claims))]
              (when (not (:verified? result))
                (throw (ex-info "Verification failed" (:details result))))))))

(defn process-jwt
  [{:keys [signing-alg encrypt-alg encrypt-enc jwt keys verifier]}]
  (let [jwk-set (JWKSet. (map k/map->JWK keys))
        key-source (ImmutableJWKSet. jwk-set)
        processor (DefaultJWTProcessor.)]
    (when signing-alg
      (.setJWSKeySelector processor
                          (JWSVerificationKeySelector.
                           (u/mk-signing-alg signing-alg)
                           key-source)))
    (when (and encrypt-alg encrypt-enc)
      (.setJWEKeySelector processor
                          (JWEDecryptionKeySelector.
                           (u/mk-encrypt-alg encrypt-alg)
                           (u/mk-encrypt-enc encrypt-enc)
                           key-source)))
    (when verifier
      (.setJWTClaimsVerifier processor (make-verifier verifier)))
    (claims-set->map (.process processor jwt nil))))

(defn decrypt-jwt
  "Decrypts a JWE. verifier is an optional function that takes a map of claims
   and returns a map with keys:
   - :verified? -- true iff the claims can be verified
   - :details  -- a map of any error details you wish to include in an exception
                  when verification fails."
  [{:keys [encrypt-alg encrypt-enc serialized-jwt decrypt-keys verifier]}]
  (process-jwt {:encrypt-alg encrypt-alg :encrypt-enc encrypt-enc
                :jwt serialized-jwt :keys decrypt-keys :verifier verifier}))

(defn unsign-jwt
  "Verifies the signature of a JWS. See the docs for decrypt-jwt for details
   on the optional verifier param."
  [{:keys [signing-alg serialized-jwt unsigning-keys verifier]}]
  (process-jwt {:signing-alg signing-alg :jwt serialized-jwt
                :keys unsigning-keys :verifier verifier}))

(defn nest-jwt
  "Sign and then encrypt a nested JWT"
  [{:keys [signing-alg encrypt-alg encrypt-enc claims signing-key encrypt-key
           addl-enc-header-fields addl-sign-header-fields]}]
  (let [signer (mk-signer signing-alg signing-key)
        claims-set (map->claims-set claims)
        sign-header (mk-sign-header signing-alg addl-sign-header-fields)
        signed (doto (SignedJWT. sign-header claims-set)
                     (.sign signer))
        encrypt-alg-obj (u/mk-encrypt-alg encrypt-alg)
        encrypt-enc-obj (u/mk-encrypt-enc encrypt-enc)
        encrypt-header (mk-encrypt-header encrypt-alg encrypt-enc
                         (assoc addl-enc-header-fields :cty "JWT"))
        payload (Payload. signed)
        encrypter (mk-encrypter encrypt-alg encrypt-key)
        encrypted-jwe (doto (JWEObject. encrypt-header payload)
                            (.encrypt encrypter))]
    (.serialize encrypted-jwe)))

(defn unnest-jwt
  "Decrypt and then verify the signature of a nested JWT."
  [{:keys [signing-alg encrypt-alg encrypt-enc serialized-jwt
           unsigning-keys decrypt-keys verifier]}]
  (process-jwt {:signing-alg signing-alg :encrypt-alg encrypt-alg
                :jwt serialized-jwt
                :keys (concat unsigning-keys decrypt-keys)
                :verifier verifier :encrypt-enc encrypt-enc}))

(defn debug-unnest-jwt
  "decrypt a nested JWT and return the signed payload WITHOUT verifying the
   signature. This is INSECURE and for debugging only. The result of this
   function can be examined by calling .toString followed by
   unsafe-parse-serialized on it. You can also use debug-unsign-nested-jwt on
   the result to perform the second step of unnest."
  [{:keys [encrypt-alg encrypt-enc serialized-jwt decrypt-key]}]
  (let [decrypter (mk-decrypter encrypt-alg decrypt-key)
        decrypted-jwe (doto (com.nimbusds.jose.JWEObject/parse serialized-jwt)
                            (.decrypt decrypter))]
    (.getPayload decrypted-jwe)))

(defn debug-unsign-nested-jwt
  "attempts to verify the signature of the payload of a nested JWT after it has
   been decrypted by debug-unnest-jwt. Returns true if the signature is verified
   and false otherwise."
  [{:keys [payload unsigning-key signing-alg]}]
  (let [verifier (mk-verifier signing-alg unsigning-key)
        signed-jwt (.toSignedJWT payload)]
    (.verify signed-jwt verifier)))
