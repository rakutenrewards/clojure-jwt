(ns curbside.jwt
  (:require
   [clj-time.coerce :as time-coerce]
   [clj-time.core :as time-core]
   [clojure.string :as str]
   [cheshire.core :as json]
   [curbside.jwt.keys :as k]
   [curbside.jwt.util :as u]
   [clojure.tools.trace :as trace])
  (:import
   (com.nimbusds.jose JWSHeader Payload JWSObject JWSAlgorithm JWEAlgorithm
                      EncryptionMethod JWEHeader JOSEException JWEObject)
   (com.nimbusds.jose.crypto MACSigner RSASSASigner ECDSASigner
                             MACVerifier RSASSAVerifier ECDSAVerifier
                             RSAEncrypter AESEncrypter DirectEncrypter
                             ECDHEncrypter RSADecrypter AESDecrypter
                             DirectDecrypter ECDHDecrypter)
   (com.nimbusds.jose.jwk JWK JWKSet RSAKey)
   (com.nimbusds.jose.jwk.source ImmutableJWKSet)
   (com.nimbusds.jwt JWTClaimsSet SignedJWT EncryptedJWT)
   (com.nimbusds.jose.proc JWSVerificationKeySelector JWEDecryptionKeySelector)
   (com.nimbusds.jwt.proc DefaultJWTProcessor DefaultJWTClaimsVerifier)))

(defn- map->claims-set
  [claims]
  (let [def-claims {:sub (fn [x y] (.subject x y))
                    :aud (fn [x y] (if (string? y)
                                     (.audience x y)
                                     (.audience x (vec y))))
                    :exp (fn [x y] (.expirationTime x (time-coerce/to-date y)))
                    :iss (fn [x y] (.issuer x y))
                    :iat (fn [x y] (.issueTime x (time-coerce/to-date y)))
                    :jti (fn [x y] (.jwtID x y))
                    :nbf (fn [x y] (.notBeforeTime x (time-coerce/to-date y)))}
        add-claim (fn [builder k v]
                    (if (contains? def-claims k)
                      ((def-claims k) builder v)
                      (.claim builder (name k) v)))]
    (.build
     (reduce-kv add-claim (com.nimbusds.jwt.JWTClaimsSet$Builder.) claims))))

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
    (:ec256 :ec384 :ec512)
    (ECDSASigner. (.getS (k/map->JWK signing-key)))))


(defn sign-jwt
  [{:keys [signing-alg claims signing-key ec-key-id]}]
  (let [signer (mk-signer signing-alg signing-key)
        header (u/mk-sign-header signing-alg ec-key-id)
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
  [{:keys [encrypt-alg encrypt-enc claims encrypt-key] :as config}]
  (let [encrypter (mk-encrypter encrypt-alg encrypt-key)
        claims-set (map->claims-set claims)
        header (u/mk-encrypt-header encrypt-alg encrypt-enc)
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
            (when-not (verifier (claims-set->map claims))
              (throw (Exception. "Verification failed"))))))

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
  [{:keys [encrypt-alg encrypt-enc serialized-jwt decrypt-key verifier]}]
  (process-jwt {:encrypt-alg encrypt-alg :encrypt-enc encrypt-enc
                :jwt serialized-jwt :keys [decrypt-key] :verifier verifier}))

(defn unsign-jwt
  [{:keys [signing-alg serialized-jwt unsigning-key verifier]}]
  (process-jwt {:signing-alg signing-alg :jwt serialized-jwt
                :keys [unsigning-key] :verifier verifier}))

(defn nest-jwt
  "Sign and then encrypt a nested JWT"
  [{:keys [signing-alg encrypt-alg encrypt-enc claims signing-key encrypt-key]}]
  (let [signer (mk-signer signing-alg signing-key)
        claims-set (map->claims-set claims)
        sign-header (u/mk-sign-header signing-alg)
        signed (doto (SignedJWT. sign-header claims-set)
                     (.sign signer))
        encrypt-alg-obj (u/mk-encrypt-alg encrypt-alg)
        encrypt-enc-obj (u/mk-encrypt-enc encrypt-enc)
        encrypt-header (-> (com.nimbusds.jose.JWEHeader$Builder.
                            encrypt-alg-obj encrypt-enc-obj)
                           (.contentType "JWT")
                           (.build))
        payload (Payload. signed)
        encrypter (mk-encrypter encrypt-alg encrypt-key)
        encrypted-jwe (doto (JWEObject. encrypt-header payload)
                            (.encrypt encrypter))]
    (.serialize encrypted-jwe)))

(defn unnest-jwt
  [{:keys [signing-alg encrypt-alg encrypt-enc serialized-jwt unsigning-key
           decrypt-key verifier]}]
  (process-jwt {:signing-alg signing-alg :encrypt-alg encrypt-alg
                :jwt serialized-jwt :keys [unsigning-key decrypt-key]
                :verifier verifier :encrypt-enc encrypt-enc}))
