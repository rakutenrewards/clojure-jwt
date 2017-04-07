(ns curbside.jwt
  (:require
   [clj-time.coerce :as time-coerce]
   [clj-time.core :as time-core]
   [clojure.string :as str]
   [cheshire.core :as json]
   [curbside.jwt.util :as u])
  (:import
   (com.nimbusds.jose JWSHeader Payload JWSObject JWSAlgorithm JWEAlgorithm
                      EncryptionMethod JWEHeader JOSEException JWEObject)
   (com.nimbusds.jose.crypto MACSigner RSASSASigner ECDSASigner
                             MACVerifier RSASSAVerifier ECDSAVerifier
                             RSAEncrypter AESEncrypter DirectEncrypter
                             ECDHEncrypter RSADecrypter AESDecrypter
                             DirectDecrypter ECDHDecrypter)
   (com.nimbusds.jose.jwk JWKSet RSAKey)
   (com.nimbusds.jwt JWTClaimsSet SignedJWT EncryptedJWT)
   (java.io File)
   (java.net URL)
   (java.security KeyPairGenerator)))

(defn load-jwks-from-file
  "Load a seq of JWKs from a file."
  [path]
  (->> path
       (File.)
       (.load JWKSet)
       (.getKeys)
       (seq)))

(defn load-jwks-from-url
  "Load a seq of JWKs from a URL."
  [url]
  (->> url
       (URL.)
       (.load JWKSet)
       (.getKeys)
       (seq)))

(defn key-pairs
  "A lazy interface to java.security.KeyPairGenerator. Takes a map of arguments
  with required keys :instance and :key-len and returns a lazy-seq whose each
  element is a new KeyPair."
  ([{:keys [instance key-len] :as conf}]
   (key-pairs
     conf
     (doto (KeyPairGenerator/getInstance instance)
       (.initialize key-len))))
  ([conf gen]
   (lazy-seq
     (cons (.generateKeyPair gen) (key-pairs conf gen)))))

(defn rsa-keypair->jwk
  "Create a JWK from an RSA KeyPair."
  [{uuid? :uuid?} key-pair]
  (-> (com.nimbusds.jose.jwk.RSAKey$Builder. (.getPublic key-pair))
      (.privateKey (.getPrivate key-pair))
      ((fn [k] (if uuid? (.keyID k (first (u/uuids))) k)))
      (.build)))

(defn rsa-jwks
  "Generate a lazy sequence of new JWK RSA keypairs. Config can be:
  - :key-len - should be 2048 or larger.
  - :uuid? - if true, assigns a random UUID as the Key ID of each key pair

  See https://en.wikipedia.org/wiki/Key_size#Asymmetric_algorithm_key_lengths
  The returned JWK contains both the private and public keys! Use
  jwk-public-key to extract the public key. Use .toJSONString to get JSON."
  [config]
  (->> (key-pairs {:instance "RSA" :key-len (:key-len config)})
       (map (partial rsa-keypair->jwk config))))

(defn jwk-public-key
  [jwk]
  (.toPublicJWK jwk))

(defn- mk-ec-header
  [alg ec-key-id]
  (let [alg (case alg
               :es256 (com.nimbusds.jose.JWSAlgorithm/ES256)
               :es384 (com.nimbusds.jose.JWSAlgorithm/ES384)
               :es512 (com.nimbusds.jose.JWSAlgorithm/ES512))]
    (.build (.keyID (com.nimbusds.jose.JWSHeader$Builder. alg)))))

(defn map->claims-set
  [claims]
  (let [defClaims {:sub (fn [x y] (.subject x y))
                   :aud (fn [x y] (.audience x y))
                   :exp (fn [x y] (.expirationTime x (time-coerce/to-date y)))
                   :iss (fn [x y] (.issuer x y))
                   :iat (fn [x y] (.issueTime x (time-coerce/to-date y)))
                   :jti (fn [x y] (.jwtID x y))
                   :nbf (fn [x y] (.notBeforeTime x (time-coerce/to-date y)))}
        add-claim (fn [builder k v]
                    (if (contains? defClaims k)
                      ((defClaims k) builder v)
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
            [[:aud string? vector]
             [:exp number? numeric-date->date-time]
             [:nbf number? numeric-date->date-time]
             [:iat number? numeric-date->date-time]])))

(defn- mk-signer
  [alg signing-key]
  (case alg
    (:rs256 :rs384 :rs512)
    (RSASSASigner. signing-key)
    (:hs256 :hs384 :hs512)
    (MACSigner. signing-key)
    (:ec256 :ec384 :ec512)
    (ECDSASigner. (.getS signing-key))))

(defn- mk-sign-header
  ([alg]
   (mk-sign-header alg nil))
  ([alg ec-key-id]
   (case alg
     :rs256 (JWSHeader. (com.nimbusds.jose.JWSAlgorithm/RS256))
     :rs384 (JWSHeader. (com.nimbusds.jose.JWSAlgorithm/RS384))
     :rs512 (JWSHeader. (com.nimbusds.jose.JWSAlgorithm/RS512))

     :hs256 (JWSHeader. (com.nimbusds.jose.JWSAlgorithm/HS256))
     :hs384 (JWSHeader. (com.nimbusds.jose.JWSAlgorithm/HS384))
     :hs512 (JWSHeader. (com.nimbusds.jose.JWSAlgorithm/HS512))

     (:es256 :es384 :es512) (mk-ec-header alg ec-key-id))))

(defn sign-jwt
  ([alg claims signing-key]
   (sign-jwt alg claims signing-key nil))
  ([alg claims signing-key ec-key-id]
   (let [signer (mk-signer alg signing-key)
         header (mk-sign-header alg)
         claims (map->claims-set claims)
         jwt (SignedJWT. header claims)]
     (.sign jwt signer)
     (.serialize jwt))))

;TODO: is there a standard function for this? Or another way to accomplish the
; same with cond?
(defn- implies
  "Material implication."
  [p q]
  (or (not p) q))

(defn verify-standard-claims
  "Verify standard claims contained in a JWT. Returns the claims set as a map if
   verified successfully. Returns a symbol indicating an error otherwise."
  [jwt {:keys [alg iss sub aud] :as expected} curr-time]
  (let [alg-match (fn [alg jwt]
                    (-> jwt
                        (.getHeader)
                        (.getAlgorithm)
                        (.toString)
                        (= (str/upper-case (name alg)))))
        expired? (fn [{:keys [exp]}]
                   (and exp (time-core/after? curr-time exp)))
        too-early? (fn [{:keys [nbf]}]
                     (and nbf (time-core/before? curr-time nbf)))
        claims (claims-set->map (.getJWTClaimsSet jwt))]
    (cond
      (not (alg-match (:alg expected) jwt))
      :alg-mismatch
      (implies iss (not= (:iss claims) iss))
      :iss-mismatch
      (implies iss (not= (:sub claims) sub))
      :sub-mismatch
      (implies aud (not (some #(= % aud) (:aud claims))))
      :aud-mismatch
      (expired? claims)
      :expired
      (too-early? claims)
      :before-nbf

      :else
      claims)))

(defn- mk-verifier
  [alg unsigning-key]
  (case alg
    (:hs256 :hs384 :hs512) (MACVerifier. unsigning-key)
    (:rs256 :rs384 :rs512) (RSASSAVerifier. unsigning-key)
    (:es256 :es384 :es512) (ECDSAVerifier. unsigning-key)))

(defn unsign-jwt
  ([alg jwt unsigning-key expected-claims]
   (unsign-jwt alg jwt unsigning-key expected-claims (time-core/now)))
  ([alg jwt unsigning-key expected-claims curr-time]
   (let [verifier (mk-verifier alg unsigning-key)
         parsed (SignedJWT/parse jwt)]
     (if
       (not (.verify parsed verifier))
       :signature-mismatch
       (verify-standard-claims parsed
                               (assoc expected-claims :alg alg)
                               curr-time)
       ))))

(defn- mk-encrypt-alg
  [alg]
  (case alg
    :rsa1-5 (com.nimbusds.jose.JWEAlgorithm/RSA1_5)
    :rsa-oaep (com.nimbusds.jose.JWEAlgorithm/RSA_OAEP)
    :rsa-oaep-256 (com.nimbusds.jose.JWEAlgorithm/RSA_OAEP_256)
    :a128kw (com.nimbusds.jose.JWEAlgorithm/A128KW)
    :a192kw (com.nimbusds.jose.JWEAlgorithm/A192KW)
    :a256kw (com.nimbusds.jose.JWEAlgorithm/A256KW)
    :dir (com.nimbusds.jose.JWEAlgorithm/DIR)
    :ecdh-es (com.nimbusds.jose.JWEAlgorithm/ECDH_ES)
    :ecdh-es-a128kw (com.nimbusds.jose.JWEAlgorithm/ECDH_ES_A128KW)
    :ecdh-es-a192kw (com.nimbusds.jose.JWEAlgorithm/ECDH_ES_A192KW)
    :ecdh-es-a256kw (com.nimbusds.jose.JWEAlgorithm/ECDH_ES_A256KW)
    :a128gcmkw (com.nimbusds.jose.JWEAlgorithm/A128GCMKW)
    :a192gcmkw (com.nimbusds.jose.JWEAlgorithm/A192GCMKW)
    :a256gcmkw (com.nimbusds.jose.JWEAlgorithm/A256GCMKW)
    ;TODO: password-based encrypter support. Needs extra params.
    ;;:pbes2-hs256-a128kw (com.nimbusds.jose.JWEAlgorithm/PBES2_HS256_A128KW)
    ;;:pbes2-hs384-a192kw (com.nimbusds.jose.JWEAlgorithm/PBES2_HS384_A192KW)
    ;;:pbes2-hs512-a256kw (com.nimbusds.jose.JWEAlgorithm/PBES2_HS512_A256KW)
    ))

(defn- mk-encrypt-enc
  [enc]
  (case enc
    :a128cbc-hs256 (com.nimbusds.jose.EncryptionMethod/A128CBC_HS256)
    :a192cbc-hs384 (com.nimbusds.jose.EncryptionMethod/A192CBC_HS384)
    :a256cbc-hs512 (com.nimbusds.jose.EncryptionMethod/A256CBC_HS512)
    :a128gcm (com.nimbusds.jose.EncryptionMethod/A128GCM)
    :a192gcm (com.nimbusds.jose.EncryptionMethod/A192GCM)
    :a256gcm (com.nimbusds.jose.EncryptionMethod/A256GCM)))

(defn- mk-encrypt-header
  [alg enc]
  (let [alg (mk-encrypt-alg alg)
        enc (mk-encrypt-enc enc)]
    (JWEHeader. alg enc)))

(defn- mk-encrypter
  [alg key]
  (println "###" key)
  (case alg
    (:rsa1-5 :rsa-oaep :rsa-oaep-256)
    (RSAEncrypter. key)
    (:a128kw :a192kw :a256kw :a128gcmkw :a192gcmkw :a256gcmkw)
    (AESEncrypter. key)
    :dir
    (DirectEncrypter. key)
    (:ecdh-es :ecdh-es-a128kw :ecdh-es-a192kw :ecdh-es-a256kw)
    (ECDHEncrypter. key)
    ;TODO password-based encryption.
    ;;(:pbes2-hs256-a128kw :pbes2-hs384-a192kw :pbes2-hs512-a256kw)
    ;;(PasswordBasedEncrypter. key salt-len num-iters)
    ))

(defn encrypt-jwt
  [alg enc claims key]
  (let [encrypter (mk-encrypter alg key)
        claims (map->claims-set claims)
        header (mk-encrypt-header alg enc)
        encrypted-jwt (EncryptedJWT. header claims)
        ; TODO: this encrypter only supports a few of the algs above!
        ; need another case statement
        ]
    ;TODO: for debugging, try serializing before encrypting to see the JSON
    (.encrypt encrypted-jwt encrypter)
    (.serialize encrypted-jwt)))

(defn- mk-decrypter
  [alg key]
  (case alg
    (:rsa1-5 :rsa-oaep :rsa-oaep-256)
    (RSADecrypter. key)
    (:a128kw :a192kw :a256kw :a128gcmkw :a192gcmkw :a256gcmkw)
    (AESDecrypter. key)
    :dir
    (DirectDecrypter. key)
    (:ecdh-es :ecdh-es-a128kw :ecdh-es-a192kw :ecdh-es-a256kw)
    (ECDHDecrypter. key)))

(defn decrypt-jwt
  ([alg jwt key expected-claims]
    (decrypt-jwt alg jwt key expected-claims (time-core/now)))
  ([alg jwt key expected-claims curr-time]
    (let [decrypter (mk-decrypter alg key)
          jwt (EncryptedJWT/parse jwt)
          decrypted (try
                      (.decrypt jwt decrypter)
                      true
                      (catch IllegalStateException e
                        nil)
                      (catch JOSEException e
                        nil))]
      (if decrypted
        (verify-standard-claims jwt
                                (assoc expected-claims :alg alg)
                                curr-time)
        :decryption-failed))))

(defn sign-encrypt-nested-jwt
  "Sign and then encrypt a nested JWT"
  [sign-alg encrypt-alg encrypt-enc claims sign-key encrypt-key]
  ; TODO: there is some duplication here with the sign and encrypt fns above
  (let [signer (mk-signer sign-alg sign-key)
        claims-set (map->claims-set claims)
        sign-header (mk-sign-header sign-alg)
        signed (SignedJWT. sign-header claims-set)
        encrypt-alg-obj (mk-encrypt-alg encrypt-alg)
        encrypt-enc-obj (mk-encrypt-enc encrypt-enc)
        encrypt-header (-> (com.nimbusds.jose.JWEHeader$Builder.
                             encrypt-alg-obj encrypt-enc-obj)
                           (.contentType "JWT")
                           (.build))
        payload (do
                  (.sign signed signer)
                  (Payload. signed))
        encrypter (mk-encrypter encrypt-alg encrypt-key)
        encrypted-jwe (JWEObject. encrypt-header payload)]
    (.encrypt encrypted-jwe encrypter)
    (.serialize encrypted-jwe)))

(defn decrypt-unsign-nested-jwt
  ([unsign-alg decrypt-alg jwe-string unsign-key decrypt-key expected-claims]
   (decrypt-unsign-nested-jwt unsign-alg decrypt-alg jwe-string unsign-key
                              decrypt-key expected-claims (time-core/now)))
  ([unsign-alg decrypt-alg jwe-string unsign-key decrypt-key expected-claims
    curr-time]
   (let [jwe-obj (com.nimbusds.jose.JWEObject/parse jwe-string)
         decrypter (mk-decrypter decrypt-alg decrypt-key)
         signed-jwt (do
                      (.decrypt jwe-obj decrypter)
                      (.toSignedJWT (.getPayload jwe-obj)))
         verifier (mk-verifier unsign-alg unsign-key)]
     (.verify signed-jwt verifier)
     (verify-standard-claims signed-jwt
                             (assoc expected-claims :alg unsign-alg)
                             curr-time))))
