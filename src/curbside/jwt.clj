(ns curbside.jwt
  (:require
   [clojure.string :as str]
   [clojure.walk :refer [keywordize-keys]])
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
   (java.security KeyPairGenerator SecureRandom)
   (java.util UUID)
   (java.lang System)))

(defn load-jwks-from-file
  "Load a seq of JWKs from a file."
  [path]
  (->> path
       (new File)
       (.load JWKSet)
       (.getKeys)
       (seq)))

(defn load-jwks-from-url
  "Load a seq of JWKs from a URL."
  [url]
  (->> url
       (new URL)
       (.load JWKSet)
       (.getKeys)
       (seq)))

(defn gen-rsa-jwk
  "Generate a new JWK RSA keypair. key-len arg should be 2048 or larger.
   If uuid is true, assigns a UUID to the keypair.
   See https://en.wikipedia.org/wiki/Key_size#Asymmetric_algorithm_key_lengths
   The returned JWK contains both the private and public keys! Use
   jwk-public-key to extract the public key. Use .toJSONString to get JSON."
  [key-len uuid?]
  (let [key-pair-gen (KeyPairGenerator/getInstance "RSA")
        key-pair (do (.initialize key-pair-gen key-len)
                     (.generateKeyPair key-pair-gen))]
    (-> (new com.nimbusds.jose.jwk.RSAKey$Builder (.getPublic key-pair))
        (.privateKey (.getPrivate key-pair))
        ((fn [k] (if uuid? (.keyID k (.toString (UUID/randomUUID))) k)))
        (.build))))

(defn jwk-public-key
  [jwk]
  (.toPublicJWK jwk))

(defn- mk-ec-header
  [alg ec-key-id]
  (let [alg (case alg
               :es256 (com.nimbusds.jose.JWSAlgorithm/ES256)
               :es384 (com.nimbusds.jose.JWSAlgorithm/ES384)
               :es512 (com.nimbusds.jose.JWSAlgorithm/ES512))]
    (.build (.keyID (new com.nimbusds.jose.JWSHeader$Builder alg)))))

(defn map->claims-set
  [claims]
  (let [defClaims {:sub (fn [x y] (.subject x y))
                   :aud (fn [x y] (.audience x y))
                   :exp (fn [x y] (.expirationTime x y))
                   :iss (fn [x y] (.issuer x y))
                   :iat (fn [x y] (.issueTime x y))
                   :jti (fn [x y] (.jwtID x y))
                   :nbf (fn [x y] (.notBeforeTime x y))}
        add-claim (fn [builder k v]
                    (if (contains? defClaims k)
                      ((defClaims k) builder v)
                      (.claim builder (name k) v)))]
    (.build
     (reduce-kv add-claim (new com.nimbusds.jwt.JWTClaimsSet$Builder) claims))))

(defn claims-set->map
  [claims-set]
  (->> claims-set
       (.getClaims)
       (into {})
       (keywordize-keys)
       (map (fn [[k v]] [k (if (= (type v) java.util.ArrayList)
                               (into [] v)
                               v)]))
       (into {})))

(defn- mk-signer
  [alg signing-key]
  (case alg
    (:rs256 :rs384 :rs512)
    (new RSASSASigner signing-key)
    (:hs256 :hs384 :hs512)
    (new MACSigner signing-key)
    (:ec256 :ec384 :ec512)
    (new ECDSASigner (.getS signing-key))))

(defn- mk-sign-header
  ([alg]
   (mk-sign-header alg nil))
  ([alg ec-key-id]
   (case alg
     :rs256 (new JWSHeader (com.nimbusds.jose.JWSAlgorithm/RS256))
     :rs384 (new JWSHeader (com.nimbusds.jose.JWSAlgorithm/RS384))
     :rs512 (new JWSHeader (com.nimbusds.jose.JWSAlgorithm/RS512))

     :hs256 (new JWSHeader (com.nimbusds.jose.JWSAlgorithm/HS256))
     :hs384 (new JWSHeader (com.nimbusds.jose.JWSAlgorithm/HS384))
     :hs512 (new JWSHeader (com.nimbusds.jose.JWSAlgorithm/HS512))

     (:es256 :es384 :es512) (mk-ec-header alg ec-key-id))))

(defn sign-jwt
  ([alg claims signing-key]
   (sign-jwt alg claims signing-key nil))
  ([alg claims signing-key ec-key-id]
   (let [signer (mk-signer alg signing-key)
         header (mk-sign-header alg)
         claims (map->claims-set claims)
         jwt (new SignedJWT header claims)]
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
                   (and exp (.after curr-time exp)))
        too-early? (fn [{:keys [nbf]}]
                     (and nbf (.before curr-time nbf)))
        claims (claims-set->map (.getJWTClaimsSet jwt))
        _ (println claims)]
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
    (:hs256 :hs384 :hs512) (new MACVerifier unsigning-key)
    (:rs256 :rs384 :rs512) (new RSASSAVerifier unsigning-key)
    (:es256 :es384 :es512) (new ECDSAVerifier unsigning-key)))

(defn unsign-jwt
  ([alg jwt unsigning-key expected-claims]
   (unsign-jwt alg jwt unsigning-key expected-claims (new java.util.Date)))
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
    (new JWEHeader alg enc)))

(defn- mk-encrypter
  [alg key]
  (println "###" key)
  (case alg
    (:rsa1-5 :rsa-oaep :rsa-oaep-256)
    (new RSAEncrypter key)
    (:a128kw :a192kw :a256kw :a128gcmkw :a192gcmkw :a256gcmkw)
    (new AESEncrypter key)
    :dir
    (new DirectEncrypter key)
    (:ecdh-es :ecdh-es-a128kw :ecdh-es-a192kw :ecdh-es-a256kw)
    (new ECDHEncrypter key)
    ;TODO password-based encryption.
    ;;(:pbes2-hs256-a128kw :pbes2-hs384-a192kw :pbes2-hs512-a256kw)
    ;;(new PasswordBasedEncrypter key salt-len num-iters)
    ))

(defn encrypt-jwt
  [alg enc claims key]
  (let [encrypter (mk-encrypter alg key)
        claims (map->claims-set claims)
        header (mk-encrypt-header alg enc)
        encrypted-jwt (new EncryptedJWT header claims)
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
    (new RSADecrypter key)
    (:a128kw :a192kw :a256kw :a128gcmkw :a192gcmkw :a256gcmkw)
    (new AESDecrypter key)
    :dir
    (new DirectDecrypter key)
    (:ecdh-es :ecdh-es-a128kw :ecdh-es-a192kw :ecdh-es-a256kw)
    (new ECDHDecrypter key)))

(defn decrypt-jwt
  ([alg jwt key expected-claims]
    (decrypt-jwt alg jwt key expected-claims (new java.util.Date)))
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
        signed (new SignedJWT sign-header claims-set)
        encrypt-alg-obj (mk-encrypt-alg encrypt-alg)
        encrypt-enc-obj (mk-encrypt-enc encrypt-enc)
        encrypt-header (-> (new com.nimbusds.jose.JWEHeader$Builder
                             encrypt-alg-obj encrypt-enc-obj)
                           (.contentType "JWT")
                           (.build))
        payload (do
                  (.sign signed signer)
                  (new Payload signed))
        encrypter (mk-encrypter encrypt-alg encrypt-key)
        encrypted-jwe (new JWEObject encrypt-header payload)]
    (.encrypt encrypted-jwe encrypter)
    (.serialize encrypted-jwe)))

(defn decrypt-unsign-nested-jwt
  ([unsign-alg decrypt-alg jwe-string unsign-key decrypt-key expected-claims]
   (decrypt-unsign-nested-jwt unsign-alg decrypt-alg jwe-string unsign-key
                              decrypt-key expected-claims (new java.util.Date)))
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
