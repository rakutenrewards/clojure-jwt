(ns curbside-jwt.core
  (:require
   [clojure.string :as str])
  (:import
   (com.nimbusds.jose JWSHeader Payload JWSObject JWSAlgorithm)
   (com.nimbusds.jose.crypto MACSigner RSASSASigner ECDSASigner
                             MACVerifier RSASSAVerifier ECDSAVerifier)
   (com.nimbusds.jose.jwk JWKSet RSAKey)
   (com.nimbusds.jwt JWTClaimsSet SignedJWT)
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
  [algo ec-key-id]
  (let [algo (case algo
               :es256 (com.nimbusds.jose.JWSAlgorithm/ES256)
               :es384 (com.nimbusds.jose.JWSAlgorithm/ES384)
               :es512 (com.nimbusds.jose.JWSAlgorithm/ES512))]
    (.build (.keyID (new com.nimbusds.jose.JWSHeader$Builder algo)))))

(defn mk-claims-set
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

(defn sign-jwt
  ([algo claims signing-key]
   (sign-jwt algo claims signing-key nil))
  ([algo claims signing-key ec-key-id]
   (let [signer (case algo
                  (:rs256 :rs384 :rs512)
                  (new RSASSASigner signing-key)
                  (:hs256 :hs384 :hs512)
                  (new MACSigner signing-key)
                  (:ec256 :ec384 :ec512)
                  (new ECDSASigner (.getS signing-key)))
         header (case algo
                  :rs256 (new JWSHeader (com.nimbusds.jose.JWSAlgorithm/RS256))
                  :rs384 (new JWSHeader (com.nimbusds.jose.JWSAlgorithm/RS384))
                  :rs512 (new JWSHeader (com.nimbusds.jose.JWSAlgorithm/RS512))

                  :hs256 (new JWSHeader (com.nimbusds.jose.JWSAlgorithm/HS256))
                  :hs384 (new JWSHeader (com.nimbusds.jose.JWSAlgorithm/HS384))
                  :hs512 (new JWSHeader (com.nimbusds.jose.JWSAlgorithm/HS512))

                  (:es256 :es384 :es512) (mk-ec-header algo ec-key-id))
         claims (mk-claims-set claims)
         jwt (new SignedJWT header claims)]
     (.sign jwt signer)
     (.serialize jwt))))

(defn unsign-jwt
  [algo jwt unsigning-key]
  (let [verifier (case algo
                   (:hs256 :hs384 :hs512) (new MACVerifier unsigning-key)
                   (:rs256 :rs384 :rs512) (new RSASSAVerifier unsigning-key)
                   (:es256 :es384 :es512) (new ECDSAVerifier unsigning-key))
        parsed (SignedJWT/parse jwt)
        header-match (fn [a p]
                       (-> p
                           (.getHeader)
                           (.getAlgorithm)
                           (.toString)
                           (= (str/upper-case (name a)))))
        to-map (fn [x]
                 (->> x
                      (.getJWTClaimsSet)
                      (.getClaims)
                      (into {})))]
    (cond
      (not (.verify parsed verifier))
      :signature-mismatch
      (not (header-match algo parsed))
      :algo-mismatch

      :else
      (to-map parsed))))
