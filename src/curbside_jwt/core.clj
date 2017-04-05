(ns curbside-jwt.core
  (:import
   (com.nimbusds.jose JWSHeader Payload JWSObject JWSAlgorithm)
   (com.nimbusds.jose.crypto MACSigner RSASSASigner ECDSASigner)
   (com.nimbusds.jose.jwk JWKSet RSAKey)
   (java.io File)
   (java.net URL)
   (java.security KeyPairGenerator SecureRandom)
   (java.util UUID)
   (java.lang System)
   ))

(defn java-println
  "Can be used to print a JWK created with gen-rsa-jwk as valid JSON.
   Clojure's println prints #object gibberish."
  [x]
  (.println (System/out) x))

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

(defn gen-rsa-jwkset
  "Generate a new JWK RSA keypair. key-len arg should be 2048 or larger.
   If uuid is true, assigns a UUID to the keypair.
   See https://en.wikipedia.org/wiki/Key_size#Asymmetric_algorithm_key_lengths"
  [key-len uuid?]
  (let [key-pair-gen (KeyPairGenerator/getInstance "RSA")
        key-pair (do (.initialize key-pair-gen key-len)
                     (.generateKeyPair key-pair-gen))]
    (-> (new com.nimbusds.jose.jwk.RSAKey$Builder (.getPublic key-pair))
        (.privateKey (.getPrivate key-pair))
        ((fn [k] (if uuid? (.keyID k (.toString (UUID/randomUUID))) k)))
        (.build))))

; TODO: figure out how to determine which key in a JWKSet is the private key.
(defn jwkset-private-key
  [jwk]
  (->> jwk
      (.getKeys)
      (filter (fn [x] (.isPrivate x)))
      (first)))

(defn- sign-jws
  "Given a JWSHeader, JWSSigner, and payload, serialize a JWS to a string.
   payload can be a string, bytes, or one of several Nimbus classes."
  [header signer payload]
  (let [payload (new Payload payload)
        jwsObject (new JWSObject header payload)]
    (.sign jwsObject signer)
    (.serialize jwsObject)))

(defn- mk-ec-header
  [algo ec-key-id]
  (let [algo (case algo
               :es256 (com.nimbusds.jose.JWSAlgorithm/ES256)
               :es384 (com.nimbusds.jose.JWSAlgorithm/ES384)
               :es512 (com.nimbusds.jose.JWSAlgorithm/ES512))]
    (.build (.keyID (new com.nimbusds.jose.JWSHeader$Builder algo)))))

(defn encode-jws
  ([algo payload signing-key]
   (encode-jws algo payload signing-key nil))
  ([algo payload signing-key ec-key-id]
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

                  (:es256 :es384 :es512) (mk-ec-header algo ec-key-id))]
     (sign-jws header signer payload))))
