(ns curbside-jwt.core
  (:import
   (com.nimbusds.jose JWSHeader Payload JWSObject)
   (com.nimbusds.jose.crypto MACSigner)
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

(defn gen-rsa-jwk
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

(defn hmac-jws
  "Encode an HMAC-signed JWS. algo should be one of :hs256, :hs384, or :hs512.
   payload can be a string, bytes, or one of several Nimbus classes.
   Returns a string."
  [algo payload]
  (let [random (new SecureRandom)
        shared-secret (make-array Byte/TYPE 32)
        signer (do (.nextBytes random shared-secret)
                   (new MACSigner shared-secret))
        algorithm (case algo
                    :hs256 (new JWSHeader (com.nimbusds.jose.JWSAlgorithm/HS256))
                    :hs384 (new JWSHeader (com.nimbusds.jose.JWSAlgorithm/HS384))
                    :hs512 (new JWSHeader (com.nimbusds.jose.JWSAlgorithm/HS512)))
        payload (new Payload payload)
        jwsObject (new JWSObject algorithm payload)]
    (.sign jwsObject signer)
    (.serialize jwsObject)))
