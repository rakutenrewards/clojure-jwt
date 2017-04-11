(ns curbside.jwt.keys
  (:require
   [curbside.jwt.util :as u]
   [cheshire.core :as json])
  (:import
   (com.nimbusds.jose.jwk JWKSet RSAKey OctetSequenceKey)
   (java.io File)
   (java.net URL)
   (java.security KeyPairGenerator SecureRandom)
   (java.lang.Object)))

(defprotocol IJWK
  "A protocol representing a single JWK, used to sign, unsign, encrypt, or
   decrypt JWTs, depending on the type of key contained in the JWK."
  (get-internal [jwk]
   "Gets the internal Java representation of the key.")
  (to-map [jwk]
    "Returns the JWK as a Clojure map. Use this to get access to keys like
     'kid', 'kty', etc.")
  (private? [jwk]
    "Returns true if the key is or contains a private key.")
  (to-public [jwk]
    "Returns a new JWK containing only non-private information.")
  (to-json [jwk]
    "Converts the JWK to a JSON string."))

(deftype JWK [__internal]
  IJWK
  (get-internal [this]
    __internal)
  (to-map [this]
    (json/decode (to-json this)))
  (private? [this]
    (.isPrivate __internal))
  (to-public [this]
    (.toPublicJWK __internal))
  (to-json [this]
    (.toJSONString __internal))
  Object
  (toString [this]
    (if (private? this) "PrivateJWK" (.toString __internal))))

(defn load-jwks-from-file
  "Load a seq of JWKs from a file."
  [path]
  (->> path
       (File.)
       (.load JWKSet)
       (.getKeys)
       (seq)
       (map ->JWK)))

(defn load-jwks-from-url
  "Load a seq of JWKs from a URL."
  [url]
  (->> url
       (URL.)
       (.load JWKSet)
       (.getKeys)
       (seq)
       (map ->JWK)))

(defn key-pairs
  "A lazy interface to java.security.KeyPairGenerator. Takes a map of arguments
  with required keys :algorithm and :key-len and returns a lazy-seq whose each
  element is a new KeyPair."
  ([{:keys [algorithm key-len] :as conf}]
   (key-pairs
    conf
    (doto (KeyPairGenerator/getInstance algorithm)
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
      (.build)
      (->JWK)))

(defn rsa-jwks
  "Generate a lazy sequence of new JWK RSA keypairs. Config can be:
  - :key-len - should be 2048 or larger.
  - :uuid? - if true, assigns a random UUID as the Key ID of each key pair

  See https://en.wikipedia.org/wiki/Key_size#Asymmetric_algorithm_key_lengths
  The returned JWK contains both the private and public keys! Use
  jwk-public-key to extract the public key. Use .toJSONString to get JSON."
  [config]
  (->> (key-pairs {:algorithm "RSA" :key-len (:key-len config)})
       (map (partial rsa-keypair->jwk config))))

(defn symmetric-key
  [{:keys [key-len uuid? alg]}]
  {:pre [(= 0 (mod key-len 8))]}
  (let [secure-random (SecureRandom.)
        arr (make-array Byte/TYPE (/ key-len 8))]
    (.nextBytes secure-random arr)
    (cond-> (com.nimbusds.jose.jwk.OctetSequenceKey$Builder. arr)
            uuid? (.keyID (first (u/uuids)))
            alg (.algorithm (or (u/mk-signing-alg alg)
                                (u/mk-encrypt-alg alg)))
            true (.build)
            true (->JWK))))

(defn hmac-jwks
  "Generate a lazy sequence of new JWK HMAC secrets. key-len is given in bits."
  [key-len]
  {:pre [(= 0 (mod key-len 8))]}
  (let [secure-random (SecureRandom.)
        gen (fn [] (let [arr (make-array Byte/TYPE (/ key-len 8))]
                     (.nextBytes secure-random arr)
                     (seq arr)))]
    (repeatedly gen)))
