(ns curbside.jwt.keys
  (:require
   [curbside.jwt.util :as u]
   [cheshire.core :as json]
   [clojure.walk :refer [keywordize-keys]]
   [medley.core :refer [map-kv]])
  (:import
   (com.nimbusds.jose.jwk JWK JWKSet RSAKey OctetSequenceKey)
   (java.io File)
   (java.net URL)
   (java.security KeyPairGenerator SecureRandom)
   (java.lang.Object)))

(defprotocol IOpaque
  (reveal [x]
    "Extracts the opacified data."))

(defn opacify
  [x]
  (reify
    IOpaque
    (reveal [this] x)
    Object
    (toString [this] "Opaque object")))

(defn opaque-map->json-jwk
  "Converts a map with some opaque fields, such as produced by our key
   generation functions, into a JSON string in JWK format."
  [mp]
  (let [uncensored (map-kv (fn [k v]
                             (if (satisfies? IOpaque v)
                               [k (reveal v)]
                               [k v]))
                           mp)]
    (json/encode uncensored)))

(defn JWK->map
  "Convert a JWK Nimbus object to a map, keeping the private data within the
   map opaque to prevent accidental printing."
  [jwk]
  (let [serialize (fn [j] (-> (.toJSONString j)
                              (json/decode)
                              (keywordize-keys)))]
    (if (.isPrivate jwk)
      (let [with-private-keys (serialize jwk)
            public-only (or (some-> (.toPublicJWK jwk) (JWK->map)) {})
            public-keys (into #{} (keys public-only))
            private-keys (into #{}
                               (filter (comp not (partial contains? public-keys))
                                       (keys with-private-keys)))]
        (reduce (fn [mp k] (if (contains? private-keys k)
                             (update mp k opacify)
                             mp))
                (serialize jwk)
                private-keys))
      (serialize jwk))))

(defn map->JWK
  [mp]
  (let [as-json (opaque-map->json-jwk mp)]
    (JWK/parse as-json)))

(defn load-jwks-from-file
  "Load a seq of JWKs from a file."
  [path]
  (->> path
       (File.)
       (.load JWKSet)
       (.getKeys)
       (seq)
       (map JWK->map)))

(defn load-jwks-from-url
  "Load a seq of JWKs from a URL."
  [url]
  (->> url
       (URL.)
       (.load JWKSet)
       (.getKeys)
       (seq)
       (map JWK->map)))

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
      (JWK->map)))

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
  [{:keys [key-len uuid? alg random] :or {random (SecureRandom.)}}]
  {:pre [(= 0 (mod key-len 8))]}
  (let [arr (make-array Byte/TYPE (/ key-len 8))]
    (.nextBytes random arr)
    (cond-> (com.nimbusds.jose.jwk.OctetSequenceKey$Builder. arr)
            uuid? (.keyID (first (u/uuids)))
            alg (.algorithm (or (u/mk-signing-alg alg)
                                (u/mk-encrypt-alg alg)))
            true (.build)
            true (JWK->map))))

(defn symmetric-keys
  "Generates a lazy sequence of symmetric keys. Config should contain:
   - :key-len - length of the key to generate. Varies depending on algorithm.
   - :alg - algorithm this will be used with.
   - :uuid? if true, assign a random UUID for the key id of each key.
   - :random (optional) an instance of java.security.SecureRandom for generating
             the keys."
  [conf]
  (repeatedly (fn [] (symmetric-key conf))))
