(ns curbside.jwt.keys
  (:require
   [curbside.jwt.util :as u]
   [cheshire.core :as json]
   [medley.core :refer [map-kv filter-kv]])
  (:import
   (com.nimbusds.jose.jwk JWK JWKSet RSAKey OctetSequenceKey)
   (java.io File)
   (java.net URL)
   (java.security KeyPairGenerator SecureRandom)
   (java.lang Object String)
   (clojure.lang PersistentArrayMap)))

(defprotocol IOpaque
  (reveal [x]
    "Extracts the opacified data."))

(extend-protocol IOpaque
  java.lang.Object
  (reveal [this] this))

(def opaque-str "Opaque object")

(defn opacify
  [x]
  (reify
    IOpaque
    (reveal [this] x)
    Object
    (toString [this] opaque-str)))

(defn JWK->map
  "Convert a JWK Nimbus object to a map, keeping the private data within the
   map opaque to prevent accidental printing."
  [jwk]
  (let [serialize (fn [j] (-> (.toJSONString j)
                              (json/decode true)))]
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

(defn ->json-jwk
  "Converts a map with some opaque fields, such as produced by our key
         generation functions, into a JSON string in JWK format."
  [mp]
  (let [uncensored (map-kv (fn [k v] [k (reveal v)]) mp)]
    (json/encode uncensored)))

(defn map->JWK
  [mp]
  (let [as-json (->json-jwk mp)]
    (JWK/parse as-json)))

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

(defn private?
  "Returns true if the jwk map contains private key information."
  [jwk-map]
  (some #(= opaque-str (.toString %)) (vals jwk-map)))

(defn ->public
  "Extract public JWK map from a JWK map containing private key information.
   Returns nil if the key is symmetric (and thus there is no public key to
   extract)."
  [jwk-map]
  (some-> jwk-map
      (map->JWK)
      (.toPublicJWK)
      (JWK->map)))

(defn parse-jwk-set
  "Parse a JWK set from a JSON string"
  [jstr]
  (-> jstr
      (JWKSet/parse)
      (.getKeys)
      (seq)
      (map JWK->map)))

(defn load-jwk-set-from-file
  "Load a JWK set from a file. Returns a seq of JWK maps, with private data
   censored."
  [path]
  (->> path
       (slurp)
       (JWKSet/parse)
       (.getKeys)
       (seq)
       (map JWK->map)))

(defn load-jwk-set-from-url
  "Load a JWK set from a url. Returns a seq of JWK maps, with private data
   censored. Optionally takes a config map containing any of these keys:

   - :connect-timeout -- timeout to connect, in milliseconds.
   - :read-timeout    -- timeout to read the URL, in milliseconds.
   - :size-limit      -- maximum number of bytes to read.

  If a limit is missing, it will default to unlimited."
  ([url]
   (load-jwk-set-from-url url {}))
  ([url {:keys [connect-timeout read-timeout size-limit]
         :or  {connect-timeout 0 read-timeout 0 size-limit 0}}]
   (-> (if (= URL (type url)) url (URL. url))
       (JWKSet/load connect-timeout read-timeout size-limit)
       (.getKeys)
       (seq)
       (->> (map JWK->map)))))

(defprotocol IJWKSetConversion
  "Implemented for types that can be converted into a jwk-set."
  (jwk-set [x]))

(extend-protocol IJWKSetConversion
  String
    (jwk-set [x] (parse-jwk-set x))

  File
    (jwk-set [x] (load-jwk-set-from-file x))

  URL
    (jwk-set [x] (load-jwk-set-from-url x))

  clojure.lang.IPersistentMap
    (jwk-set [x] [x])

  clojure.lang.IPersistentCollection
    (jwk-set [x] (into [] x)))

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
            alg (.algorithm (if (u/encrypt-alg? alg)
                                (u/mk-encrypt-alg alg)
                                (u/mk-signing-alg alg)))
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
