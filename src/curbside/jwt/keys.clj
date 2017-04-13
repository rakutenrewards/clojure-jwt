(ns curbside.jwt.keys
  (:require
   [curbside.jwt.util :as u]
   [curbside.jwt.keys.internal :as internal]
   [cheshire.core :as json]
   [medley.core :refer [map-kv filter-kv]]
   [curbside.jwt.keys.internal :refer [map->JWK JWK->map]])
  (:import
   (com.nimbusds.jose.jwk JWK JWKSet RSAKey OctetSequenceKey)
   (java.io File)
   (java.net URL)
   (java.security KeyPairGenerator SecureRandom)
   (java.lang.Object)))

(defn private?
  "Returns true if the jwk map contains private key information."
  [jwk-map]
  (some #(= internal/opaque-str (.toString %)) (vals jwk-map)))

(defn get-public
  "Extract public JWK map from a JWK map containing private key information."
  [jwk-map]
  (filter-kv (fn [k v] (not (= internal/opaque-str (.toString v)))) jwk-map))

(def ->json-jwk internal/->json-jwk)

(defn load-jwk-set-from-file
  "Load a JWK set from a file. Returns a seq of JWK maps, with private data
   censored."
  [path]
  (->> path
       (File.)
       (JWKSet/load)
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

(defn rsa-jwks
  "Generate a lazy sequence of new JWK RSA keypairs. Config can be:
  - :key-len - should be 2048 or larger.
  - :uuid? - if true, assigns a random UUID as the Key ID of each key pair

  See https://en.wikipedia.org/wiki/Key_size#Asymmetric_algorithm_key_lengths
  The returned JWK contains both the private and public keys! Use
  jwk-public-key to extract the public key. Use .toJSONString to get JSON."
  [config]
  (->> (internal/key-pairs {:algorithm "RSA" :key-len (:key-len config)})
       (map (partial internal/rsa-keypair->jwk config))))

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
