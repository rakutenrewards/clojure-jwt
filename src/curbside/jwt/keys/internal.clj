(ns curbside.jwt.keys.internal
  (:require
   [cheshire.core :as json]
   [curbside.jwt.util :as u]
   [medley.core :refer [map-kv filter-kv]])
  (:import
   (com.nimbusds.jose.jwk JWK)
   (java.security KeyPairGenerator SecureRandom)))


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
