(ns curbside.jwt.spec
  (:require
   [clojure.spec :as s]
   [clojure.spec.gen :as g]
   [curbside.jwt :as jwt]
   [curbside.jwt.keys :as keys]
   [curbside.jwt.util :as u]
   [clj-time.core :as t])
  (:import
   (org.joda.time DateTime)
   (com.nimbusds.jose.jwk RSAKey JWK)))

(s/def ::encrypt-alg #{:rsa1-5 :rsa-oaep :rsa-oaep-256 :a128kw :a192kw :a256kw
                       :dir :ecdh-es :ecdh-es-a128kw :ecdh-es-a192kw
                       :ecdh-es-a256kw :a128gcmkw :a192gcmkw :a256gcmkw})

(s/def ::encrypt-enc #{:a128cbc-hs256 :a192cbc-hs384 :a256cbc-hs512 :a128gcm
                       :a192gcm :a256gcm})

(s/def ::signing-alg #{:rs256 :rs384 :rs512 :hs256 :hs384 :hs512 :es256 :es384
                       :es512})

; TODO: https://github.com/Curbside/curbside-jwt/issues/27
(def encs-for-alg
  (let [all-encs u/encoding-algs]
    {:rsa1-5 #{:a128gcm}
     :rsa-oaep all-encs
     :rsa-oaep-256 all-encs
     :dir all-encs}))

(defn alg-supports-enc?
  [{:keys [encrypt-alg encrypt-enc]}]
  (contains? (encrypt-alg encs-for-alg) encrypt-enc))

(s/def ::claims map?)

(s/def ::expected-claims map?)

(s/def ::serialized-jwt string?)

(s/def ::curr-time #(= DateTime (type %)))

(def key-spec map?)

(s/def ::signing-key key-spec)

(s/def ::encrypt-key key-spec)

(s/def ::decrypt-key key-spec)

(s/def ::verifier #(or (fn? %) (nil? %)))

(s/def ::addl-header-fields map?)

(s/def ::addl-enc-header-fields map?)

(s/def ::addl-sign-header-fields map?)

(defn gen-encrypt-key
  [encrypt-alg]
  ;TODO: implement non-rsa test cases!
  (case encrypt-alg
    (:rsa1-5 :rsa-oaep :rsa-oaep-256)
    (g/return (first (keys/rsa-jwks {:key-len 2048 :uuid? true})))
    (:a128kw :a192kw :a256kw :a128gcmkw :a192gcmkw :a256gcmkw)
    (throw (ex-info "AES keygen not yet implemented." {:alg encrypt-alg}))
    :dir
    (g/bind
      (g/return 128) ;TODO: other key lengths. See issue #32
      (fn [key-len]
        (g/return (keys/symmetric-key {:key-len key-len :alg encrypt-alg}))))
    (:ecdh-es :ecdh-es-a128kw :ecdh-es-a192kw :ecdh-es-a256kw)
    (throw (ex-info "ECDH keygen not yet implemented." {:alg encrypt-alg}))))

(defn gen-encrypt-jwt-config
  []
  ;TODO: generate non-rsa test cases!
  (g/bind (s/gen #{:rsa1-5 :rsa-oaep :rsa-oaep-256 :dir})
    (fn [encrypt-alg]
      (g/hash-map :encrypt-alg (g/return encrypt-alg)
                  :encrypt-enc (s/gen #{:a128gcm}) ;see issue #32
                  :claims (g/return {:iss "foo" :aud "foo"})
                  :encrypt-key (gen-encrypt-key encrypt-alg)))))

(s/def ::encrypt-jwt-config
  (s/with-gen
    (s/and (s/keys :req-un [::encrypt-alg ::encrypt-enc ::claims ::encrypt-key]
                   :opt-un [::addl-header-fields])
           alg-supports-enc?)
    gen-encrypt-jwt-config))

(s/def ::decrypt-jwt-config
  (s/keys :req-un [::encrypt-alg ::encrypt-enc ::serialized-jwt
                   ::decrypt-key]
          :opt-un [::verifier]))

(s/def ::sign-jwt-config
  (s/and (s/keys :req-un [::signing-alg ::claims ::signing-key]
                 :opt-un [::addl-header-fields])
         (fn [config]
           (or (not (some #(= % (:signing-alg config))
                          [:es256 :es384 :es512]))
               (contains? :ec-key-id)))))

(s/def ::unsign-jwt-config
  (s/keys :req-un [::signing-alg ::serialized-jwt ::unsigning-key]
          :opt-un [::verifier]))

(s/def ::nest-jwt-config
  (s/keys :req-un [::signing-alg ::encrypt-alg ::encrypt-enc ::claims
                   ::signing-key ::encrypt-key]
          :opt-un [::addl-sign-header-fields ::addl-enc-header-fields]))

(s/def ::unnest-jwt-config
  (s/keys :req-un [::signing-alg ::encrypt-alg ::serialized-jwt ::unsigning-key
                   ::decrypt-key ::encrypt-enc]
          :opt-un [::verifier]))

(s/fdef jwt/encrypt-jwt
        :args (s/cat :config ::encrypt-jwt-config)
        :ret string?)

(s/fdef jwt/decrypt-jwt
        :args (s/cat :config ::decrypt-jwt-config)
        :ret map?)

(s/fdef jwt/sign-jwt
        :args (s/cat :config ::sign-jwt-config)
        :ret string?)

(s/fdef jwt/unsign-jwt
        :args (s/cat :config ::unsign-jwt-config)
        :ret map?)

(s/fdef jwt/nest-jwt
        :args (s/cat :config ::nest-jwt-config)
        :ret string?)

(s/fdef jwt/unnest-jwt
        :args (s/cat :config ::unnest-jwt-config)
        :ret map?)
