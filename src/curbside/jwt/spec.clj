(ns curbside.jwt.spec
  (:require
   [clojure.spec :as s]
   [curbside.jwt :as jwt]
   [clj-time.core :as t])
  (:import
   (org.joda.time DateTime)))

(s/def ::encrypt-alg #{:rsa1-5 :rsa-oaep :rsa-oaep-256 :a128kw :a192kw :a256kw
                       :dir :ecdh-es :ecdh-es-a128kw :ecdh-es-a192kw
                       :ecdh-es-a256kw :a128gcmkw :a192gcmkw :a256gcmkw})

(s/def ::encrypt-enc #{:a128cbc-hs256 :a192cbc-hs384 :a256cbc-hs512 :a128gcm
                       :a192gcm :a256gcm})

(s/def ::signing-alg #{:rs256 :rs384 :rs512 :hs256 :hs384 :hs512 :es256 :es384
                       :es512})

(s/def ::claims map?)

(s/def ::expected-claims map?)

(s/def ::serialized-jwt string?)

(s/def ::curr-time #(= DateTime (type %)))

(s/def ::encrypt-jwt-config
  (s/keys :req-un [::encrypt-alg ::encrypt-enc ::claims]))

(s/def ::decrypt-jwt-config
  (s/keys :req-un [::encrypt-alg ::serialized-jwt ::expected-claims]
          :opt-un [::curr-time]))

(s/def ::sign-jwt-config
  (s/and (s/keys :req-un [::signing-alg ::claims])
         (fn [config]
           (or (not (some #(= % (:signing-alg config))
                          [:es256 :es384 :es512]))
               (contains? :ec-key-id)))))

(s/def ::unsign-jwt-config
  (s/keys :req-un [::signing-alg ::serialized-jwt ::expected-claims]
          :opt-un [::curr-time]))

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
