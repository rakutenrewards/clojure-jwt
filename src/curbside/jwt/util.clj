(ns curbside.jwt.util
  (:require [medley.core :refer [filter-kv]])
  (:import
   (java.util UUID)
   (com.nimbusds.jose JWSHeader Payload JWSObject JWSAlgorithm JWEAlgorithm
                      EncryptionMethod JWEHeader JOSEException JWEObject)
   (com.nimbusds.jose.crypto MACSigner RSASSASigner ECDSASigner
                             MACVerifier RSASSAVerifier ECDSAVerifier
                             RSAEncrypter AESEncrypter DirectEncrypter
                             ECDHEncrypter RSADecrypter AESDecrypter
                             DirectDecrypter ECDHDecrypter)
   (com.nimbusds.jose.jwk JWK JWKSet RSAKey)
   (com.nimbusds.jwt JWTClaimsSet SignedJWT EncryptedJWT)))

(def alg-info
  {:dir {:type :encrypt
         :alg-field "dir"}
   :rsa1-5 {:type :encrypt
            :alg-field "RSA1_5"}
   :rsa-oaep {:type :encrypt
              :alg-field "RSA-OAEP"}
   :rsa-oaep-256 {:type :encrypt
                  :alg-field "RSA-OAEP-256"}
   :a128kw {:type :encrypt
            :alg-field "A128KW"}
   :a192kw {:type :encrypt
            :alg-field "A192KW"}
   :a256kw {:type :encrypt
            :alg-field "A256KW"}
   :ecdh-es {:type :encrypt
             :alg-field "ECDH-ES"}
   :ecdh-es-a128kw {:type :encrypt
                    :alg-field "ECDH-ES+A128KW"}
   :ecdh-es-a192kw {:type :encrypt
                    :alg-field "ECDH-ES+A192KW"}
   :ecdh-es-a256kw {:type :encrypt
                    :alg-field "ECDH-ES+A256KW"}
   :pbes2-hs256 {:type :encrypt
                 :alg-field "PBES2-HS256+A128KW"}
   :pbes2-hs384 {:type :encrypt
                 :alg-field "PBES2-HS384+A192KW"}
   :pbes2-hs512 {:type :encrypt
                 :alg-field "PBES2-HS512+A256KW"}
   :hs256 {:type :signing
           :alg-field "HS256"}
   :hs384 {:type :signing
           :alg-field "HS384"}
   :hs512 {:type :signing
           :alg-field "HS512"}
   :es256 {:type :signing
           :alg-field "ES256"}
   :es384 {:type :signing
           :alg-field "ES384"}
   :es512 {:type :signing
           :alg-field "ES512"}
   :ps256 {:type :signing
           :alg-field "PS256"}
   :ps384 {:type :signing
           :alg-field "PS384"}
   :ps512 {:type :signing
           :alg-field "PS512"}
   :rs256 {:type :signing
           :alg-field "RS256"}
   :rs384 {:type :signing
           :alg-field "RS384"}
   :rs512 {:type :signing
           :alg-field "RS512"}
   :a128cbc-hs256 {:type :encoding
                   :alg-field "A128CBC-HS256"}
   :a192cbc-hs384 {:type :encoding
                   :alg-field "A192CBC-HS384"}
   :a256cbc-hs512 {:type :encoding
                   :alg-field "A256CBC-HS512"}
   :a128gcm {:type :encoding
             :alg-field "A128GCM"}
   :a192gcm {:type :encoding
             :alg-field "A192GCM"}
   :a256gcm {:type :encoding
             :alg-field "A256GCM"}})

(defn algs-of-type
  [t]
  (into #{} (keys (filter-kv (fn [k v] (= t (:type v))) alg-info))))

(def encoding-algs
  (algs-of-type :encoding))

(def signing-algs
  (algs-of-type :signing))

(def encrypt-algs
  (algs-of-type :encrypt))

(defn alg-field-str
  [alg]
  (get-in alg-info [alg :alg-field]))

(defn uuids
  []
  "Infinite lazy sequence of random UUIDs. This is a function because we don't
   want to retain the head of the list -- no UUID should be used more than
   once."
  (map str (repeatedly #(UUID/randomUUID))))


(defn mk-encrypt-alg
  [encrypt-alg]
  (case encrypt-alg
    :rsa1-5 (com.nimbusds.jose.JWEAlgorithm/RSA1_5)
    :rsa-oaep (com.nimbusds.jose.JWEAlgorithm/RSA_OAEP)
    :rsa-oaep-256 (com.nimbusds.jose.JWEAlgorithm/RSA_OAEP_256)
    :a128kw (com.nimbusds.jose.JWEAlgorithm/A128KW)
    :a192kw (com.nimbusds.jose.JWEAlgorithm/A192KW)
    :a256kw (com.nimbusds.jose.JWEAlgorithm/A256KW)
    :dir (com.nimbusds.jose.JWEAlgorithm/DIR)
    :ecdh-es (com.nimbusds.jose.JWEAlgorithm/ECDH_ES)
    :ecdh-es-a128kw (com.nimbusds.jose.JWEAlgorithm/ECDH_ES_A128KW)
    :ecdh-es-a192kw (com.nimbusds.jose.JWEAlgorithm/ECDH_ES_A192KW)
    :ecdh-es-a256kw (com.nimbusds.jose.JWEAlgorithm/ECDH_ES_A256KW)
    :a128gcmkw (com.nimbusds.jose.JWEAlgorithm/A128GCMKW)
    :a192gcmkw (com.nimbusds.jose.JWEAlgorithm/A192GCMKW)
    :a256gcmkw (com.nimbusds.jose.JWEAlgorithm/A256GCMKW)
    ;TODO: password-based encrypter support. Needs extra params.
    ;;:pbes2-hs256-a128kw (com.nimbusds.jose.JWEAlgorithm/PBES2_HS256_A128KW)
    ;;:pbes2-hs384-a192kw (com.nimbusds.jose.JWEAlgorithm/PBES2_HS384_A192KW)
    ;;:pbes2-hs512-a256kw (com.nimbusds.jose.JWEAlgorithm/PBES2_HS512_A256KW)
))

(defn is-encrypt-alg?
  [alg]
  (contains?
    #{:rsa1-5 :rsa-oaep :rsa-oaep-256 :a128kw :a192kw :a256kw
      :dir :ecdh-es :ecdh-es-a128kw :ecdh-es-a192kw :ecdh-es-a256kw
      :a128gcmkw :a192gcmkw :a256gcmkw :pbes2-hs256-a128kw
      :pbes2-hs384-a192kw :pbes2-hs512-a256kw}
    alg))

(defn is-signing-alg?
  [alg]
  (contains? #{:rs256 :rs384 :rs512 :hs256 :hs384 :hs512 :es256 :es384 :es512}
             alg))

(defn mk-signing-alg
  [signing-alg]
  (case signing-alg
    :rs256 (com.nimbusds.jose.JWSAlgorithm/RS256)
    :rs384 (com.nimbusds.jose.JWSAlgorithm/RS384)
    :rs512 (com.nimbusds.jose.JWSAlgorithm/RS512)

    :hs256 (com.nimbusds.jose.JWSAlgorithm/HS256)
    :hs384 (com.nimbusds.jose.JWSAlgorithm/HS384)
    :hs512 (com.nimbusds.jose.JWSAlgorithm/HS512)
    :es256 (com.nimbusds.jose.JWSAlgorithm/ES256)
    :es384 (com.nimbusds.jose.JWSAlgorithm/ES384)
    :es512 (com.nimbusds.jose.JWSAlgorithm/ES512)))

(defn mk-encrypt-enc
  [encrypt-enc]
  (case encrypt-enc
    :a128cbc-hs256 (com.nimbusds.jose.EncryptionMethod/A128CBC_HS256)
    :a192cbc-hs384 (com.nimbusds.jose.EncryptionMethod/A192CBC_HS384)
    :a256cbc-hs512 (com.nimbusds.jose.EncryptionMethod/A256CBC_HS512)
    :a128gcm (com.nimbusds.jose.EncryptionMethod/A128GCM)
    :a192gcm (com.nimbusds.jose.EncryptionMethod/A192GCM)
    :a256gcm (com.nimbusds.jose.EncryptionMethod/A256GCM)))

(defn mk-encrypt-header
  [encrypt-alg encrypt-enc]
  (let [alg-obj (mk-encrypt-alg encrypt-alg)
        enc-obj (mk-encrypt-enc encrypt-enc)]
    (JWEHeader. alg-obj enc-obj)))

(defn mk-ec-header
  [signing-alg-obj ec-key-id]
  (-> signing-alg-obj
      (com.nimbusds.jose.JWSHeader$Builder.)
      (.keyID)
      (.build)))

(defn mk-sign-header
  ([signing-alg]
   (mk-sign-header signing-alg nil))
  ([signing-alg ec-key-id]
   (let [signing-alg-obj (mk-signing-alg signing-alg)]
     (case signing-alg
       (:es256 :es384 :es512) (mk-ec-header signing-alg-obj ec-key-id)
       (JWSHeader. signing-alg-obj)))))
