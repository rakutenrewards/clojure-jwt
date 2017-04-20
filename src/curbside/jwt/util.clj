(ns curbside.jwt.util
  (:require [medley.core :refer [filter-kv]])
  (:import
   (java.util UUID)
   (com.nimbusds.jose JWSHeader Payload JWSObject JWSAlgorithm JWEAlgorithm
                      EncryptionMethod JWEHeader JOSEException JWEObject
                      CompressionAlgorithm)
   (com.nimbusds.jose.crypto MACSigner RSASSASigner ECDSASigner
                             MACVerifier RSASSAVerifier ECDSAVerifier
                             RSAEncrypter AESEncrypter DirectEncrypter
                             ECDHEncrypter RSADecrypter AESDecrypter
                             DirectDecrypter ECDHDecrypter)
   (com.nimbusds.jose.jwk JWK JWKSet RSAKey)
   (com.nimbusds.jwt JWTClaimsSet SignedJWT EncryptedJWT)
   (java.util Base64)
   (java.net URI)
   (com.nimbusds.jose.util Base64URL)
   (com.nimbusds.jose.util.Base64)))

(def alg-info
  {:dir {:type :encrypt
         :alg-field "dir"
         :mk-obj com.nimbusds.jose.JWEAlgorithm/DIR}
   :rsa1-5 {:type :encrypt
            :alg-field "RSA1_5"
            :mk-obj com.nimbusds.jose.JWEAlgorithm/RSA1_5}
   :rsa-oaep {:type :encrypt
              :alg-field "RSA-OAEP"
              :mk-obj com.nimbusds.jose.JWEAlgorithm/RSA_OAEP}
   :rsa-oaep-256 {:type :encrypt
                  :alg-field "RSA-OAEP-256"
                  :mk-obj com.nimbusds.jose.JWEAlgorithm/RSA_OAEP_256}
   :a128kw {:type :encrypt
            :alg-field "A128KW"
            :mk-obj com.nimbusds.jose.JWEAlgorithm/A128KW}
   :a192kw {:type :encrypt
            :alg-field "A192KW"
            :mk-obj com.nimbusds.jose.JWEAlgorithm/A192KW}
   :a256kw {:type :encrypt
            :alg-field "A256KW"
            :mk-obj com.nimbusds.jose.JWEAlgorithm/A256KW}
   :ecdh-es {:type :encrypt
             :alg-field "ECDH-ES"
             :mk-obj com.nimbusds.jose.JWEAlgorithm/ECDH_ES}
   :ecdh-es-a128kw {:type :encrypt
                    :alg-field "ECDH-ES+A128KW"
                    :mk-obj
                    com.nimbusds.jose.JWEAlgorithm/ECDH_ES_A128KW}
   :ecdh-es-a192kw {:type :encrypt
                    :alg-field "ECDH-ES+A192KW"
                    :mk-obj
                    com.nimbusds.jose.JWEAlgorithm/ECDH_ES_A192KW}
   :ecdh-es-a256kw {:type :encrypt
                    :alg-field "ECDH-ES+A256KW"
                    :mk-obj
                    com.nimbusds.jose.JWEAlgorithm/ECDH_ES_A256KW}
   :pbes2-hs256 {:type :encrypt
                 :alg-field "PBES2-HS256+A128KW"}
   :pbes2-hs384 {:type :encrypt
                 :alg-field "PBES2-HS384+A192KW"}
   :pbes2-hs512 {:type :encrypt
                 :alg-field "PBES2-HS512+A256KW"}
   :hs256 {:type :signing
           :alg-field "HS256"
           :mk-obj com.nimbusds.jose.JWSAlgorithm/HS256}
   :hs384 {:type :signing
           :alg-field "HS384"
           :mk-obj com.nimbusds.jose.JWSAlgorithm/HS384}
   :hs512 {:type :signing
           :alg-field "HS512"
           :mk-obj com.nimbusds.jose.JWSAlgorithm/HS512}
   :es256 {:type :signing
           :alg-field "ES256"
           :mk-obj com.nimbusds.jose.JWSAlgorithm/ES256}
   :es384 {:type :signing
           :alg-field "ES384"
           :mk-obj com.nimbusds.jose.JWSAlgorithm/ES384}
   :es512 {:type :signing
           :alg-field "ES512"
           :mk-obj com.nimbusds.jose.JWSAlgorithm/ES512}
   :ps256 {:type :signing
           :alg-field "PS256"
           :mk-obj com.nimbusds.jose.JWSAlgorithm/PS256}
   :ps384 {:type :signing
           :alg-field "PS384"
           :mk-obj com.nimbusds.jose.JWSAlgorithm/PS384}
   :ps512 {:type :signing
           :alg-field "PS512"
           :mk-obj com.nimbusds.jose.JWSAlgorithm/PS512}
   :rs256 {:type :signing
           :alg-field "RS256"
           :mk-obj com.nimbusds.jose.JWSAlgorithm/RS256}
   :rs384 {:type :signing
           :alg-field "RS384"
           :mk-obj com.nimbusds.jose.JWSAlgorithm/RS384}
   :rs512 {:type :signing
           :alg-field "RS512"
           :mk-obj com.nimbusds.jose.JWSAlgorithm/RS512}
   :a128cbc-hs256 {:type :encoding
                   :alg-field "A128CBC-HS256"
                   :mk-obj
                   com.nimbusds.jose.EncryptionMethod/A128CBC_HS256}
   :a192cbc-hs384 {:type :encoding
                   :alg-field "A192CBC-HS384"
                   :mk-obj
                   com.nimbusds.jose.EncryptionMethod/A192CBC_HS384}
   :a256cbc-hs512 {:type :encoding
                   :alg-field "A256CBC-HS512"
                   :mk-obj
                   com.nimbusds.jose.EncryptionMethod/A256CBC_HS512}
   :a128gcm {:type :encoding
             :alg-field "A128GCM"
             :mk-obj com.nimbusds.jose.EncryptionMethod/A128GCM}
   :a192gcm {:type :encoding
             :alg-field "A192GCM"
             :mk-obj com.nimbusds.jose.EncryptionMethod/A192GCM}
   :a256gcm {:type :encoding
             :alg-field "A256GCM"
             :mk-obj com.nimbusds.jose.EncryptionMethod/A256GCM}})

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

(defn mk-alg-obj
  [alg]
  (get-in alg-info [alg :mk-obj]))

(defn mk-encrypt-alg
  [encrypt-alg]
  (mk-alg-obj encrypt-alg))

(defn mk-signing-alg
  [signing-alg]
  (mk-alg-obj signing-alg))

(defn mk-encrypt-enc
  [enc]
  (mk-alg-obj enc))

(defn encrypt-alg?
  [alg]
  (contains? encrypt-algs alg))

(defn signing-alg?
  [alg]
  (contains? signing-algs alg))

(defn- not-impl!
  [expl]
  (throw (ex-info "Functionality not implemented." {:explanation expl})))

(def header-builder-fields
  {:apu (fn [obj v] (.agreementPartyUInfo obj (Base64URL. v)))
   :apv (fn [obj v] (.agreementPartyVInfo obj (Base64URL. v)))
   :tag (fn [obj v] (.authTag obj (Base64URL. v)))
   :zip (fn [obj v] (.compressionAlgorithm obj (CompressionAlgorithm. v)))
   :cty (fn [obj v] (.contentType obj v))
   :epk (fn [obj v] (.ephemeralPublicKey obj (not-impl! "epk header param")))
   :iv (fn [obj v] (.iv obj (Base64URL. v)))
   :jku (fn [obj v] (.jwkURL obj (URI. v)))
   :kid (fn [obj v] (.keyID obj v))
   :p2c (fn [obj v] (.pbes2Count obj v))
   :p2s (fn [obj v] (.pbes2Salt obj (Base64URL. v)))
   :typ (fn [obj v] (.type obj (not-impl! ":typ header param")))
   :x5c (fn [obj v] (.x509CertChain obj
                      (map #(com.nimbusds.jose.util.Base64. %) v)))
   :x5t#S256 (fn [obj v] (.x509CertSHA256Thumbprint obj (Base64URL. v)))
   :x5t (fn [obj v] (.x509CertURL obj (URI. v)))
   :jwk (fn [obj v] (.jwk obj v))})

(defn map->builder-w-defaults
  [builder-constructor build-fn custom-field-fn field-defaults fields]
  (let [stringify-if-keyword (fn [x] (if (keyword? x)
                                         (name x)
                                         x))
        add-field (fn [builder k v]
                    (if (contains? field-defaults k)
                      ((field-defaults k) builder v)
                      (custom-field-fn builder
                                       (name k)
                                       (stringify-if-keyword v))))]
    (build-fn (reduce-kv add-field (builder-constructor) fields))))

(defn mk-encrypt-header
  ([encrypt-alg encrypt-enc]
   (mk-encrypt-header encrypt-alg encrypt-enc {}))
  ([encrypt-alg encrypt-enc addl-header-fields]
   (let [alg-obj (mk-encrypt-alg encrypt-alg)
         enc-obj (mk-encrypt-enc encrypt-enc)]
     (map->builder-w-defaults
       #(com.nimbusds.jose.JWEHeader$Builder. alg-obj enc-obj)
       #(.build %)
       #(.customParam %1 %2 %3)
       header-builder-fields
       addl-header-fields))))

(defn mk-ec-header
  [signing-alg-obj ec-key-id]
  (-> signing-alg-obj
      (com.nimbusds.jose.JWSHeader$Builder.)
      (.keyID)
      (.build)))

(defn mk-sign-header
  ([signing-alg]
    (mk-sign-header signing-alg {}))
  ([signing-alg addl-header-fields]
    (let [signing-alg-obj (mk-signing-alg signing-alg)]
      (map->builder-w-defaults
       #(com.nimbusds.jose.JWSHeader$Builder. signing-alg-obj)
       #(.build %)
       #(.customParam %1 %2 %3)
       header-builder-fields
       addl-header-fields))))

(defn base64decode
  [s]
  (as-> s $
       (.decode (Base64/getUrlDecoder) $)
       (String. $ "UTF-8")))
