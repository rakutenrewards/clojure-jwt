(ns curbside.jwt-test
  (:require [clojure.test :refer :all]
            [clj-time.core :as t]
            [curbside.jwt :refer :all]
            [curbside.jwt.keys :as keys]
            [clojure.spec.test :as stest]
            [curbside.jwt.spec :as spec]))

;; enforce spec on these functions when running unit tests
(stest/instrument `encrypt-jwt)
(stest/instrument `decrypt-jwt)
(stest/instrument `sign-jwt)
(stest/instrument `unsign-jwt)
(stest/instrument `sign-encrypt-nested-jwt)
(stest/instrument `decrypt-unsign-nested-jwt)

(def rsa-jwk (first (keys/rsa-jwks {:key-len 2048 :uuid? false})))

(def std-claims {:iss "curbside.com" :aud "curbside.com" :sub "jim"})

(defn sign-claims
  "Sign with RSA-256 and the standard test key. For claims validation tests."
  [claims]
  (sign-jwt {:signing-alg :rs256 :claims claims :signing-key rsa-jwk}))

(defn unsign-claims
  "Unsign with RSA-256 and the standard test key. For claims validation tests."
  [jwt claims]
  (unsign-jwt {:signing-alg :rs256 :serialized-jwt jwt
               :unsigning-key rsa-jwk :expected-claims claims}))

(defn sign-unsign
  [claims exp-claims]
  (unsign-claims (sign-claims claims) exp-claims))

(deftest test-sign-rsa
  (let [verified (sign-unsign std-claims std-claims)]
    (is (map? verified)) "Expecting the claims we used as input succeeds."))

(deftest test-nbf
  (testing "Validation of nbf (not before) claim"
    (let [nbf-claims (assoc std-claims :nbf (t/plus (t/now) (t/weeks 5)))
          verified (sign-unsign nbf-claims std-claims)]
      (is (= :before-nbf verified) "current time before nbf -> failure"))
    (let [nbf-claims (assoc std-claims :nbf (t/minus (t/now) (t/weeks 1)))
          verified (sign-unsign nbf-claims std-claims)]
      (is (map? verified) "nbf in the past is okay"))))

(deftest test-exp
  (testing "Validation rejects expired JWTs"
    (let [exp-claims (assoc std-claims :exp (t/minus (t/now) (t/weeks 1)))
          verified (sign-unsign exp-claims std-claims)]
      (is (= :expired verified))))
  (testing "Validation accepts JWTs that have not expired"
    (let [exp-claims (assoc std-claims :exp (t/plus (t/now) (t/weeks 1)))
          verified (sign-unsign exp-claims std-claims)]
      (is (map? verified)))))

(deftest test-iss
  (let [iss-claims (assoc std-claims :iss "sephora.com")
        verified (sign-unsign iss-claims std-claims)]
    (is (= :iss-mismatch verified) "wrong iss rejected.")))

(deftest test-sub
  (let [sub-claims (assoc std-claims :sub "foo")
        verified (sign-unsign sub-claims std-claims)]
    (is (= :sub-mismatch verified) "wrong sub rejected")))

(deftest test-aud
  (let [aud-claims (assoc std-claims :aud ["sephora.com"])
        verified (sign-unsign aud-claims std-claims)
        bigger-aud (assoc std-claims :aud ["curbside.com" "sephora.com"])
        verified2 (sign-unsign bigger-aud std-claims)]
    (is (= :aud-mismatch verified) "wrong aud rejected")
    (is (map? verified2) "aud contains expected aud -> accepted")))

(deftest encrypt-decrypt
  (let [alg :rsa-oaep-256
        enc :a128gcm
        encrypted (encrypt-jwt {:encrypt-alg alg :encrypt-enc enc
                                :claims std-claims :encrypt-key rsa-jwk})
        verified (decrypt-jwt {:encrypt-alg alg :serialized-jwt encrypted
                               :decrypt-key rsa-jwk :expected-claims std-claims})]
    (is (map? verified) "encrypt/decrypt succeeds")))

(deftest nested-roundtrip
  (let [encrypt-alg :rsa-oaep-256
        encrypt-enc :a128gcm
        sign-alg :hs256
        sign-key (keys/symmetric-key {:key-len 256 :uuid? false :alg :hs256})
        encoded (sign-encrypt-nested-jwt
                 {:signing-alg sign-alg :encrypt-alg encrypt-alg
                  :encrypt-enc encrypt-enc :claims std-claims
                  :signing-key sign-key :encrypt-key rsa-jwk})
        verified (decrypt-unsign-nested-jwt
                   {:signing-alg sign-alg :encrypt-alg encrypt-alg
                    :serialized-jwt encoded :unsigning-key sign-key
                    :decrypt-key rsa-jwk :expected-claims std-claims})]
    (is (map? verified) "nested sign/encrypt followed by decrypt/unsign")))


;; property-based tests
(deftest prop-encrypt-jwt
  (stest/check `encrypt-jwt))
