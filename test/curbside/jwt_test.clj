(ns curbside.jwt-test
  (:require [clojure.test :refer :all]
            [clj-time.core :as t]
            [curbside.jwt :refer :all]))

(def rsa-jwk (gen-rsa-jwk 2048 false))

(def std-claims {:iss "curbside.com" :aud "curbside.com" :sub "jim"})

(defn sign-claims
  "Sign with RSA-256 and the standard test key. For claims validation tests."
  [claims]
  (sign-jwt :rs256 claims rsa-jwk))

(defn unsign-claims
  "Unsign with RSA-256 and the standard test key. For claims validation tests."
  [jwt claims]
  (unsign-jwt :rs256 jwt rsa-jwk claims))

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
        encrypted (encrypt-jwt alg enc std-claims rsa-jwk)
        verified (decrypt-jwt alg encrypted rsa-jwk std-claims)]
    (is (map? verified) "encrypt/decrypt succeeds")))

(deftest nested-roundtrip
  (let [encrypt-alg :rsa-oaep-256
        encrypt-enc :a128gcm
        sign-alg :hs256
        sign-key "this is a signing key that is sufficiently long"
        encoded (sign-encrypt-nested-jwt sign-alg encrypt-alg encrypt-enc
                                         std-claims sign-key rsa-jwk)
        verified (decrypt-unsign-nested-jwt sign-alg encrypt-alg encoded
                                            sign-key rsa-jwk std-claims)]
    (is (map? verified) "nested sign/encrypt followed by decrypt/unsign")))
