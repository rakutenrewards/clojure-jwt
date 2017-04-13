(ns curbside.jwt-test
  (:require [clojure.test :refer :all]
            [clj-time.core :as t]
            [curbside.jwt :refer :all]
            [curbside.jwt.keys :as keys]
            [clojure.spec.test :as stest]
            [curbside.jwt.spec :as spec]
            [clojure.spec.gen :as g]
            ;clojure.test.check is unused, but if it's not included,
            ;stest/check throws an incomprehensible exception.
            [clojure.test.check :as tc]
            [clojure.java.io :as io])
  (:import
   (com.nimbusds.jose JOSEException)
   (java.io IOException)))

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
  (let [verify (fn [] (sign-unsign std-claims std-claims))]
    (is (map? (verify))) "Expecting the claims we used as input succeeds."))

(deftest unpexpected-signature
  (let [signed (sign-claims std-claims)
        wrong-key (first (keys/rsa-jwks {:key-len 2048 :uuid? true}))
        unsign (fn [] (unsign-jwt {:signing-alg :rs256 :serialized-jwt signed
                                   :unsigning-key wrong-key
                                   :expected-claims std-claims}))]
    (is (thrown-with-msg? Exception #"Signature not valid" (unsign)))))

(deftest test-nbf
  (testing "Validation of nbf (not before) claim"
    (let [nbf-claims (assoc std-claims :nbf (t/plus (t/now) (t/weeks 5)))
          verify (fn [] (sign-unsign nbf-claims std-claims))]
      (is (thrown-with-msg? Exception #"not valid yet" (verify))
          "current time before nbf -> failure"))
    (let [nbf-claims (assoc std-claims :nbf (t/minus (t/now) (t/weeks 1)))
          verify (fn [] (sign-unsign nbf-claims std-claims))]
      (is (map? (verify)) "nbf in the past is okay"))))

(deftest test-exp
  (testing "Validation rejects expired JWTs"
    (let [exp-claims (assoc std-claims :exp (t/minus (t/now) (t/weeks 1)))
          verify (fn [] (sign-unsign exp-claims std-claims))]
      (is (thrown-with-msg? Exception #"JWT expired" (verify)))))
  (testing "Validation accepts JWTs that have not expired"
    (let [exp-claims (assoc std-claims :exp (t/plus (t/now) (t/weeks 1)))
          verify (fn [] (sign-unsign exp-claims std-claims))]
      (is (map? (verify))))))

(deftest test-iss
  (let [iss-claims (assoc std-claims :iss "sephora.com")
        verify (fn [] (sign-unsign iss-claims std-claims))]
    (is (thrown-with-msg? Exception #"'iss' field doesn't match" (verify))
        "wrong iss rejected.")))

(deftest test-sub
  (let [sub-claims (assoc std-claims :sub "foo")
        verify (fn [] (sign-unsign sub-claims std-claims))]
    (is (thrown-with-msg? Exception #"'sub' field doesn't match" (verify))
        "wrong sub rejected")))

(deftest test-aud
  (let [aud-claims (assoc std-claims :aud ["sephora.com"])
        verify-bad (fn [] (sign-unsign aud-claims std-claims))
        bigger-aud (assoc std-claims :aud ["curbside.com" "sephora.com"])
        verify-good (fn [] (sign-unsign bigger-aud std-claims))]
    (is (thrown-with-msg? Exception #"'aud' field doesn't match" (verify-bad))
        "wrong aud rejected")
    (is (map? (verify-good)) "aud contains expected aud -> accepted")))

(deftest encrypt-decrypt
  (let [alg :rsa-oaep-256
        enc :a128gcm
        encrypted (encrypt-jwt {:encrypt-alg alg :encrypt-enc enc
                                :claims std-claims :encrypt-key rsa-jwk})
        verify (fn [] (decrypt-jwt {:encrypt-alg alg
                                    :serialized-jwt encrypted
                                    :decrypt-key rsa-jwk
                                    :expected-claims std-claims}))]
    (is (map? (verify)) "encrypt/decrypt succeeds")))

(deftest encrypt-decrypt-dir
  (let [alg :dir
        enc :a128cbc-hs256
        key (keys/symmetric-key {:key-len 256 :alg alg})
        encrypted (encrypt-jwt {:encrypt-alg alg :encrypt-enc enc
                                :claims std-claims :encrypt-key key})
        verified (decrypt-jwt {:encrypt-alg alg :serialized-jwt encrypted
                               :decrypt-key key :expected-claims std-claims})]
    (is (map? verified) "Symmetric encrypt/decrypt succeeds")))

(deftest decrypt-wrong-key
  (let [alg :rsa-oaep-256
        enc :a128gcm
        encrypted (encrypt-jwt {:encrypt-alg alg :encrypt-enc enc
                                :claims std-claims :encrypt-key rsa-jwk})
        wrong-key (first (keys/rsa-jwks {:key-len 2048 :uuid? false}))
        verify (fn [] (decrypt-jwt {:encrypt-alg alg :serialized-jwt encrypted
                                    :decrypt-key wrong-key
                                    :expected-claims std-claims}))]
    (is (thrown? JOSEException (verify)))))

(deftest nested-roundtrip
  (let [encrypt-alg :rsa-oaep-256
        encrypt-enc :a128gcm
        sign-alg :hs256
        sign-key (keys/symmetric-key {:key-len 256 :uuid? false :alg :hs256})
        encoded (sign-encrypt-nested-jwt
                 {:signing-alg sign-alg :encrypt-alg encrypt-alg
                  :encrypt-enc encrypt-enc :claims std-claims
                  :signing-key sign-key :encrypt-key rsa-jwk})
        verify (fn [] (decrypt-unsign-nested-jwt
                       {:signing-alg sign-alg :encrypt-alg encrypt-alg
                        :serialized-jwt encoded :unsigning-key sign-key
                        :decrypt-key rsa-jwk :expected-claims std-claims}))]
    (is (map? (verify)) "nested sign/encrypt followed by decrypt/unsign")))

(deftest jwk->map-roundtrip
  (let [back-to-jwk (keys/map->JWK rsa-jwk)
        jwk-map (keys/JWK->map back-to-jwk)
        back-to-jwk2 (keys/map->JWK jwk-map)
        thumb1 (.computeThumbprint back-to-jwk)
        thumb2 (.computeThumbprint back-to-jwk2)]
    (is (= thumb1 thumb2))))

(deftest jwk-parsing
  (let [jwk-set-json (slurp (io/resource "example-jwk-set.json"))
        jwk-set (keys/parse-jwk-set jwk-set-json)]
    (is (seq? jwk-set))))

(deftest load-jwk-set-file
  (let [jwk-set (keys/load-jwk-set-from-file
                  (.toURI (io/resource "example-jwk-set.json")))]
    (is (seq? jwk-set))))

; the following tests are disabled by default since they hit URLs.

#_(deftest load-jwk-set-url
  (let [jwk-set (keys/load-jwk-set-from-url
                 "https://myapp.auth0.com/.well-known/jwks.json")]
    (is (seq? jwk-set))))

#_(deftest load-jwk-url-size-limit
  (let [jwk-set (fn [] (keys/load-jwk-set-from-url
                         "https://myapp.auth0.com/.well-known/jwks.json"
                         {:size-limit 1}))]
    (is (thrown-with-msg? IOException
                          #"Exceeded configured input limit"
                          (jwk-set)))))

(deftest jwk-private?
  (let [jwk (first (keys/rsa-jwks {:key-len 2048 :uuid? true}))]
    (is (keys/private? jwk))
    (is (not (keys/private? (keys/->public jwk))))))

(deftest test-process-jwt
  (let [nest (fn [claims]
               (sign-encrypt-nested-jwt
                 {:signing-alg :rs256
                  :encrypt-alg :rsa-oaep
                  :encrypt-enc :a256gcm
                  :claims claims
                  :signing-key rsa-jwk
                  :encrypt-key rsa-jwk}))

        process (fn process
                  ([claims]
                   (process claims (constantly true)))
                  ([claims verifier]
                   (process-jwt
                     {:signing-alg :rs256
                      :encrypt-alg :rsa-oaep
                      :encrypt-enc :a256gcm
                      :keys [rsa-jwk]
                      :jwt (nest claims)
                      :verifier verifier})))]

  (testing "by default verifies exp and nbf, if they are present"
    (is (= {:iss "curbside.com" :aud #{"curbside.com"} :sub "jim"}
           (process std-claims)))

    (is (thrown? Exception
                 (process
                   (assoc std-claims
                          :exp (t/minus (t/now) (t/days 7))))))

    (is (thrown? Exception
                 (process
                   (assoc std-claims
                          :nbf (t/plus (t/now) (t/days 7)))))))

  (testing "allows custom claims verification"
    (is (= {:iss "curbside.com" :aud #{"curbside.com"} :sub "jim"}
           (process std-claims
                    (fn [claims-set]
                      (and (= (:iss claims-set) "curbside.com")
                           (contains? (:aud claims-set) "curbside.com"))))))

    (is (thrown? Exception
           (process (assoc std-claims
                           :exp (t/minus (t/now) (t/days 7)))
                    (fn [claims-set]
                      (and (= (:iss claims-set) "curbside.com")
                           (contains? (:aud claims-set) "curbside.com"))))))

    (is (thrown? Exception
                 (process std-claims
                          (fn [claims-set]
                            (and (= (:iss claims-set) "blurbside.com")
                                 (contains? (:aud claims-set) "bopis")))))))


  (testing "rejects unsecured / plain JWTs")
  (testing "rejects downgraded crypto attacks")))

;; property-based tests
(deftest prop-encrypt-jwt
  (is (every? (comp nil? :failure)
              (stest/check `encrypt-jwt
                           {:clojure.spec.test.check/opts {:num-tests 10}}))))
