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
            [clojure.test.check :as tc])
  (:import
   (com.nimbusds.jose JOSEException)
   (com.nimbusds.jose.proc BadJWEException)))

;; enforce spec on these functions when running unit tests
(stest/instrument `encrypt-jwt)
(stest/instrument `decrypt-jwt)
(stest/instrument `sign-jwt)
(stest/instrument `unsign-jwt)
(stest/instrument `nest-jwt)
(stest/instrument `unnest-jwt)

(def rsa-jwk (first (keys/rsa-jwks {:key-len 2048 :uuid? false})))

(def std-claims {:iss "curbside.com" :aud #{"curbside.com"} :sub "jim"})

(defn sign-claims
  "Sign with RSA-256 and the standard test key. For claims validation tests."
  [claims]
  (sign-jwt {:signing-alg :rs256 :claims claims :signing-key rsa-jwk}))

(defn unsign-claims
  "Unsign with RSA-256 and the standard test key. For claims validation tests."
  [jwt claims verifier]
  (unsign-jwt {:signing-alg :rs256 :serialized-jwt jwt
               :unsigning-key rsa-jwk
               :verifier verifier}))

(defn sign-unsign
  [claims exp-claims verifier]
  (unsign-claims (sign-claims claims) exp-claims verifier))

(deftest test-sign-rsa
  (let [verify (fn [] (sign-unsign std-claims std-claims nil))]
    (is (map? (verify))) "Expecting the claims we used as input succeeds."))

(deftest unexpected-signature
  (let [signed (sign-claims std-claims)
        wrong-key (first (keys/rsa-jwks {:key-len 2048 :uuid? true}))
        unsign (fn [] (unsign-jwt {:signing-alg :rs256 :serialized-jwt signed
                                   :unsigning-key wrong-key
                                   :expected-claims std-claims}))]
    (is (thrown-with-msg? Exception #"Invalid signature" (unsign)))))

(deftest encrypt-decrypt
  (let [alg :rsa-oaep-256
        enc :a128gcm
        encrypted (encrypt-jwt {:encrypt-alg alg :encrypt-enc enc
                                :claims std-claims :encrypt-key rsa-jwk})
        verify (fn [] (decrypt-jwt {:encrypt-alg alg
                                    :encrypt-enc enc
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
        verified (decrypt-jwt {:encrypt-alg alg :encrypt-enc enc
                               :serialized-jwt encrypted
                               :decrypt-key key :expected-claims std-claims})]
    (is (map? verified) "Symmetric encrypt/decrypt succeeds")))

(deftest decrypt-wrong-key
  (let [alg :rsa-oaep-256
        enc :a128gcm
        encrypted (encrypt-jwt {:encrypt-alg alg :encrypt-enc enc
                                :claims std-claims :encrypt-key rsa-jwk})
        wrong-key (first (keys/rsa-jwks {:key-len 2048 :uuid? false}))
        verify (fn [] (decrypt-jwt {:encrypt-alg alg :encrypt-enc enc
                                    :serialized-jwt encrypted
                                    :decrypt-key wrong-key
                                    :expected-claims std-claims}))]
    (is (thrown? BadJWEException (verify)))))

(deftest nested-roundtrip
  (let [encrypt-alg :rsa-oaep-256
        encrypt-enc :a128gcm
        sign-alg :hs256
        sign-key (keys/symmetric-key {:key-len 256 :uuid? false :alg :hs256})
        encoded (nest-jwt
                 {:signing-alg sign-alg :encrypt-alg encrypt-alg
                  :encrypt-enc encrypt-enc :claims std-claims
                  :signing-key sign-key :encrypt-key rsa-jwk})
        verify (fn [] (unnest-jwt
                       {:signing-alg sign-alg :encrypt-alg encrypt-alg
                        :serialized-jwt encoded :unsigning-key sign-key
                        :decrypt-key rsa-jwk :encrypt-enc encrypt-enc}))]
    (is (map? (verify)) "nested sign/encrypt followed by decrypt/unsign")))

(deftest jwk->map-roundtrip
  (let [back-to-jwk (keys/map->JWK rsa-jwk)
        jwk-map (keys/JWK->map back-to-jwk)
        back-to-jwk2 (keys/map->JWK jwk-map)
        thumb1 (.computeThumbprint back-to-jwk)
        thumb2 (.computeThumbprint back-to-jwk2)]
    (is (= thumb1 thumb2))))

(deftest test-process-jwt
  (let [nest (fn [claims]
               (nest-jwt
                 {:signing-alg :rs256
                  :encrypt-alg :rsa-oaep
                  :encrypt-enc :a256gcm
                  :claims claims
                  :signing-key rsa-jwk
                  :encrypt-key rsa-jwk}))

        process (fn process
                  ([jwt]
                   (process jwt (constantly true)))
                  ([jwt verifier]
                   (process-jwt
                     {:signing-alg :rs256
                      :encrypt-alg :rsa-oaep
                      :encrypt-enc :a256gcm
                      :keys [rsa-jwk]
                      :jwt jwt
                      :verifier verifier})))]

  (testing "by default verifies exp and nbf, if they are present"
    (is (= {:iss "curbside.com" :aud #{"curbside.com"} :sub "jim"}
           (process (nest std-claims))))

    (is (thrown? Exception
                 (process
                   (nest
                     (assoc std-claims
                            :exp (t/minus (t/now) (t/days 7)))))))

    (is (thrown? Exception
                 (process
                   (nest
                     (assoc std-claims
                            :nbf (t/plus (t/now) (t/days 7))))))))

  (testing "allows custom claims verification"
    (is (= {:iss "curbside.com" :aud #{"curbside.com"} :sub "jim"}
           (process (nest std-claims)
                    (fn [claims-set]
                      (and (= (:iss claims-set) "curbside.com")
                           (contains? (:aud claims-set) "curbside.com"))))))

    (is (thrown? Exception
                 (process (nest (assoc std-claims
                                       :exp (t/minus (t/now) (t/days 7))))
                          (fn [claims-set]
                            (and (= (:iss claims-set) "curbside.com")
                                 (contains? (:aud claims-set) "curbside.com"))))))

    (is (thrown? Exception
                 (process (nest std-claims)
                          (fn [claims-set]
                            (and (= (:iss claims-set) "blurbside.com")
                                 (contains? (:aud claims-set) "bopis")))))))


  (testing "accepts signed JWTs"
    (is (= {:iss "curbside.com" :aud #{"curbside.com"} :sub "jim"}
           (process-jwt
             {:signing-alg :rs256
              :keys [rsa-jwk]
              :jwt (sign-jwt
                     {:signing-alg :rs256
                      :claims std-claims
                      :signing-key rsa-jwk})}))))

  (testing "accepts encrypted JWTs"
    (is (= {:iss "curbside.com" :aud #{"curbside.com"} :sub "jim"}
           (process-jwt
             {:encrypt-alg :rsa-oaep
              :encrypt-enc :a256gcm
              :keys [rsa-jwk]
              :jwt (encrypt-jwt
                    {:encrypt-alg :rsa-oaep
                     :encrypt-enc :a256gcm
                     :claims std-claims
                     :encrypt-key rsa-jwk})}))))

  (testing "rejects unsecured / plain JWTs")
  (testing "rejects downgraded crypto attacks")))

;; property-based tests
(deftest prop-encrypt-jwt
  (is (every? (comp nil? :failure)
              (stest/check `encrypt-jwt
                           {:clojure.spec.test.check/opts {:num-tests 10}}))))
