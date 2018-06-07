(ns curbside.jwt-test
  (:require [clojure.test :refer :all]
            [clj-time.core :as t]
            [curbside.jwt :refer :all]
            [curbside.jwt.keys :as keys]
            [curbside.jwt.util :as util]
            [clojure.spec.test :as stest]
            [curbside.jwt.spec :as spec]
            [clojure.spec.gen :as g]
            ;clojure.test.check is unused, but if it's not included,
            ;stest/check throws an incomprehensible exception.
            [clojure.test.check :as tc]
            [clojure.java.io :as io]
            [cheshire.core :as json])
  (:import
   (com.nimbusds.jose JOSEException)
   (com.nimbusds.jose.proc BadJWEException)
   (com.nimbusds.jose.proc BadJOSEException)))

;; enforce spec on these functions when running unit tests
(stest/instrument `encrypt-jwt)
(stest/instrument `decrypt-jwt)
(stest/instrument `sign-jwt)
(stest/instrument `unsign-jwt)
(stest/instrument `nest-jwt)
(stest/instrument `unnest-jwt)

(def none-jws
  (let [none-header "{\"alg\":\"none\",\"typ\":\"jwt\"}"
        none-body "{\"loggedInAs\":\"admin\",\"iat\":1422779638}"
        enc #(util/base64encode %)]
    (str (enc none-header) "." (enc none-body) ".")))

(def rsa-jwk (first (keys/rsa-jwks {:key-len 2048 :uuid? false})))

(def ec-jwk (first (keys/ec-jwks {:curve :p256 :uuid? false})))

(def std-claims {:iss "curbside.com" :aud #{"curbside.com"} :sub "jim"})

(defn sign-claims
  "Sign with RSA-256 and the standard test key. For claims validation tests."
  [claims]
  (sign-jwt {:signing-alg :rs256 :claims claims :signing-key rsa-jwk}))

(defn unsign-claims
  "Unsign with RSA-256 and the standard test key. For claims validation tests."
  [jwt claims verifier]
  (unsign-jwt {:signing-alg :rs256 :serialized-jwt jwt
               :unsigning-keys [rsa-jwk]
               :verifier verifier}))

(defn sign-unsign
  [claims exp-claims verifier]
  (unsign-claims (sign-claims claims) exp-claims verifier))

(deftest test-sign-rsa
  (let [verify (fn [] (sign-unsign std-claims std-claims nil))
        verify-fail (fn [] (sign-unsign std-claims std-claims
                                        (constantly {:verified? false
                                                     :details {:bad :bad}})))]
    (is (= std-claims (verify)))
    (try
      (verify-fail)
      (catch Exception e (is (= :bad (:bad (ex-data e))))))))

(deftest test-sign-ec
  (let [signed (sign-jwt {:signing-alg :es256 :claims std-claims
                          :signing-key ec-jwk})
        unsigned (unsign-jwt {:signing-alg :es256 :serialized-jwt signed
                              :unsigning-keys [ec-jwk]})]
    (is (= std-claims unsigned))))


(deftest test-uri-claim-almost-roundtrip
  (let [claims (assoc std-claims "https://curbside.com/loyalty_id" "abc123")
        expected (assoc std-claims :https://curbside.com/loyalty_id "abc123")
        signed (sign-jwt {:signing-alg :es256 :claims claims
                          :signing-key ec-jwk})
        unsigned (unsign-jwt {:signing-alg :es256 :serialized-jwt signed
                              :unsigning-keys [ec-jwk]})]
    (is (= expected unsigned))))

(deftest test-nested-map-claims
  (let [nested-map {:a {:b :c}}
        verify (fn [] (sign-unsign nested-map nested-map nil))
        result (verify)]
    (is (map? result))
    (is (= {:a {:b "c"}} result))))

(deftest unexpected-signature
  (let [signed (sign-claims std-claims)
        wrong-key (first (keys/rsa-jwks {:key-len 2048 :uuid? true}))
        unsign (fn [] (unsign-jwt {:signing-alg :rs256 :serialized-jwt signed
                                   :unsigning-keys [wrong-key]
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
                                    :decrypt-keys [rsa-jwk]
                                    :expected-claims std-claims}))]
    (is (map? (verify)) "encrypt/decrypt succeeds")))

(deftest encrypt-decrypt-ecdh
  (let [alg :ecdh-es-a128kw
        enc :a128gcm
        encrypted (encrypt-jwt {:encrypt-alg alg :encrypt-enc enc
                                :claims std-claims :encrypt-key ec-jwk})
        claims (decrypt-jwt {:encrypt-alg alg :encrypt-enc enc
                             :serialized-jwt encrypted :decrypt-keys[ec-jwk]
                             :expected-claims std-claims})]
    (is (= std-claims claims))))

(deftest encrypt-decrypt-dir
  (let [alg :dir
        enc :a128cbc-hs256
        key (keys/symmetric-key {:key-len 256 :alg alg})
        encrypted (encrypt-jwt {:encrypt-alg alg :encrypt-enc enc
                                :claims std-claims :encrypt-key key})
        verified (decrypt-jwt {:encrypt-alg alg :encrypt-enc enc
                               :serialized-jwt encrypted
                               :decrypt-keys [key] :expected-claims std-claims})]
    (is (map? verified) "Symmetric encrypt/decrypt succeeds")))

(deftest decrypt-wrong-key
  (let [alg :rsa-oaep-256
        enc :a128gcm
        encrypted (encrypt-jwt {:encrypt-alg alg :encrypt-enc enc
                                :claims std-claims :encrypt-key rsa-jwk})
        wrong-key (first (keys/rsa-jwks {:key-len 2048 :uuid? false}))
        verify (fn [] (decrypt-jwt {:encrypt-alg alg :encrypt-enc enc
                                    :serialized-jwt encrypted
                                    :decrypt-keys [wrong-key]
                                    :expected-claims std-claims}))]
    (testing "Decrypting with wrong key throws exception"
      (is (thrown? BadJWEException (verify))))

    (testing "When multiple keys are provided, Nimbus uses correct key"
      (is (decrypt-jwt {:encrypt-alg alg :encrypt-enc enc
                        :serialized-jwt encrypted
                        :decrypt-keys [wrong-key rsa-jwk]
                        :expected-claims std-claims})))))

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
                        :serialized-jwt encoded :unsigning-keys [sign-key]
                        :decrypt-keys [rsa-jwk] :encrypt-enc encrypt-enc}))]
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

(deftest test-jwk-set
  (let [set1 (keys/jwk-set
               (io/as-file (io/resource "example-jwk-set.json")))]
    (is (vector? (keys/jwk-set set1)))
    (is (vector? (keys/jwk-set (first set1))))))

(deftest test-parse-jwk-json
  (let [jwk-set-json (str "{\"keys\" : [" (keys/->json-jwk rsa-jwk) "]}")]
    (is (coll? (keys/parse-jwk-set jwk-set-json)))))

(deftest jwk-private?
  (let [jwk (first (keys/rsa-jwks {:key-len 2048 :uuid? true}))]
    (is (keys/private? jwk))
    (is (not (keys/private? (keys/->public jwk))))))

(deftest test->public
  (let [rsa-jwk (first (keys/rsa-jwks {:key-len 2048}))
        sym-jwk (first (keys/symmetric-keys {:key-len 256 :alg :rs256}))]
    (is (map? (keys/->public rsa-jwk)) "Public RSA key extracted")
    (is (nil? (keys/->public sym-jwk)) "No public key for a symmetric key")))

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
                   (process jwt (constantly {:verified? true})))
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
    (let [verifier (fn [claims-set]
                     {:verified?
                      (and (= (:iss claims-set) "curbside.com")
                           (contains? (:aud claims-set) "curbside.com"))
                      :details "iss and aud didn't both match"})
          bad-verifier (fn [claims-set]
                         {:verified? (and (= (:iss claims-set) "blurbside.com")
                                          (contains? (:aud claims-set) "bopis"))
                          :details {:iss "not blurbside.com"}})]


      (is (= {:iss "curbside.com" :aud #{"curbside.com"} :sub "jim"}
             (process (nest std-claims)
                      verifier)))

      (is (thrown? Exception
                   (process (nest (assoc std-claims
                                         :exp (t/minus (t/now) (t/days 7))))
                            verifier)))

      (is (thrown? Exception
                   (process (nest std-claims)
                            bad-verifier)))))


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

(defn- make-verifier [expected]
  (fn [{:keys [iss aud]}]
    {:verified? (and (= iss (:iss expected))
                     (contains? aud (:aud expected)))}))

(deftest test-nest-unsign-fails
  (let [signing-alg :rs256
        encrypt-alg :rsa-oaep
        encrypt-enc :a256gcm
        claims {:iss "https://auth.curbside.com"
                :aud "https://api.curbside.com"
                :sub "1234"}
        [sign-key enc-key] (take 2 (keys/rsa-jwks {:key-len 2048}))
        nested (nest-jwt {:signing-alg signing-alg
                          :encrypt-alg encrypt-alg
                          :encrypt-enc encrypt-enc
                          :claims claims
                          :signing-key sign-key
                          :encrypt-key enc-key})
        unsign (fn [] (unsign-jwt {:signing-alg signing-alg
                                   :serialized-jwt nested
                                   :unsigning-keys [sign-key]
                                   :verifier (make-verifier
                                              {:iss "https://auth.curbside.com"
                                               :aud "https://api.curbside.com"})}))]
    (is (thrown? BadJOSEException (unsign)))))

(deftest test-unsafe-parse
  (let [claims {:foo "bar"}
        encoded (sign-claims claims)
        [header decoded-claims sig] (unsafe-parse-serialized encoded)]
    (testing "header decoded as map"
      (is (map? header)))
    (testing "claims decoded"
      (is (= decoded-claims claims)))
    (testing "parsing raw data of encrypted JWT reveals header"
      (let [alg :rsa-oaep-256
            enc :a128gcm
            encrypted (encrypt-jwt {:encrypt-alg alg :encrypt-enc enc
                                    :claims std-claims :encrypt-key rsa-jwk})
            [header _ _ _ _] (unsafe-parse-serialized encrypted)]
        (is (map? header))))))

(deftest test-custom-header-params
  (let [kid "coolest kid on the block"
        addl-header-fields {:kid kid}
        alg :rsa-oaep
        enc :a256gcm
        encrypted (encrypt-jwt {:claims std-claims :encrypt-alg alg
                                :encrypt-enc enc :encrypt-key rsa-jwk
                                :addl-header-fields addl-header-fields})
        [header _ _ _ _] (unsafe-parse-serialized encrypted)]

    (testing "serialized JWT header contains custom key"
      (is (= kid (:kid header))))

    (testing "Nimbus fails to decrypt if kid is set in JWE header but not
              in key"
      (is (thrown? BadJOSEException
                   (decrypt-jwt
                     {:encrypt-alg alg :encrypt-enc enc
                      :serialized-jwt encrypted :decrypt-keys [rsa-jwk]}))))

    (testing "decryption succeeds if kid is assoced into key"
      (is (decrypt-jwt {:encrypt-alg alg :encrypt-enc enc
                        :serialized-jwt encrypted
                        :decrypt-keys [(assoc rsa-jwk :kid kid)]})))

    (testing "lots of standard header fields work correctly"
      (let [txt "http://www.example.com"
            many-fields {:apu txt
                         :apv txt
                         :tag txt
                         :zip "DEF"
                         :cty "JWT"
                         :iv txt
                         :jku txt
                         :kid kid
                         :p2c 5
                         :p2s txt
                         :x5c [txt txt]
                         :x5t#S256 txt}]
        (is (encrypt-jwt {:claims std-claims :encrypt-alg alg
                          :encrypt-enc enc :encrypt-key rsa-jwk
                          :addl-header-fields many-fields}))))))

(defn test-jwk-alg-enc
  [alg enc]
  (let [with-alg (assoc rsa-jwk :alg alg :enc enc)
         json-map (json/decode (keys/->json-jwk with-alg) true)
         nimbus-jwk (keys/map->JWK with-alg)
         json-nimbus-map (json/decode (.toJSONString nimbus-jwk) true)
         jwk (keys/JWK->map nimbus-jwk)]
    (testing "After conversion to JSON, :alg field has been translated from
              our keyword to the standard string"
      (is (= "RSA-OAEP" (:alg json-map))))
    (testing "After converting our JWK map to a Nimbus object, the algorithm
              field is set correctly"
      (is (= "RSA-OAEP" (.getName (.getAlgorithm nimbus-jwk)))))
    (testing "After converting Nimbus JWK to map, :alg field is once again a
              keyword"
      (is (= :rsa-oaep (:alg jwk))))))

(deftest test-jwk-alg-enc-keywords
  (test-jwk-alg-enc :rsa-oaep :rs256))

(deftest test-jwk-alg-enc-uppercase-keywords
  (test-jwk-alg-enc :RSA-OAEP :rs256))

(deftest test-none-alg
  (testing "Nimbus throws with none alg when another alg is expected"
    (is (thrown-with-msg?
           com.nimbusds.jose.proc.BadJOSEException
           #"Unsecured.*JWTs are rejected"
           (unsign-jwt {:signing-alg :hs256 :serialized-jwt none-jws
                        :unsigning-keys
                        [(first (keys/symmetric-keys
                                 {:key-len 256 :alg :hs256}))]})))
    (is (thrown-with-msg?
           com.nimbusds.jose.proc.BadJOSEException
           #"Unsecured.*JWTs are rejected"
           (decrypt-jwt {:encrypt-enc :a256gcm :encrypt-alg :rsa-oaep
                         :serialized-jwt none-jws :decrypt-keys [rsa-jwk]})))))

;; property-based tests
(deftest prop-encrypt-jwt
  (is (every? (comp nil? :failure)
              (stest/check `encrypt-jwt
                           {:clojure.spec.test.check/opts {:num-tests 100}}))))
