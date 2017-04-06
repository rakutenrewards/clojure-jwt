(ns curbside-jwt.core-test
  (:require [clojure.test :refer :all]
            [curbside-jwt.core :refer :all]))

(def rsa-jwk (gen-rsa-jwk 2048 false))

(deftest test-sign-rsa
  (let [claims {:iss "curbside.com" :aud ["curbside.com"]}
        jwt (sign-jwt :rs256 claims rsa-jwk)
        verified (unsign-jwt :rs256 jwt rsa-jwk claims)]
    (is (map? verified))))
