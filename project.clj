(defproject curbside-jwt "0.1.0-SNAPSHOT"
  :description "FIXME: write description"
  :url "http://example.com/FIXME"
  :dependencies [[org.clojure/clojure "1.9.0-alpha15"]
                 [clj-time "0.13.0"]
                 [com.nimbusds/nimbus-jose-jwt "4.35"
                  :exclusions [net.minidev/json-smart]]
                 [net.minidev/json-smart "1.3.1"]
                 [cheshire "5.7.0"]
                 [medley "0.8.4"]]
  :plugins [[lein-cljfmt "0.5.6"]]
  :profiles {:dev {:dependencies [[org.clojure/test.check "0.9.0"]]}})
