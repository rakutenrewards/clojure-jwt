(defproject com.curbside/curbside-jwt "2.0.0-SNAPSHOT"
  :description "JWT processing based on Nimbus JOSE + JWT"
  :url "https://github.com/Curbside/curbside-jwt"
  :dependencies [[org.clojure/clojure "1.10.0"]
                 [org.clojure/spec.alpha "0.2.176"]
                 [clj-time "0.13.0"]
                 [com.nimbusds/nimbus-jose-jwt "4.41.2"
                  :exclusions [net.minidev/json-smart]]
                 [net.minidev/json-smart "1.3.1"]
                 [cheshire "5.7.0"]
                 [medley "0.8.4"]]
  :plugins [[lein-cljfmt "0.5.6"]]
  :profiles {:dev {:dependencies [[org.clojure/test.check "0.9.0"]
                                  [org.clojure/tools.trace "0.7.9"]]}}

  :deploy-repositories
  [["releases"
    {:url "https://maven.pkg.github.com/RakutenReady/curbside-jwt"
     :username :env/github_actor
     :password :env/github_token
     :sign-releases false}]])
