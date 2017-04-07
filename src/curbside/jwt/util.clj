(ns curbside.jwt.util
  (:import java.util.UUID))

(def uuids
  "Infinite lazy sequence of random UUIDs."
  (map str (repeatedly #(UUID/RandomUUID))))
