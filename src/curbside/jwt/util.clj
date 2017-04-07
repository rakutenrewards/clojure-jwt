(ns curbside.jwt.util
  (:import java.util.UUID))

(defn uuids
  "Returns an infinite lazy sequence of random UUIDs."
  []
  (lazy-seq
    (cons (str (UUID/randomUUID)) (uuids))))
