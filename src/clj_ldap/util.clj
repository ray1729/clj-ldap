(ns clj-ldap.util
  (:require [clojure.string :as str])
  (:import [com.unboundid.util Base64]))

(defn- authority
  [s]
  (let [hex-str (apply str (map (fn [ix] (Integer/toHexString (bit-and 0xFF (aget s ix))))
                                [2 3 4 5 6 7]))]
    (Long/parseLong hex-str 16)))

(defn- sub-authority
  [s n]
  (let [offset (* n 4)
        hex-str (apply format "%02x%02x%02x%02x"
                       (map (fn [ix] (bit-and 0xFF (aget s (+ ix offset)))) [11 10 9 8]))]
    (Long/parseLong hex-str 16)))

(defn decode-object-sid
  "Convert an objectSID from a byte-array (returned from Active Directory) to a string.
   Based on code from <http://www.jroller.com/eyallupu/entry/java_jndi_how_to_convert>."
  [s]
  (let [s                   (if (string? s) (Base64/decode s) s)
        version             (int (aget s 0))
        num-sub-authorities (int (aget s 1))]
    (str "S-" version "-" (authority s) "-"
         (str/join "-" (map (partial sub-authority s) (range num-sub-authorities))))))

(defn gid-from-object-sid
  "When an object represents a group, the last component of objectSID encodes the GID
   that should be the primaryGroupID of users in that group."
  [s]
  (let [s (if (string? s) (Base64/decode s) s)
        n (int (aget s 1))]
    (sub-authority s (dec n))))
