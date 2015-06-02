module Main where

import Test.Tasty
import Test.LDAP.Classy.Dn (dnTests)

main = defaultMain tests

tests :: TestTree
tests = testGroup "Tests" [dnTests]
