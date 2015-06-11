module Main where

import Test.Tasty
import Test.Tasty.HUnit
import Test.LDAP.Classy.Dn    (dnTests)
import Language.Haskell.HLint (hlint)

main = defaultMain tests

tests :: TestTree
tests = testGroup "Tests" [dnTests,hlintTests]

hlintTests :: TestTree
hlintTests = testCase "HLint check" $ do
  result <- hlint [ "LDAP/" ]
  result @?= []
