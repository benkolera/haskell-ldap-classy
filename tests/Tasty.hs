module Main where

import Control.Monad          (unless)
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
  unless (null result) $ assertFailure "There were HLint errors, sry!"
