{-# LANGUAGE OverloadedStrings #-}
module Test.LDAP.Classy.Dn (dnTests) where

import Test.Tasty (TestTree,testGroup)
import Test.Tasty.HUnit (Assertion,testCase,(@?=))

import Control.Applicative ((<*))
import Data.Attoparsec.Text (feed,parse,Parser,eitherResult,endOfInput)
import Data.Text (Text)
import Data.List.NonEmpty (NonEmpty((:|)))
import LDAP.Classy.Dn

dnTests :: TestTree
dnTests = testGroup "dn"
  [ testGroup "fromText"
    [ testCase "nullCharacter" dnFromTextNull
    , testCase "ok"            dnFromTextOk
    ]
  , testGroup "parsers"
    [ testCase "dnStringOk"                       parseDnStringOk
    , testCase "attributeValueOk"                 parseAttributeValueOk
    , testCase "attributeTypeOk"                  parseAttributeTypeOk
    , testCase "attributeTypeAndValueOk"          parseAttributeTypeAndValueOk
    , testCase "relativeDistinguishedNameOk"      parseRelativeDistinguishedNameOk
    , testCase "relativeDistinguishedNameMultiOk" parseRelativeDistinguishedNameMultiOk
    , testCase "distinguishedNameOk"              parseDistinguishedNameOk
    ]
  ]

dnFromTextNull :: Assertion
dnFromTextNull =
  (dnFromText "uid=benkolera\x00,dc=benkolera,dc=com") @?= Nothing

dnFromTextOk :: Assertion
dnFromTextOk = dnFromTextEither "uid=benkolera,dc=benkolera,dc=com" @?= expected
  where
    expected  = Right . Dn $ rDnSingle (uid "benkolera") :|
      [ rDnSingle (dc "benkolera")
      , rDnSingle (dc "com")
      ]

parserTest :: (Eq a, Show a) => Parser a -> Text -> Either String a -> Assertion
parserTest p t expected = eitherResult (feed (parse (p <* endOfInput) t) "") @?= expected

parseDnStringOk :: Assertion
parseDnStringOk = parserTest dnString "benkolera" (Right "benkolera")

parseAttributeValueOk :: Assertion
parseAttributeValueOk = parserTest attributeValue "benkolera" (Right "benkolera")

parseAttributeTypeOk :: Assertion
parseAttributeTypeOk = parserTest attributeType "uid" (Right "uid")

parseAttributeTypeAndValueOk :: Assertion
parseAttributeTypeAndValueOk =
  parserTest attributeTypeAndValue "uid=benkolera" (Right ("uid","benkolera"))

parseRelativeDistinguishedNameOk :: Assertion
parseRelativeDistinguishedNameOk = parserTest
  relativeDistinguishedName
  "uid=benkolera"
  (Right $ rDnSingle (uid "benkolera"))

parseRelativeDistinguishedNameMultiOk :: Assertion
parseRelativeDistinguishedNameMultiOk = parserTest
  relativeDistinguishedName
  "uid=benkolera+cn=Ben Kolera"
  (Right . RelativeDn $ (uid "benkolera") :| [cn "Ben Kolera"])

parseDistinguishedNameOk :: Assertion
parseDistinguishedNameOk = parserTest
  distinguishedName
  "uid=benkolera,dc=benkolera,dc=com"
  (Right . Dn $ (rDnSingle $ uid "benkolera") :|
    [ rDnSingle $ dc "benkolera"
    , rDnSingle $ dc "com"
    ])
