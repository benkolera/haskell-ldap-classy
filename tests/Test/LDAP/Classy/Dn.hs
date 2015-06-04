{-# LANGUAGE OverloadedStrings #-}
module Test.LDAP.Classy.Dn (dnTests) where

import           Test.Tasty              (TestTree, testGroup)
import           Test.Tasty.HUnit        (Assertion, testCase, (@?=))

import           Control.Applicative     ((*>), (<*), (<|>))
import           Data.Attoparsec.Text    (Parser, eitherResult, endOfInput,
                                          feed, option, parse)
import           Data.Foldable           (traverse_)
import           Data.List.NonEmpty      (NonEmpty ((:|)))
import           Data.Semigroup          ((<>))
import           Data.Text               (Text)
import qualified Data.Text               as T

import           LDAP.Classy.Dn
import           LDAP.Classy.Dn.Internal
import           LDAP.Classy.Dn.Types

dnTests :: TestTree
dnTests = testGroup "dn"
  [ testGroup "fromText"
    [ testCase "nullCharacter" dnFromTextNull
    , testCase "ok"            dnFromTextOk
    , testCase "craycray"      dnFromTextCrayCray
    ]
  , testGroup "toText"
    [ testCase "ok"            dnToTextOk
    , testCase "crayCray"      dnToTextCrayCray
    ]
  , testGroup "parsers"
    [ testCase "parsePairOk"                          parsePairOk
    , testCase "dnStringOk"                           parseDnStringOk
    , testCase "dnStringSpacesOk"                     parseDnStringSpacesOk
    , testCase "attributeValueOk"                     parseAttributeValueOk
    , testCase "attributeTypeOk"                      parseAttributeTypeOk
    , testCase "attributeTypeAndValueOid"             parseAttributeTypeAndValueOid
    , testCase "attributeTypeAndValueOther"           parseAttributeTypeAndValueOther
    , testCase "attributeTypeAndValueOk"              parseAttributeTypeAndValueOk
    , testCase "attributeTypeAndValueSpaces"          parseAttributeTypeAndValueSpaces
    , testCase "parseNumericOid"                      parseNumericOid
    , testCase "relativeDistinguishedNameOk"          parseRelativeDistinguishedNameOk
    , testCase "relativeDistinguishedNameMultiSpaces" parseRelativeDistinguishedNameMultiSpaces
    , testCase "relativeDistinguishedNameMultiOk"     parseRelativeDistinguishedNameMultiOk
    , testCase "distinguishedNameOk"                  parseDistinguishedNameOk
    , testCase "parseEndOfDnOk"                       parseEndOfDnOk
    ]
  ]

dnFromTextNull :: Assertion
dnFromTextNull =
  (dnFromText "uid=benkolera\x00,dc=benkolera,dc=com") @?= Nothing

okDnText :: Text
okDnText = "UID=benkolera,DC=benkolera,DC=com"

okDn :: Dn
okDn = Dn
  [ rDnSingle $ uid "benkolera"
  , rDnSingle $ dc "benkolera"
  , rDnSingle $ dc "com"
  ]

dnFromTextOk :: Assertion
dnFromTextOk = dnFromTextEither okDnText @?= (Right okDn)

dnToTextOk :: Assertion
dnToTextOk = dnToText okDn @?= okDnText

crayCrayDnText :: Text
crayCrayDnText = "UID=benkolera + CN=  Ben Kolera\\ ,1337=foo,DC=benkolera,DC=com"

crayCrayDn :: Dn
crayCrayDn = Dn
  [ RelativeDn ( uid "benkolera" :| [cn "Ben Kolera "])
  , rDnSingle $ oid 1337 "foo"
  , rDnSingle $ dc "benkolera"
  , rDnSingle $ dc "com"
  ]


dnFromTextCrayCray :: Assertion
dnFromTextCrayCray = dnFromTextEither crayCrayDnText @?= (Right crayCrayDn)

dnToTextCrayCray :: Assertion
dnToTextCrayCray = dnToText crayCrayDn @?= crayCrayDnText

parserTest :: (Eq a, Show a) => Parser a -> Text -> Either String a -> Assertion
parserTest p t expected = eitherResult (feed (parse (p <* endOfInput) t) "") @?= expected

parsePairOk :: Assertion
parsePairOk =
  traverse_ (\ c -> parserTest pair ("\\" <> c) (Right c))
    [ " "
    , "#"
    , "+"
    , ","
    , ";"
    , "<"
    , ">"
    , "="
    , "\\"
    ]

parseDnStringOk :: Assertion
parseDnStringOk = parserTest dnString "benkolera" (Right "benkolera")

parseDnStringSpacesOk :: Assertion
parseDnStringSpacesOk = parserTest dnString "\\ ben kolera\\ " (Right " ben kolera ")

parseAttributeValueOk :: Assertion
parseAttributeValueOk = parserTest attributeValue "benkolera" (Right "benkolera")

parseAttributeValueSpaces :: Assertion
parseAttributeValueSpaces = parserTest attributeValue " ben kolera " (Right "ben kolera")

parseAttributeTypeOk :: Assertion
parseAttributeTypeOk = traverse_
  (\ (t,e) -> do
    parserTest attributeType (T.toUpper t) (Right e)
    parserTest attributeType (T.toLower t) (Right e)
  )
  [ ("uid"    , UserId )
  , ("l"      , LocalityName )
  , ("cn"     , CommonName )
  , ("ou"     , OrganizationalUnitName )
  , ("o"      , OrganizationName)
  , ("st"     , StateOrProvinceName)
  , ("street" , StreetAddress )
  , ("c"      , CountryName )
  , ("dc"     , DomainComponent )
  ]

parseAttributeTypeAndValueOk :: Assertion
parseAttributeTypeAndValueOk =
  parserTest attributeTypeAndValue "uid=benkolera" (Right (UserId,"benkolera"))

parseAttributeTypeAndValueOid :: Assertion
parseAttributeTypeAndValueOid =
  parserTest attributeTypeAndValue
    "1337=benkolera"
    (Right (OidAttrType 1337,"benkolera"))

parseNumericOid :: Assertion
parseNumericOid = parserTest numericOid "1337" (Right $ OidAttrType 1337)

parseAttributeTypeAndValueOther :: Assertion
parseAttributeTypeAndValueOther =
  parserTest attributeTypeAndValue
    "butts=benkolera"
    (Right (OtherAttrType "butts","benkolera"))

parseAttributeTypeAndValueSpaces :: Assertion
parseAttributeTypeAndValueSpaces =
  parserTest attributeTypeAndValue "uid = benkolera " (Right (UserId,"benkolera"))

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

parseRelativeDistinguishedNameMultiSpaces :: Assertion
parseRelativeDistinguishedNameMultiSpaces = parserTest
  relativeDistinguishedName
  "uid=benkolera + cn=Ben Kolera\\  "
  (Right . RelativeDn $ (uid "benkolera") :| [cn "Ben Kolera "])

parseDistinguishedNameOk :: Assertion
parseDistinguishedNameOk = parserTest
  distinguishedName
  "uid=benkolera,dc=benkolera,dc=com"
  (Right . Dn $
    [ rDnSingle $ uid "benkolera"
    , rDnSingle $ dc "benkolera"
    , rDnSingle $ dc "com"
    ])

parseEndOfDnOk :: Assertion
parseEndOfDnOk = traverse_
  (\(x,e) -> parserTest
    (endOfDn *> option T.empty (fmap T.singleton (comma <|> plus))) -- Mess around consuming the trailing comma we expect
    x
    (Right e))
  [(" ","")
  ,("   ","")
  ,(",",",")
  ,(" ,",",")
  ,("   ,",",")
  ,("+","+")
  ,(" +","+")
  ,("   +","+")
  ]
