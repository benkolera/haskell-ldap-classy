{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TupleSections     #-}
module LDAP.Classy.Dn.Internal where

import           BasePrelude            hiding ((<>))

import           Control.Lens           (Getter, Prism', prism', to)
import           Data.Attoparsec.Text   (Parser, char, eitherResult, endOfInput,
                                         feed, inClass, many1, manyTill,
                                         maybeResult, notInClass, option, parse,
                                         peekChar, satisfy, sepBy, sepBy1,
                                         skipMany, takeText)
import           Data.ByteString.Base16 as B16
import           Data.List.NonEmpty     (NonEmpty ((:|)), nonEmpty)
import qualified Data.List.NonEmpty     as NEL
import qualified Data.Monoid            as M
import           Data.Semigroup         (Semigroup (..))
import           Data.Text              (Text)
import qualified Data.Text              as T
import qualified Data.Text.Encoding     as T
import           LDAP                   (LDAPEntry (..))

import           LDAP.Classy.Dn.Types
import           LDAP.Classy.AttributeType
import           LDAP.Classy.AttributeValue
import           LDAP.Classy.ParsingUtils    (invalidStrCharSet,inClassP)

-- The logic for encoding / decoding the strings can be found here:
-- https://tools.ietf.org/html/rfc4514
-- https://tools.ietf.org/html/rfc4512

relativeDnToText :: RelativeDn -> Text
relativeDnToText =
  T.intercalate "+"
  . toList
  . fmap (\ (k,v) -> attrTypeToText k <> "=" <> escapeAttrValueText v)
  . unRelativeDn

-- distinguishedName =
--  [ relativeDistinguishedName
--  * ( COMMA relativeDistinguishedName ) ]
distinguishedName :: Parser Dn
distinguishedName = Dn
  <$> (sepBy relativeDistinguishedName comma <* endOfInput)

-- relativeDistinguishedName = attributeTypeAndValue
-- *( PLUS attributeTypeAndValue )

relativeDistinguishedName :: Parser RelativeDn
relativeDistinguishedName = RelativeDn . NEL.fromList
   <$> sepBy1 attributeTypeAndValue (plus <* optionalSpace)

-- attributeTypeAndValue = attributeType EQUALS attributeValue
attributeTypeAndValue :: Parser (AttributeType,Text)
attributeTypeAndValue = (,)
   <$> (attributeType <* optionalSpace <* equals)
   <*> attributeValue

-- attributeType = descr / numericoid
attributeType :: Parser AttributeType
attributeType = descr <|> numericOid

-- attributeValue = string / hexstring
attributeValue :: Parser Text
attributeValue = dnString <|> hexString

-- descr = keystring
-- keystring = leadkeychar *keychar
-- leadkeychar = ALPHA
-- keychar = ALPHA / DIGIT / HYPHEN
descr :: Parser AttributeType
descr = do
  t <- T.cons
    <$> alpha
    <*> (T.pack <$> many (alpha <|> digit <|> hyphen))
  pure $ case T.toUpper t of
    "L"      -> LocalityName
    "CN"     -> CommonName
    "ST"     -> StateOrProvinceName
    "O"      -> OrganizationName
    "OU"     -> OrganizationalUnitName
    "C"      -> CountryName
    "STREET" -> StreetAddress
    "DC"     -> DomainComponent
    "UID"    -> UserId
    _        -> OtherAttributeDescr t


-- numericoid = number 1*( DOT number )
-- number  = DIGIT / ( LDIGIT 1*DIGIT )
numericOid :: Parser AttributeType
numericOid = OidAttributeType . read <$>
  (   ((:)   <$> lDigit <*> many1 digit)
  <|> ((:[]) <$> digit)
  )

-- Simplifying this (probably incorrectly) based on the fact that we've
-- already gotten to a utf8 decoded Text anyway.
-- See http://www-01.ibm.com/support/knowledgecenter/SSVJJU_6.4.0/com.ibm.IBMDS.doc_6.4/ds_ag_dir_over_dn_syntax.html
dnString :: Parser Text
dnString = do
  skipMany space
  fmap T.concat . manyTill ((T.singleton <$> strChar) <|> pair) $ endOfDn

endOfDn :: Parser ()
endOfDn = do
  skipMany space
  ch <- peekChar
  case ch of
    Just ',' -> return ()
    Just '+' -> return ()
    Nothing  -> return ()
    _        -> mzero

strChar :: Parser Char
strChar = satisfy (notInClass invalidStrCharSet)

escapedSpace :: Parser Char
escapedSpace = esc *> space

-- pair = ESC ( ESC / special / hexpair )
pair :: Parser Text
pair = esc *>
  (   (T.singleton <$> esc)
  <|> (T.singleton <$> special)
  <|> hexPair
  )

singletonParser :: Parser Char -> Parser Text
singletonParser = fmap T.singleton

-- special = escaped / SPACE / SHARP / EQUALS
special :: Parser Char
special = escaped <|> space <|> sharp <|> equals

-- escaped = DQUOTE / PLUS / COMMA / SEMI / LANGLE / RANGLE
escaped :: Parser Char
escaped = dQuote <|> plus <|> comma <|> semiColon <|> lAngle <|> rAngle

optionalSpace :: Parser ()
optionalSpace = skipMany space

-- hexstring = SHARP 1*hexpair
hexString :: Parser Text
hexString = sharp *> (T.concat <$> many1 hexPair)

-- hexpair = HEX HEX
-- WARNING: This is making the assumption that all escaped hex pairs
-- only represent LATIN1 or ASCII characters. It does not join together
-- adjacent hexpairs and decode the resulting bytes as UTF8.
-- This doesn't seem a problem to me right now as the only things that
-- get escaped are the special characters.
hexPair :: Parser Text
hexPair = hexToChar <$> hex <*> hex
  where
    hexToChar a b = T.decodeUtf8 . fst . B16.decode . T.encodeUtf8 . T.pack $ [a,b]

-- ALPHA   = %x41-5A / %x61-7A   ; "A"-"Z" / "a"-"z"
alpha :: Parser Char
alpha = inClassP ['A'..'Z'] <|> inClassP ['a'..'z']

-- DIGIT   = %x30 / LDIGIT       ; "0"-"9"
digit :: Parser Char
digit = char '0' <|> lDigit

-- LDIGIT  = %x31-39             ; "1"-"9"
lDigit :: Parser Char
lDigit = inClassP ['1'..'9']

-- HEX     = DIGIT / %x41-46 / %x61-66 ; "0"-"9" / "A"-"F" / "a"-"f"
hex :: Parser Char
hex = digit <|> inClassP ['a'..'z'] <|> inClassP ['A'..'Z']

dQuote :: Parser Char
dQuote = char '"'

sharp :: Parser Char
sharp = char '#'

space :: Parser Char
space = char ' '

esc :: Parser Char
esc = char '\\'

semiColon :: Parser Char
semiColon = char ';'

rAngle :: Parser Char
rAngle = char '>'

lAngle :: Parser Char
lAngle = char '<'

hyphen :: Parser Char
hyphen = char '-'

comma :: Parser Char
comma = char ','

equals :: Parser Char
equals = char '='

plus :: Parser Char
plus = char '+'
