{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TupleSections     #-}
module LDAP.Classy.Dn where

-- The logic for encoding / decoding the strings can be found here:
-- https://tools.ietf.org/html/rfc4514
-- https://tools.ietf.org/html/rfc4512

import           BasePrelude          hiding ((<>))

import           Control.Lens         (Getter, Prism', prism', to)
import           Data.Attoparsec.Text (Parser,maybeResult,eitherResult,parse,sepBy1,char,many1,option,inClass,satisfy,notInClass,endOfInput,feed)
import           Data.List.NonEmpty   (NonEmpty((:|)), nonEmpty)
import qualified Data.List.NonEmpty   as NEL
import           Data.Semigroup       (Semigroup (..))
import           Data.Text            (Text)
import qualified Data.Text            as T
import           LDAP                 (LDAPEntry (..))

data AttrType
  = LocalityName
  | CommonName
  | StateOrProvinceName
  | OrganizationName
  | OrganizationalUnitName
  | CountryName
  | StreetAddress
  | DomainComponent
  | UserId
  | OtherAttrType Text
  | OidAttrType Integer
  deriving (Eq)

instance Show AttrType where
  show LocalityName           = "L"
  show CommonName             = "CN"
  show StateOrProvinceName    = "ST"
  show OrganizationName       = "O"
  show OrganizationalUnitName = "OU"
  show CountryName            = "C"
  show StreetAddress          = "STREET"
  show DomainComponent        = "DC"
  show UserId                 = "UID"
  show (OtherAttrType t)      = T.unpack t
  show (OidAttrType i)        = show i

newtype RelativeDn = RelativeDn
  { unRelativeDn :: NonEmpty (AttrType,Text)
  } deriving (Eq,Show)

-- BUG: Note that our derived equality here doesn't work in all cases
-- because we at least need to treat the relative DNs as sets rather
-- than have the ordering affect equality. There is something in an
-- RFC about this that I'll have to read later.
newtype Dn = Dn { unDn :: NonEmpty RelativeDn } deriving (Eq)

uid :: Text -> (AttrType,Text)
uid = (UserId,)

cn :: Text -> (AttrType,Text)
cn = (CommonName,)

ou :: Text -> (AttrType,Text)
ou = (OrganizationalUnitName,)

dc :: Text -> (AttrType,Text)
dc = (DomainComponent,)

l :: Text -> (AttrType,Text)
l = (LocalityName,)

st :: Text -> (AttrType,Text)
st = (StateOrProvinceName,)

o :: Text -> (AttrType,Text)
o = (OrganizationName,)

c :: Text -> (AttrType,Text)
c = (CountryName,)

street :: Text -> (AttrType,Text)
street = (StreetAddress,)

oid :: Integer -> Text -> (AttrType,Text)
oid o = (OidAttrType o,)

dnCons :: RelativeDn -> Dn -> Dn
dnCons p (Dn nel) = Dn (NEL.cons p nel)

rDnSingle :: (AttrType,Text) -> RelativeDn
rDnSingle = RelativeDn . (:| [])

rDnCons :: (AttrType,Text) -> RelativeDn -> RelativeDn
rDnCons kv (RelativeDn nel) = RelativeDn (NEL.cons kv nel)

dnText :: Getter Dn Text
dnText = to dnToText

isParentOf :: Dn -> Dn -> Bool
isParentOf (Dn p) (Dn c) = pl < cl && NEL.drop (cl - pl) c == NEL.toList p
  where
    pl = NEL.length p
    cl = NEL.length c

isChildOf :: Dn -> Dn -> Bool
isChildOf c p = c /= p && (isParentOf p c)

-- We're assuming that the LDAP server is going to return a valid DN
dnFromEntry :: LDAPEntry -> Dn
dnFromEntry (LDAPEntry dnStr _) =
  fromMaybe (error $ "DN from LDAP was not valid: " <> dnStr)
  . dnFromText
  . T.pack
  $ dnStr

_DnFromText :: Prism' Text Dn
_DnFromText = prism' dnToText dnFromText

-- TODO: This probably needs to do something with escaping stuff.
dnToText :: Dn -> Text
dnToText =
  T.intercalate ","
  . toList
  . fmap relativeDnToText
  . unDn

relativeDnToText :: RelativeDn -> Text
relativeDnToText =
  T.intercalate "+"
  . toList
  . fmap (\ (k,v) -> attrTypeToText k <> "=" <> v)
  . unRelativeDn

attrTypeToText :: AttrType -> Text
attrTypeToText = T.pack . show

dnFromText :: Text -> Maybe Dn
dnFromText = either (const Nothing) Just . dnFromTextEither

dnFromTextEither :: Text -> Either String Dn
dnFromTextEither = eitherResult . flip feed "" . parse distinguishedName

-- distinguishedName =
--  [ relativeDistinguishedName
--  * ( COMMA relativeDistinguishedName ) ]
distinguishedName :: Parser Dn
distinguishedName = Dn . NEL.fromList
  <$> (sepBy1 relativeDistinguishedName comma <* endOfInput)


-- relativeDistinguishedName = attributeTypeAndValue
-- *( PLUS attributeTypeAndValue )

relativeDistinguishedName :: Parser RelativeDn
relativeDistinguishedName = RelativeDn . NEL.fromList
   <$> sepBy1 attributeTypeAndValue plus

-- attributeTypeAndValue = attributeType EQUALS attributeValue
attributeTypeAndValue :: Parser (AttrType,Text)
attributeTypeAndValue = (,)
   <$> (attributeType <* optionalSpace <* equals <* optionalSpace)
   <*> (attributeValue <* optionalSpace)

-- attributeType = descr / numericoid
attributeType :: Parser AttrType
attributeType = descr <|> numericOid

-- attributeValue = string / hexstring
attributeValue :: Parser Text
attributeValue = dnString <|> hexString

-- descr = keystring
-- keystring = leadkeychar *keychar
-- leadkeychar = ALPHA
-- keychar = ALPHA / DIGIT / HYPHEN
descr :: Parser AttrType
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
    _        -> OtherAttrType t


-- numericoid = number 1*( DOT number )
-- number  = DIGIT / ( LDIGIT 1*DIGIT )
numericOid :: Parser AttrType
numericOid = OidAttrType . read <$>
  (   ((:)   <$> lDigit <*> many1 digit)
  <|> ((:[]) <$> digit)
  )

-- Simplifying this (probably incorrectly) based on the fact that we've
-- already gotten to a utf8 decoded Text anyway.
-- See http://www-01.ibm.com/support/knowledgecenter/SSVJJU_6.4.0/com.ibm.IBMDS.doc_6.4/ds_ag_dir_over_dn_syntax.html
-- TODO: I think there is something missing here with trimming leading/trailing space or something.
-- BUG: Yeah this doesn't allow a string in the middle.
dnString :: Parser Text
dnString = fmap T.concat . many1 $ (T.singleton <$> strChar) <|> pair

strChar :: Parser Char
strChar = satisfy (notInClass ",#=+;<>\\\x00")

escapedSpace :: Parser Char
escapedSpace = esc *> space

-- pair = ESC ( ESC / special / hexpair )
pair :: Parser Text
pair = esc *>
  (   (T.singleton <$> esc)
  <|> (T.singleton <$> special)
-- Our datastructure can't handle the hex pairs well nor do I have a
-- use for it. Lets omit unless it is needed later.
--  <|> hexPair
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
optionalSpace = void $ many space

-- hexstring = SHARP 1*hexpair
hexString :: Parser Text
hexString = sharp *> (T.concat <$> many1 hexPair)

-- hexpair = HEX HEX
hexPair :: Parser Text
hexPair = (\ a b -> T.pack [a,b]) <$> hex <*> hex

inClassP :: String -> Parser Char
inClassP = satisfy . inClass

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

instance Show Dn where
  show = T.unpack . dnToText

instance Semigroup Dn where
  (Dn nel1) <> (Dn nel2) = Dn (nel1 <> nel2)
