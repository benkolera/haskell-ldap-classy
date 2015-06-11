{-# LANGUAGE TupleSections #-}
module LDAP.Classy.AttributeType where

import           Data.Text          (Text)
import qualified Data.Text          as T

data AttributeType
  = LocalityName
  | CommonName
  | StateOrProvinceName
  | OrganizationName
  | OrganizationalUnitName
  | CountryName
  | StreetAddress
  | DomainComponent
  | UserId
  | OtherAttributeDescr Text
  | OidAttributeType Integer
  deriving (Eq)

instance Show AttributeType where
  show LocalityName            = "L"
  show CommonName              = "CN"
  show StateOrProvinceName     = "ST"
  show OrganizationName        = "O"
  show OrganizationalUnitName  = "OU"
  show CountryName             = "C"
  show StreetAddress           = "STREET"
  show DomainComponent         = "DC"
  show UserId                  = "UID"
  show (OtherAttributeDescr t) = T.unpack t
  show (OidAttributeType i)    = show i

uid :: Text -> (AttributeType,Text)
uid = (UserId,)

cn :: Text -> (AttributeType,Text)
cn = (CommonName,)

ou :: Text -> (AttributeType,Text)
ou = (OrganizationalUnitName,)

dc :: Text -> (AttributeType,Text)
dc = (DomainComponent,)

l :: Text -> (AttributeType,Text)
l = (LocalityName,)

st :: Text -> (AttributeType,Text)
st = (StateOrProvinceName,)

o :: Text -> (AttributeType,Text)
o = (OrganizationName,)

c :: Text -> (AttributeType,Text)
c = (CountryName,)

street :: Text -> (AttributeType,Text)
street = (StreetAddress,)

oid :: Integer -> Text -> (AttributeType,Text)
oid i = (OidAttributeType i,)

-- TODO: Need to actually implement this
otherAttrType :: Text -> Text -> Maybe AttributeType
otherAttrType _ _ = Nothing

attrTypeToText :: AttributeType -> Text
attrTypeToText = T.pack . show
