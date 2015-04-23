{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TupleSections     #-}
module LDAP.Classy.Dn where

import           BasePrelude        hiding ((<>))

import           Control.Lens       (Getter, Prism', prism', to)
import           Data.List.NonEmpty (NonEmpty, nonEmpty)
import qualified Data.List.NonEmpty as NEL
import           Data.Semigroup     (Semigroup (..))
import           Data.Text          (Text)
import qualified Data.Text          as T
import           LDAP               (LDAPEntry (..))

newtype Dn = Dn { unDn :: NonEmpty (Text,Text) } deriving (Eq)

cn :: Text -> (Text,Text)
cn = ("cn",)

ou :: Text -> (Text,Text)
ou = ("ou",)

dc :: Text -> (Text,Text)
dc = ("dc",)

dnCons :: (Text,Text) -> Dn -> Dn
dnCons p (Dn nel) = Dn (NEL.cons p nel)

dnText :: Getter Dn Text
dnText = to dnToText

isParentOf :: Dn -> Dn -> Bool
isParentOf (Dn p) (Dn c) =
  pl < cl && NEL.drop (pl - cl) p == NEL.toList c
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
  . fmap (\ (k,v) -> k <> "=" <> v)
  . unDn

dnFromText :: Text -> Maybe Dn
dnFromText = fmap Dn . (nonEmpty =<<) . traverse parseDn . T.splitOn ","
  where
    parseDn t = case (T.splitOn "=" t) of
      [k,v] -> Just (k,v)
      _     -> Nothing

instance Show Dn where
  show = T.unpack . dnToText

instance Semigroup Dn where
  (Dn nel1) <> (Dn nel2) = Dn (nel1 <> nel2)
