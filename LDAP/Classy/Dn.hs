{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TupleSections     #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}
module LDAP.Classy.Dn
  ( module LDAP.Classy.Dn.Types
  -- Lenses and Prisms
  , dnText
  , _DnText
  -- Other DN functions
  , isParentOf
  , isChildOf
  , dnToText
  -- Dn Construction combinators
  , dnCons
  , rDnCons
  , rDnSingle
  , dnFromText
  , dnFromTextEither
  , dnFromEntry
  ) where

import           Prelude                   (Show, error, show, (&&), (-), (/=),
                                            (<), (==))

import           Control.Category          ((.))
import           Control.Lens              (Getter, Prism', prism', to)

import           Data.Attoparsec.Text      (eitherResult, feed, parse)
import           Data.Bool                 (Bool (..))
import           Data.Either               (Either, either)
import           Data.Foldable             (length)
import           Data.Function             (const, flip, ($))
import           Data.Functor              (fmap)
import           Data.List                 (drop)
import           Data.List.NonEmpty        (NonEmpty ((:|)))
import qualified Data.List.NonEmpty        as NEL
import           Data.Maybe                (Maybe (..), fromMaybe)
import           Data.Semigroup            ((<>))
import           Data.String               (String)
import           Data.Text                 (Text)
import qualified Data.Text                 as T

import           LDAP                      (LDAPEntry (..))

import           LDAP.Classy.AttributeType (AttributeType)
import           LDAP.Classy.Dn.Internal
import           LDAP.Classy.Dn.Types

dnCons :: RelativeDn -> Dn -> Dn
dnCons p (Dn nel) = Dn (p : nel)

rDnSingle :: (AttributeType,Text) -> RelativeDn
rDnSingle = RelativeDn . (:| [])

rDnCons :: (AttributeType,Text) -> RelativeDn -> RelativeDn
rDnCons kv (RelativeDn nel) = RelativeDn (NEL.cons kv nel)

isParentOf :: Dn -> Dn -> Bool
isParentOf (Dn p) (Dn c) = pl < cl && drop (cl - pl) c == p
  where
    pl = length p
    cl = length c

isChildOf :: Dn -> Dn -> Bool
isChildOf c p = c /= p && isParentOf p c

-- We're assuming that the LDAP server is going to return a valid DN
dnFromEntry :: LDAPEntry -> Dn
dnFromEntry (LDAPEntry dnStr _) =
  fromMaybe (error $ "DN from LDAP was not valid: " <> dnStr)
  . dnFromText
  . T.pack
  $ dnStr

dnText :: Getter Dn Text
dnText = to dnToText

_DnText :: Prism' Text Dn
_DnText = prism' dnToText dnFromText

dnToText :: Dn -> Text
dnToText =
  T.intercalate ","
  . fmap relativeDnToText
  . unDn

dnFromText :: Text -> Maybe Dn
dnFromText = either (const Nothing) Just . dnFromTextEither

dnFromTextEither :: Text -> Either String Dn
dnFromTextEither = eitherResult . flip feed "" . parse distinguishedName

instance Show RelativeDn where
  show = T.unpack . relativeDnToText

instance Show Dn where
  show = T.unpack . dnToText
