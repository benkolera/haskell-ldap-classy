{-# LANGUAGE FlexibleInstances     #-}
{-# LANGUAGE NoImplicitPrelude     #-}
{-# LANGUAGE TemplateHaskell       #-}
{-# LANGUAGE TupleSections         #-}
module LDAP.Classy.Decode
  ( LdapEntryDecodeError(..)
  , FromLdapAttribute(..)
  , ToLdapAttribute(..)
  , FromLdapEntry(..)
  , ToLdapEntry(..)
  , attrMay
  , attrSingle
  , attrList
  , attrNel
  , AsLdapEntryDecodeError
  , _LdapEntryDecodeError
  , _RequiredAttributeMissing
  , _AttributeFailedParse
  ) where

import           Prelude                   (Double, Int, Integer, Read, Show,
                                            show, (==))

import           Control.Applicative       (Applicative (..), pure)
import           Control.Category          (id, (.))
import           Control.Lens
import           Control.Monad             ((=<<))
import           Control.Monad.Error.Hoist (hoistError, (<%?>))
import           Control.Monad.Error.Lens  (throwing)
import           Control.Monad.Except      (MonadError)

import           Safe                      (headMay, readMay)

import           Data.Either               (Either (..))
import           Data.Foldable             (find)
import           Data.Function             (const, ($))
import           Data.Functor              (Functor, fmap)
import           Data.List.NonEmpty        (NonEmpty (..))
import qualified Data.List.NonEmpty        as NEL
import           Data.Maybe                (Maybe (..), maybe)
import           Data.String               (String)
import qualified Data.Text                 as T
import qualified Data.Text.Lazy            as TL
import           Data.Text.Lens            (packed)
import           Data.Tuple                (snd)
import           LDAP                      as L

import           LDAP.Classy.Dn
import           LDAP.Classy.Types

data LdapEntryDecodeError
  = RequiredAttributeMissing LDAPEntry String
  | AttributeFailedParse LDAPEntry String String
  deriving Show
makeClassyPrisms ''LdapEntryDecodeError

class FromLdapAttribute a where
  fromLdapAttribute :: String -> Either String a

class ToLdapAttribute a where
  toLdapAttribute :: a -> String

class FromLdapEntry a where
  fromLdapEntry :: (MonadError e m,AsLdapEntryDecodeError e,Applicative m) => L.LDAPEntry -> m a

class ToLdapEntry a where
  toLdapAttrs :: a -> [(String,[String])]
  toLdapAttrs = leattrs . toLdapEntry
  toLdapDn :: a -> Dn
  toLdapDn = dnFromEntry . toLdapEntry
  toLdapEntry :: a -> LDAPEntry
  toLdapEntry a = LDAPEntry (toLdapDn a ^.dnText.from packed) (toLdapAttrs a)

  {-# MINIMAL toLdapAttrs, toLdapDn | toLdapEntry #-}

attrMay
  :: (MonadError e m, AsLdapEntryDecodeError e,FromLdapAttribute a,Applicative m)
  => String
  -> LDAPEntry
  -> m (Maybe a)
attrMay = attrsParse (pure . headMay)

attrList
  :: (MonadError e m, AsLdapEntryDecodeError e,FromLdapAttribute a,Applicative m)
  => String
  -> LDAPEntry
  -> m [a]
attrList = attrsParse pure

attrSingle
  :: (MonadError e m, AsLdapEntryDecodeError e,FromLdapAttribute a,Applicative m,Functor m)
  => String
  -> LDAPEntry
  -> m a
attrSingle n e =
  fmap runIdentity
  . attrsParse (fmap (Identity . NEL.head) .  requireNel n e) n
  $ e

attrNel
  :: (MonadError e m, AsLdapEntryDecodeError e,FromLdapAttribute a,Applicative m)
  => String
  -> LDAPEntry
  -> m (NonEmpty a)
attrNel n e = attrsParse (requireNel n e) n e

requireNel
  :: ( AsLdapEntryDecodeError e
    , MonadError e m
    , Applicative m
    )
  => String
  -> LDAPEntry
  -> [a]
  -> m (NonEmpty a)
requireNel n e []     = throwing _RequiredAttributeMissing (e,n)
requireNel _ _ (x:xs) = pure (x :| xs)

attrsParse
  :: ( MonadError e m
    , AsLdapEntryDecodeError e
    , FromLdapAttribute a
    , Traversable t
    , Applicative m
    )
  => ([String] -> m (t String))
  -> String
  -> LDAPEntry
  -> m (t a)
attrsParse f n e =
  (traverse parse =<<)
  . f
  . findAttribute n
  $ e
  where
    parse s = fromLdapAttribute s <%?> ((_AttributeFailedParse #) . (e,n,))

findAttribute :: String -> LDAPEntry -> [String]
findAttribute n (LDAPEntry _ as) =
  maybe [] snd $ find (^._1.to(== n)) as

instance FromLdapAttribute Int where
  fromLdapAttribute = readLdapAttribute "Invalid Int"

instance FromLdapAttribute Integer where
  fromLdapAttribute = readLdapAttribute "Invalid Integer"

instance FromLdapAttribute Double where
  fromLdapAttribute = readLdapAttribute "Invalid Double"

instance FromLdapAttribute T.Text where
  fromLdapAttribute = pure . T.pack

instance FromLdapAttribute TL.Text where
  fromLdapAttribute = pure . TL.pack

instance FromLdapAttribute String where
  fromLdapAttribute = pure

instance ToLdapAttribute Int where
  toLdapAttribute = show

instance ToLdapAttribute Integer where
  toLdapAttribute = show

instance ToLdapAttribute Double where
  toLdapAttribute = show

instance ToLdapAttribute T.Text where
  toLdapAttribute = T.unpack

instance ToLdapAttribute TL.Text where
  toLdapAttribute = TL.unpack

instance ToLdapAttribute String where
  toLdapAttribute = id

instance FromLdapEntry LDAPEntry where
  fromLdapEntry = pure

instance ToLdapEntry LDAPEntry where
  toLdapEntry = id

instance ToLdapAttribute Dn where
  toLdapAttribute = T.unpack . dnToText

instance FromLdapAttribute Dn where
  fromLdapAttribute =
    maybe (Left "Invalid DN") Right
    . dnFromText
    . T.pack

instance FromLdapAttribute Uid where
  fromLdapAttribute = fmap Uid . fromLdapAttribute

instance FromLdapAttribute UidNumber where
  fromLdapAttribute = fmap UidNumber . fromLdapAttribute

instance FromLdapAttribute GidNumber where
  fromLdapAttribute = fmap GidNumber . fromLdapAttribute

readLdapAttribute :: (MonadError e m, Read a) => e -> String -> m a
readLdapAttribute e = hoistError (const e) . readMay
