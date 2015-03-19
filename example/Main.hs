{-# LANGUAGE ConstraintKinds            #-}
{-# LANGUAGE FlexibleContexts           #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE NoImplicitPrelude          #-}
{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE TemplateHaskell            #-}
{-# LANGUAGE TypeFamilies               #-}
module Main where

import BasePrelude hiding (first, try)

import Control.Lens
import Control.Monad.Error.Hoist ((<?>))
import Control.Monad.Except      (MonadError, runExceptT)
import Control.Monad.Reader      (MonadReader, runReaderT)
import Control.Monad.Trans       (MonadIO)
import Data.Text                 (Text)
import Data.Text.Lens
import LDAP.Classy               (AsLdapError (..), Dn (..), HasLdapEnv (..),
                                  LDAPMod (..), LDAPModOp (..), LDAPScope (..),
                                  LdapConfig (..), LdapError,
                                  SearchAttributes (..), Uid (..),
                                  UidNumber (..), ledn, runLdap, searchFirst,
                                  update)
import LDAP.Classy.Decode        (AsLdapEntryDecodeError (..),
                                  FromLdapEntry (..), attrList, attrMay,
                                  attrSingle)
import LDAP.Classy.Search        (isPosixAccount, isPosixGroup, (&&.), (==.))

data ExampleLdapError = ExampleLdapErrorError LdapError | NoMaxUid deriving Show
makeClassyPrisms ''ExampleLdapError

instance AsLdapError ExampleLdapError where
  _LdapError = _ExampleLdapErrorError . _LdapError

instance AsLdapEntryDecodeError ExampleLdapError where
  _LdapEntryDecodeError = _ExampleLdapErrorError . _LdapError . _LdapEntryDecodeError

type CanExampleLdap m c e
   = ( MonadError e m
     , MonadReader c m
     , MonadIO m
     , AsLdapError e
     , AsLdapEntryDecodeError e
     , HasLdapEnv c
     )

newtype AccountId = AccountId Text deriving (Show)
makeWrapped ''AccountId

newtype MemberUids = MemberUids [Uid] deriving Show
makeWrapped ''MemberUids

newtype NextUidNumber = NextUidNumber UidNumber deriving (Show,Num)
makeWrapped ''NextUidNumber

data User = User
  { _userUid         :: Uid
  , _userDn          :: Dn
  , _userUidNumber   :: UidNumber
  , _userFirstName   :: String
  , _userLastName    :: String
  , _userDisplayName :: String
  , _userEmail       :: String
  , _userMobile      :: Maybe String
  } deriving Show
makeClassy ''User

userAttrs :: SearchAttributes
userAttrs = LDAPAttrList ["uid","uidNumber","givenName","sn","displayName","mail","mobile"]

listUidsForAccount :: (CanExampleLdap m c e, Applicative m) => AccountId -> m MemberUids
listUidsForAccount a = do
  res <- searchFirst (isPosixGroup &&. "iseekSalesforceID" ==. (a^._Wrapped.from packed)) (LDAPAttrList ["memberUid"])
  pure . fromMaybe (MemberUids []) $ res

getUser :: (CanExampleLdap m c e, Applicative m , Functor m) => Uid -> m (Maybe User)
getUser uid = searchFirst
   (isPosixAccount &&. "uid" ==. (uid^._Wrapped.from packed))
   userAttrs

getUserByUidNumber :: (CanExampleLdap m c e, Applicative m , Functor m)  => UidNumber -> m (Maybe User)
getUserByUidNumber uidNum = searchFirst
   (isPosixAccount &&. "uidNumber" ==. (uidNum^._Wrapped.to show))
   userAttrs

getNextUidNumber :: (CanExampleLdap m c e, Applicative m , Functor m,AsExampleLdapError e) => m NextUidNumber
getNextUidNumber = do
  mUidMay <- getMaxUidNumber
  mUid    <- mUidMay <?> (_NoMaxUid # ())
  nUid    <- nextFreeUid (mUid + 1)
  update "cn=MaxCustomerUid,ou=users,dc=iseek,dc=com,dc=au" [LDAPMod LdapModReplace "uidNumber" [nUid^._Wrapped._Wrapped.to show]]
  pure nUid
  where
    nextFreeUid mUid = do
      uMay <- getUserByUidNumber (mUid^._Wrapped)
      maybe (pure mUid) (const (nextFreeUid (mUid+1))) uMay

getMaxUidNumber :: (CanExampleLdap m c e, Applicative m, Functor m) => m (Maybe NextUidNumber)
getMaxUidNumber =  searchFirst
  ("objectClass" ==. "iseekUidNext" &&. "cn" ==. "MaxCustomerUid")
  (LDAPAttrList ["uidNumber"])

instance FromLdapEntry User where
  fromLdapEntry e = User
    <$> (attrSingle "uid" e <&> Uid)
    <*> pure (e ^.to ledn.packed.from _Wrapped)
    <*> (attrSingle "uidNumber" e <&> UidNumber)
    <*> attrSingle "givenName" e
    <*> attrSingle "sn" e
    <*> attrSingle "displayName" e
    <*> attrSingle "mail" e
    <*> attrMay "mobile" e

instance FromLdapEntry MemberUids where
  fromLdapEntry e = MemberUids <$> attrList "memberUid" e

instance FromLdapEntry NextUidNumber where
  fromLdapEntry e = NextUidNumber <$> attrSingle "uidNumber" e

main :: IO ()
main = do
  uMay <- runLdap' (getUser (Uid "bkolera")) :: IO (Either ExampleLdapError (Maybe User))
  print uMay
  -- Right (Just (User {_userUid = Uid "bkolera", _userDn = Dn "cn=Ben Kolera,ou=iseek,ou=users,dc=iseek,dc=com,dc=au", _userUidNumber = UidNumber 1234, _userFirstName = "Ben", _userLastName = "Kolera", _userDisplayName = "Ben Kolera", _userEmail = "bkolera@email.com.au", _userMobile = Just "0400123456"}))
  where
    conf = LdapConfig "localhost" 3389 (Just "dc=iseek,dc=com,dc=au") LdapScopeSubtree Nothing
    runLdap'  = flip runReaderT conf . runExceptT . runLdap
