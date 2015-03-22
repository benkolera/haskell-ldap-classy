{-# LANGUAGE ConstraintKinds            #-}
{-# LANGUAGE FlexibleContexts           #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE NoImplicitPrelude          #-}
{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE TemplateHaskell            #-}
{-# LANGUAGE TypeFamilies               #-}
module LDAP.Classy
  ( Uid(..)
  , UidNumber(..)
  , Dn(..)
  , LdapConfig(..)
  , LdapError
  , AsLdapError(..)
  , LdapCredentials(..)
  , LdapEnv
  , HasLdapConfig(..)
  , HasLdapEnv(..)
  , search
  , searchWithScope
  , searchFirst
  , searchFirstWithScope
  , modifyEntry
  , insertEntry
  , deleteEntry
  , modify
  , insert
  , delete
  , setPassword
  , changePassword
  , resetPassword
  , checkPassword
  , bindLdap
  , runLdap
  , runLdapSimple
  , module LDAP
  , module LDAP.Classy.Types
  ) where

import BasePrelude hiding (delete, first, insert, try)

import           Control.Lens
import           Control.Monad.Catch       (try)
import           Control.Monad.Error.Hoist ((<%!?>))
import           Control.Monad.Error.Lens  (catching, throwing)
import           Control.Monad.Except      (ExceptT, MonadError, runExceptT,
                                            throwError)
import           Control.Monad.IO.Class    (MonadIO, liftIO)
import           Control.Monad.Reader      (MonadReader, ReaderT, runReaderT)
import           Crypto.Password           (CharType (..), PasswordFeature (..),
                                            generatePassword)
import           Data.Text                 (Text, pack)
import           Data.Text.Lazy            (fromStrict)
import           Data.Text.Lens
import           LDAP                      (LDAP, LDAPEntry (..),
                                            LDAPException (..), LDAPMod (..),
                                            LDAPModOp (..), LDAPScope (..),
                                            SearchAttributes (..))
import qualified LDAP                      as L
import           LDAP.Classy.Decode        (AsLdapEntryDecodeError,
                                            FromLdapEntry (..),
                                            LdapEntryDecodeError,
                                            ToLdapEntry (..),
                                            _LdapEntryDecodeError)
import           LDAP.Classy.Search        (LdapSearch, ldapSearchStr)
import           LDAP.Classy.SSha          (toSSha)
import           LDAP.Classy.Types
import           Safe                      (headMay)

data LdapCredentials = LdapCredentials
  { _ldapCredentialsDn       :: Dn
  , _ldapCredentialsPassword :: Text
  }
makeClassy ''LdapCredentials

data LdapConfig = LdapConfig
  { _ldapConfigHost        :: Text
  , _ldapConfigPort        :: Int
  , _ldapConfigBaseDn      :: Maybe Dn
  , _ldapConfigScope       :: LDAPScope
  , _ldapConfigCredentials :: Maybe LdapCredentials
  }
makeClassy ''LdapConfig

data LdapEnv = LdapEnv
  { _ldapEnvContext :: LDAP
  , _ldapEnvConfig  :: LdapConfig
  }
makeClassy ''LdapEnv

instance HasLdapConfig LdapEnv where
  ldapConfig = ldapEnvConfig

data LdapError =
  ConnectException LDAPException
  | DecodeFailure LdapEntryDecodeError
  | BindFailure LDAPException
  deriving Show
makeClassyPrisms ''LdapError

instance AsLdapEntryDecodeError LdapError where
  _LdapEntryDecodeError = _DecodeFailure . _LdapEntryDecodeError


type CanLdap m c e =
  ( MonadError e m
  , MonadReader c m
  , MonadIO m
  , AsLdapEntryDecodeError e
  , HasLdapEnv c
  )

searchWithScope
  :: ( CanLdap m c e , AsLdapError e, Applicative m, FromLdapEntry a )
  => LdapSearch
  -> SearchAttributes
  -> Maybe Dn
  -> LDAPScope
  -> m [a]
searchWithScope q a dn s = do
  es <- liftLdap $ \ l -> L.ldapSearch l (dn^?_Just._Wrapped.from packed) s (Just qs) a False
  traverse fromLdapEntry es
  where
    qs = ldapSearchStr q

-- TODO: I don't like that the searchAttrs passed in are separate from
--       the FromLdapEntry instance meaning you can change one and
--       easily forget to change the other.
search :: ( CanLdap m c e , AsLdapError e, Applicative m, FromLdapEntry a )
  => LdapSearch
  -> SearchAttributes
  -> m [a]
search q a = do
  dn <- view (ldapEnvConfig.ldapConfigBaseDn)
  s  <- view (ldapEnvConfig.ldapConfigScope)
  searchWithScope q a dn s

searchFirstWithScope :: ( CanLdap m c e , AsLdapError e, Applicative m, FromLdapEntry a )
  => LdapSearch
  -> SearchAttributes
  -> Maybe Dn
  -> LDAPScope
  -> m (Maybe a)
searchFirstWithScope q a dn = fmap headMay . searchWithScope q a dn

searchFirst :: ( CanLdap m c e , AsLdapError e, Applicative m, FromLdapEntry a )
  => LdapSearch
  -> SearchAttributes
  -> m (Maybe a)
searchFirst q = fmap headMay . search q

modify :: (CanLdap m c e, AsLdapError e) => Dn -> [LDAPMod] -> m ()
modify dn mods = liftLdap $ \ l -> L.ldapModify l (dn^._Wrapped.from packed) mods

modifyEntry :: (CanLdap m c e, AsLdapError e,ToLdapEntry a) => a -> m ()
modifyEntry a =
  modify (toLdapDn a) . L.list2ldm LdapModReplace . toLdapAttrs $ a

insert :: (CanLdap m c e, AsLdapError e) => LDAPEntry -> m ()
insert le = liftLdap $ \ l ->
  L.ldapAdd l (ledn le) . L.list2ldm LdapModAdd . leattrs $ le

insertEntry :: (CanLdap m c e, AsLdapError e,ToLdapEntry a) => a -> m ()
insertEntry = insert . toLdapEntry

delete :: (CanLdap m c e, AsLdapError e) => Dn -> m ()
delete dn = liftLdap $ \ l -> L.ldapDelete l (dn^._Wrapped.from packed)

deleteEntry :: (CanLdap m c e, AsLdapError e,ToLdapEntry a) => a -> m ()
deleteEntry = delete . toLdapDn . toLdapEntry

setPassword :: (CanLdap m c e, AsLdapError e) => Dn -> Text -> m ()
setPassword dn pw = do
  sSha <- liftIO $ toSSha (fromStrict pw)
  modify dn [LDAPMod LdapModReplace "userPassword" [show sSha]]

changePassword :: (CanLdap m c e, AsLdapError e,Applicative m) => Dn -> Text -> Text -> m ()
changePassword dn oldPw newPw = do
  checkPassword dn oldPw
  setPassword dn newPw

resetPassword :: (CanLdap m c e, AsLdapError e,Applicative m) => Dn -> m Text
resetPassword dn = do
  pw <- liftIO $ pack <$> generatePassword
    [ Length 10
    , Include Lowercase
    , Include Uppercase
    , Include Symbol
    , Include Digit
    , IncludeAtLeast 1 Symbol
    , IncludeAtLeast 1 Digit
    , IncludeAtLeast 2 Uppercase
    , IncludeAtLeast 3 Uppercase
    ]
  setPassword dn pw
  pure pw

checkPassword :: (CanLdap m c e, AsLdapError e,Applicative m) => Dn -> Text -> m ()
checkPassword dn pw = bindLdap dn pw >> bindRootDn

bindLdap :: (CanLdap m c e, AsLdapError e) => Dn -> Text -> m ()
bindLdap d p = catching _ConnectException doBind (throwing _BindFailure)
  where
    doBind = liftLdap $ \ c ->
      L.ldapSimpleBind c (d^._Wrapped.from packed) (p^.from packed)

bindRootDn :: (CanLdap m c e, AsLdapError e,Applicative m) => m ()
bindRootDn =
  view (ldapEnvConfig.ldapConfigCredentials) >>= traverse_ rootLogin
  where
    rootLogin (LdapCredentials d p) = bindLdap d p

liftLdap :: (CanLdap m c e, AsLdapError e) => (LDAP -> IO a) -> m a
liftLdap f = view ldapEnvContext >>= tryLdap . f

tryLdap :: (MonadError e m, MonadIO m, AsLdapError e) => IO a -> m a
tryLdap m = (liftIO . try $ m) <%!?> (_ConnectException #)

runLdap
  :: ( MonadReader c m
    , MonadError e m
    , MonadIO m
    , Applicative m
    , AsLdapError e
    , AsLdapEntryDecodeError e
    , HasLdapConfig c
    )
  => ExceptT e (ReaderT LdapEnv IO) a
  -> m a
runLdap m = do
  c <- view ldapConfig
  let h = c ^.ldapConfigHost.from packed
  let p = c ^.ldapConfigPort.to fromIntegral
  ctx <- tryLdap $ L.ldapInit h p
  let env = LdapEnv ctx c
  doLdap env $ bindRootDn >> m
  where
    doLdap env m' = do
      e <- liftIO $ (runReaderT (runExceptT m') env)
      either throwError pure e

runLdapSimple
  :: ExceptT LdapError (ReaderT LdapEnv IO) a
  -> LdapConfig
  -> IO (Either LdapError a)
runLdapSimple m e = runExceptT $ runReaderT (runLdap m) e
