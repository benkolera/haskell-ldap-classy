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
  , searchFirst
  , updateEntry
  , modify
  , bindLdap
  , runLdap
  , module LDAP
  , module LDAP.Classy.Types
  ) where

import           BasePrelude               hiding (first, try)

import           Control.Lens
import           Control.Monad.Catch       (try)
import           Control.Monad.Error.Hoist ((<%!?>))
import           Control.Monad.Error.Lens  (catching, throwing)
import           Control.Monad.Except      (ExceptT, MonadError, runExceptT,
                                            throwError)
import           Control.Monad.IO.Class    (MonadIO, liftIO)
import           Control.Monad.Reader      (MonadReader, ReaderT, runReaderT)
import           Data.Text                 (Text)
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
import           LDAP.Classy.Types
import           Safe                      (headMay)

--
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


search :: ( CanLdap m c e , AsLdapError e, Applicative m, FromLdapEntry a )
  => LdapSearch
  -> SearchAttributes
  -> m [a]
search q a = do
  dn <- view (ldapEnvConfig.ldapConfigBaseDn)
  s  <- view (ldapEnvConfig.ldapConfigScope)
  es <- liftLdap $ \ l -> L.ldapSearch l (dn^?_Just._Wrapped.from packed) s (Just qs) a False
  traverse fromLdapEntry es
  where
    qs = ldapSearchStr q

searchFirst :: ( CanLdap m c e , AsLdapError e, Applicative m, FromLdapEntry a )
  => LdapSearch
  -> SearchAttributes
  -> m (Maybe a)
searchFirst q = fmap headMay . search q

modify :: (CanLdap m c e, AsLdapError e) => String -> [LDAPMod] -> m ()
modify dn mods = liftLdap $ \ l -> L.ldapModify l (traceShowId dn) (traceShowId mods)

updateEntry :: (CanLdap m c e, AsLdapError e,ToLdapEntry a) => a -> m ()
updateEntry a = modify (ledn lde) mods
  where
    lde  = toLdapEntry a
    mods = L.list2ldm LdapModReplace (leattrs lde)

bindLdap :: (CanLdap m c e, AsLdapError e) => Dn -> Text -> m ()
bindLdap d p = catching _ConnectException doBind (throwing _BindFailure)
  where
    doBind = liftLdap $ \ c ->
      L.ldapSimpleBind c (d^._Wrapped.from packed) (p^.from packed)

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
  let l = c ^.ldapConfigCredentials
  ctx <- tryLdap $ L.ldapInit h p
  let env = LdapEnv ctx c
  traverse_ (doLdap env . rootLogin) l
  doLdap env m
  where
    rootLogin (LdapCredentials d p) = bindLdap d p
    doLdap env m' = do
      e <- liftIO $ (runReaderT (runExceptT m') env)
      either throwError pure e
