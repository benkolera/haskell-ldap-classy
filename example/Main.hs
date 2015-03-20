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


import           BasePrelude               hiding (first, try)

import           Control.Lens
import           Control.Monad.Error.Hoist ((<?>))
import           Control.Monad.Except      (ExceptT (..), MonadError,
                                            runExceptT)
import           Control.Monad.Reader      (MonadReader, ReaderT, runReaderT)
import           Control.Monad.Trans       (liftIO)
import           Control.Monad.Trans       (MonadIO)
import           Data.Bifunctor            (first)
import           Data.Text                 (Text, pack)
import qualified Data.Text                 as T
import           Data.Text.Lens
import           LDAP.Classy               (AsLdapError (..), Dn (..),
                                            HasLdapEnv (..), LDAPMod (..),
                                            LDAPModOp (..), LDAPScope (..),
                                            LdapConfig (..),
                                            LdapCredentials (..), LdapEnv,
                                            LdapError, SearchAttributes (..),
                                            Uid (..), UidNumber (..), ledn,
                                            modify, runLdap, searchFirst,
                                            updateEntry)
import           LDAP.Classy.Decode        (AsLdapEntryDecodeError (..),
                                            FromLdapEntry (..),
                                            ToLdapEntry (..), attrList, attrMay,
                                            attrSingle)
import           LDAP.Classy.Search        (isPosixAccount, isPosixGroup, (&&.),
                                            (==.))
import           Options.Applicative


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

updateUser :: (CanExampleLdap m c e, Applicative m, Functor m) => User -> m ()
updateUser = updateEntry

getUserByUidNumber :: (CanExampleLdap m c e, Applicative m , Functor m)  => UidNumber -> m (Maybe User)
getUserByUidNumber uidNum = searchFirst
   (isPosixAccount &&. "uidNumber" ==. (uidNum^._Wrapped.to show))
   userAttrs

getNextUidNumber :: (CanExampleLdap m c e, Applicative m , Functor m,AsExampleLdapError e) => m NextUidNumber
getNextUidNumber = do
  mUidMay <- getMaxUidNumber
  mUid    <- mUidMay <?> (_NoMaxUid # ())
  nUid    <- nextFreeUid (mUid + 1)
  modify "cn=MaxCustomerUid,ou=users,dc=iseek,dc=com,dc=au" [LDAPMod LdapModReplace "uidNumber" [nUid^._Wrapped._Wrapped.to show]]
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

instance ToLdapEntry User where
  toLdapDn    = view userDn
  toLdapAttrs u =
    [ ("uidNumber"   , [u^.userUidNumber._Wrapped.to show])
    , ("givenName"   , [u^.userFirstName.from packed])
    , ("sn"          , [u^.userLastName.from packed])
    , ("displayName" , [u^.userLastName.from packed])
    , ("mail"        , [u^.userEmail.from packed])
    , ("mobile"      , toList $ u^?userMobile._Just.from packed)
    ]

instance FromLdapEntry MemberUids where
  fromLdapEntry e = MemberUids <$> attrList "memberUid" e

instance FromLdapEntry NextUidNumber where
  fromLdapEntry e = NextUidNumber <$> attrSingle "uidNumber" e

main :: IO ()
main = printErr $ do
  o@(LdapOpts h p d s uMay pMay) <- liftIO $ execParser opts
  liftIO $ print o
  let conf = LdapConfig h p d s (LdapCredentials <$> traceShowId uMay <*> traceShowId pMay)
  runLdap' conf $ do
    u <- fromMaybe (error "User not found") <$> getUser (Uid "bkolera")
    liftIO $ print u
    -- User {_userUid = Uid "bkolera", _userDn = Dn "cn=Ben Kolera,ou=iseek,ou=users,dc=iseek,dc=com,dc=au", _userUidNumber = UidNumber 1234, _userFirstName = "Ben", _userLastName = "Kolera", _userDisplayName = "Ben Kolera", _userEmail = "bkolera@email.com.au", _userMobile = Just "0400123456"}
    void $ updateEntry (u & userMobile .~ (Just "0499333555"))
    uMayAfter <- getUser (Uid "bkolera")
    liftIO $ print (uMayAfter :: Maybe User)
    -- Just (User {_userUid = Uid "bkolera", _userDn = Dn "cn=Ben Kolera,ou=iseek,ou=users,dc=iseek,dc=com,dc=au", _userUidNumber = UidNumber 1234, _userFirstName = "Ben", _userLastName = "Kolera", _userDisplayName = "Ben Kolera", _userEmail = "bkolera@email.com.au", _userMobile = Just "0499333666"})
  where
    runLdap' :: LdapConfig -> ExceptT ExampleLdapError (ReaderT LdapEnv IO) a -> ExceptT String IO a
    runLdap' conf =
      ExceptT
      . fmap (first show)
      . flip runReaderT conf
      . runExceptT
      . runLdap
    printErr :: ExceptT String IO () -> IO ()
    printErr et = runExceptT et >>= either print (const . pure $ ())

data LdapOpts = LdapOpts Text Int (Maybe Dn) LDAPScope (Maybe Dn) (Maybe Text) deriving Show

opts :: ParserInfo LdapOpts
opts = info (helper <*> ldapOpts) ( fullDesc <> progDesc "Sample LDAP Class App")

ldapOpts :: Parser LdapOpts
ldapOpts = LdapOpts
  <$> textOption
    ( long     "host"
    <> metavar "HOSTNAME"
    <> help    "LDAP server hostname to connect to"
    <> value   "localhost"
    <> showDefault
    )
  <*> option auto
    ( long     "port"
    <> metavar "PORT"
    <> value   3389
    <> help    "Port on the LDAP server to connect to"
    )
  <*> option dnReader
    ( long    "baseDn"
    <> metavar "DN"
    <> value   (Just . Dn $ "dc=iseek,dc=com,dc=au")
    <> help    "Base DN to search from"
    )
  <*> option (eitherReader scopeFromString)
    ( long     "scope"
    <> metavar "SEARCH_SCOPE"
    <> value   LdapScopeSubtree
    <> help    "Either Default,Base,OneLevel or Subtree"
    <> showDefaultWith showScope )
  <*> option dnReader
    ( long    "rootDn"
    <> metavar "DN"
    <> value   Nothing
    <> help    "Optional root DN to bind with"
    <> showDefault
    )
  <*> textOptionMay
    ( long     "password"
    <> metavar "PASSWORD"
    <> help    "Password to bind with"
    <> value   Nothing
    <> showDefault
    )

textOption :: Mod OptionFields Text -> Parser Text
textOption = option (pack  <$> str)

textOptionMay :: Mod OptionFields (Maybe Text) -> Parser (Maybe Text)
textOptionMay = option textOptionMayReader

textOptionMayReader :: ReadM (Maybe Text)
textOptionMayReader = eitherReader (pure . mfilter (not . T.null) . Just . pack)

scopeFromString :: String -> Either String LDAPScope
scopeFromString "Default"  = Right LdapScopeDefault
scopeFromString "Base"     = Right LdapScopeBase
scopeFromString "OneLevel" = Right LdapScopeOnelevel
scopeFromString "Subtree"  = Right LdapScopeSubtree
scopeFromString s          = Left $ "Invalid Scope: " <> s

showScope :: LDAPScope -> String
showScope LdapScopeDefault     = "Default"
showScope LdapScopeBase        = "Base"
showScope LdapScopeOnelevel    = "OneLevel"
showScope LdapScopeSubtree     = "SubTree"
showScope (UnknownLDAPScope l) = "Level_" <> show l

dnReader :: ReadM (Maybe Dn)
dnReader = fmap Dn <$> textOptionMayReader
