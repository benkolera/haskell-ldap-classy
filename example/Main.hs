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
                                            GidNumber (..), HasLdapEnv (..),
                                            LDAPMod (..), LDAPModOp (..),
                                            LDAPScope (..), LdapConfig (..),
                                            LdapCredentials (..), LdapEnv,
                                            LdapError, SearchAttributes (..),
                                            Uid (..), UidNumber (..),
                                            changePassword, checkPassword,
                                            deleteEntry, insertEntry, ledn,
                                            modify, modifyEntry, resetPassword,
                                            runLdap, searchFirst, setPassword)
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

data User' a = User
  { _userUid         :: Uid
  , _userDn          :: Dn
  , _userGidNumber   :: GidNumber
  , _userUidNumber   :: a
  , _userFirstName   :: String
  , _userLastName    :: String
  , _userDisplayName :: String
  , _userEmail       :: String
  , _userMobile      :: Maybe String
  } deriving Show
makeLenses ''User'

type NewUser = User' ()
type User    = User' UidNumber

userAttrs :: SearchAttributes
userAttrs = LDAPAttrList
  [ "uid"
  , "gidNumber"
  , "uidNumber"
  , "givenName"
  , "sn"
  , "displayName"
  , "mail"
  , "mobile"
  , "cn"
  ]

listUidsForAccount :: (CanExampleLdap m c e, Applicative m) => AccountId -> m MemberUids
listUidsForAccount a = do
  res <- searchFirst (isPosixGroup &&. "iseekSalesforceID" ==. (a^._Wrapped.from packed)) (LDAPAttrList ["memberUid"])
  pure . fromMaybe (MemberUids []) $ res

getUser :: (CanExampleLdap m c e, Applicative m , Functor m) => Uid -> m (Maybe User)
getUser uid = searchFirst
   (isPosixAccount &&. "uid" ==. (uid^._Wrapped.from packed))
   userAttrs

updateUser :: (CanExampleLdap m c e, Applicative m, Functor m) => User -> m ()
updateUser = modifyEntry

insertUser :: (CanExampleLdap m c e, Applicative m, Functor m, AsExampleLdapError e) => NewUser -> m Text
insertUser nu = do
  uidNumber <- view _Wrapped <$> getNextUidNumber
  insertEntry $ nu & userUidNumber .~ uidNumber
  resetPassword $ nu^.userDn

deleteUser :: (CanExampleLdap m c e, Applicative m, Functor m, AsExampleLdapError e) => User -> m ()
deleteUser = deleteEntry

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
    <$> (attrSingle "uid" (traceShowId e) <&> Uid)
    <*> pure (e ^.to ledn.packed.from _Wrapped)
    <*> (attrSingle "gidNumber" e <&> GidNumber)
    <*> (attrSingle "uidNumber" e <&> UidNumber)
    <*> attrSingle "givenName" e
    <*> attrSingle "sn" e
    <*> attrSingle "displayName" e
    <*> attrSingle "mail" e
    <*> attrMay "mobile" e

instance ToLdapEntry User where
  toLdapDn    = view userDn
  toLdapAttrs u =
    [ ("gidNumber"     , [u^.userGidNumber._Wrapped.to show])
    , ("uidNumber"     , [u^.userUidNumber._Wrapped.to show])
    , ("givenName"     , [u^.userFirstName.from packed])
    , ("sn"            , [u^.userLastName.from packed])
    , ("displayName"   , [u^.userDisplayName.from packed])
    , ("cn"            , [u^.userDisplayName.from packed])
    , ("mail"          , [u^.userEmail.from packed])
    , ("mobile"        , toList $ u^?userMobile._Just.from packed)
    , ("objectClass"   , ["posixAccount","inetOrgPerson","top"])
    , ("homeDirectory" , ["/dev/null"])
    ]

instance FromLdapEntry MemberUids where
  fromLdapEntry e = MemberUids <$> attrList "memberUid" e

instance FromLdapEntry NextUidNumber where
  fromLdapEntry e = NextUidNumber <$> attrSingle "uidNumber" e

main :: IO ()
main = printErr $ do
  LdapOpts h p d s uMay pMay <- liftIO $ execParser opts
  let conf = LdapConfig h p d s (LdapCredentials <$> uMay <*> pMay)
  let dn   = Dn "uid=bkolera2,ou=customers,ou=users,dc=iseek,dc=com,dc=au"
  let newU = User (Uid "bkolera2") dn (GidNumber 11121) () "Ben" "Kolera" "Ben Kolera" "ben.kolera@email.com" (Just "0400123456")
  runLdap' conf $ do
    pw <- insertUser newU
    liftIO . putStrLn . T.unpack $ pw
    checkPassword dn pw
    setPassword dn "hunter2"
    checkPassword dn "hunter2"
    Just u <- getUser (Uid "bkolera2")
    liftIO $ print u
    void $ updateUser (u & userMobile .~ (Just "0499333555"))
    uMayAfter <- getUser (Uid "bkolera2")
    liftIO $ print (uMayAfter :: Maybe User)
    deleteUser u
    uMayGone <- getUser (Uid "bkolera2")
    liftIO $ print (uMayGone :: Maybe User)
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
