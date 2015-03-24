{-# LANGUAGE ConstraintKinds            #-}
{-# LANGUAGE FlexibleContexts           #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE NoImplicitPrelude          #-}
{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE ScopedTypeVariables        #-}
{-# LANGUAGE TemplateHaskell            #-}
{-# LANGUAGE TypeFamilies               #-}
module Main where

{-
   WARNING: This Example was actually more used as a POC for the
   library to be added to some iseek code.

   As such, the example is weird and certainly could be better
   organised / more concise, but it certainly is an exhaustive example
   of the use cases that I'm writing the library for...
-}

import           BasePrelude               hiding (first, try)

import           Control.Lens
import           Control.Monad.Error.Hoist ((<!?>), (<?>))
import           Control.Monad.Except      (ExceptT (..), MonadError,
                                            runExceptT)
import           Control.Monad.Reader      (MonadReader, ReaderT, runReaderT)
import           Control.Monad.TM          ((.>>=.))
import           Control.Monad.Trans       (liftIO)
import           Control.Monad.Trans       (MonadIO)
import           Data.Bifunctor            (first)
import           Data.List.NonEmpty        (NonEmpty)
import qualified Data.List.NonEmpty        as NEL
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
                                            checkPassword, deleteEntry,
                                            findByDn, insertEntry, ledn, modify,
                                            modifyEntry, resetPassword, runLdap,
                                            search, searchFirst, setPassword)
import           LDAP.Classy.Decode        (AsLdapEntryDecodeError (..),
                                            FromLdapEntry (..),
                                            ToLdapEntry (..), attrList, attrMay,
                                            attrSingle)
import           LDAP.Classy.Search        (isPosixAccount, isPosixGroup, (&&.),
                                            (==.), (||.))
import           Options.Applicative


data ExampleLdapError
  = ExampleLdapErrorError LdapError
  | NoMaxUid
  | NoMaxGid
  | UserNotFound Dn
  | MissingGid GidNumber
  deriving Show
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

newtype AccountCrmId = AccountCrmId Text deriving (Show)
makeWrapped ''AccountCrmId

newtype CustomerNumber = CustomerNumber Text deriving (Show)
makeWrapped ''CustomerNumber

newtype MemberUids = MemberUids [Uid] deriving Show
makeWrapped ''MemberUids

newtype NextUidNumber = NextUidNumber UidNumber deriving (Show,Num)
makeWrapped ''NextUidNumber

newtype NextGidNumber = NextGidNumber GidNumber deriving (Show,Num)
makeWrapped ''NextGidNumber

data Account' a = Account
  { _accountGid            :: a
  , _accountDn             :: Dn
  , _accountName           :: Text
  , _accountAlias          :: Text
  , _accountCustomerNumber :: CustomerNumber
  , _accountCrmId          :: AccountCrmId
  , _accountMemberUids     :: [Uid]
  , _accountUniqueMembers  :: [Dn]
  } deriving Show
makeLenses ''Account'

type Account    = Account' GidNumber
type NewAccount = Account' ()

data AccountSearchTerm
  = AccountSearchName Text
  | AccountSearchCustomerNumber CustomerNumber
  | AccountSearchCrmId AccountCrmId
  | AccountSearchUsername Uid
makeClassyPrisms ''AccountSearchTerm

data User' a = User
  { _userUid         :: Uid
  , _userDn          :: Dn
  , _userGidNumber   :: GidNumber
  , _userUidNumber   :: a
  , _userFirstName   :: Text
  , _userLastName    :: Text
  , _userDisplayName :: Text
  , _userEmail       :: Text
  , _userMobile      :: Maybe Text
  } deriving Show
makeLenses ''User'

type NewUser = User' ()
type User    = User' UidNumber

data UserSearchTerm
  = UserSearchFirstName Text
  | UserSearchLastName Text
  | UserSearchEmail Text
  | UserSearchUsername Uid
makeClassyPrisms ''UserSearchTerm

accountAttrs :: SearchAttributes
accountAttrs = LDAPAttrList
  [ "gidNumber"
  , "cn"
  , "iseekAlias"
  , "memberUid"
  , "dn"
  , "uniqueMember"
  ]

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

getUserByGidNumber :: (CanExampleLdap m c e, Applicative m , Functor m)  => GidNumber -> m (Maybe User)
getUserByGidNumber gidNum = searchFirst
   (isPosixGroup &&. "gidNumber" ==. (gidNum^._Wrapped.to show))
   accountAttrs

getNextGidNumber :: (CanExampleLdap m c e, Applicative m , Functor m,AsExampleLdapError e) => m NextGidNumber
getNextGidNumber = do
  mGidMay <- getMaxGidNumber
  mGid    <- mGidMay <?> (_NoMaxGid # ())
  nGid    <- nextFreeGid (mGid + 1)
  modify "cn=MaxGroupGid,ou=groups,dc=iseek,dc=com,dc=au" [LDAPMod LdapModReplace "gidNumber" [nGid^._Wrapped._Wrapped.to show]]
  pure nGid
  where
    nextFreeGid mGid = do
      uMay <- getUserByGidNumber (mGid^._Wrapped)
      maybe (pure mGid) (const (nextFreeGid (mGid+1))) uMay

getMaxGidNumber :: (CanExampleLdap m c e, Applicative m, Functor m) => m (Maybe NextGidNumber)
getMaxGidNumber = searchFirst
  ("objectClass" ==. "iseekGidNext" &&. "cn" ==. "MaxGroupGid")
  (LDAPAttrList ["gidNumber"])

insertAccount :: (CanExampleLdap m c e, Applicative m, Functor m, AsExampleLdapError e) => NewAccount -> m ()
insertAccount na = do
  gid <- view _Wrapped <$> getNextGidNumber
  let acct  = na & accountGid .~ gid
  insertEntry acct

updateAccount :: (CanExampleLdap m c e, Applicative m, Functor m) => Account -> m ()
updateAccount = modifyEntry

listUidsForAccount :: (CanExampleLdap m c e, Applicative m) => AccountCrmId -> m MemberUids
listUidsForAccount a = do
  res <- searchFirst (isPosixGroup &&. "iseekSalesforceID" ==. (a^._Wrapped.from packed)) (LDAPAttrList ["memberUid"])
  pure . fromMaybe (MemberUids []) $ res

addUserToAccount :: (CanExampleLdap m c e, Applicative m) => User -> Account-> m ()
addUserToAccount u a = updateAccount $ a
  & accountUniqueMembers %~ (++ [u^.userDn])
  & accountMemberUids    %~ (++ [u^.userUid])

addUserToGid :: (CanExampleLdap m c e, Applicative m,AsExampleLdapError e) => User -> GidNumber -> m ()
addUserToGid u gid = do
  a <- getAccountByGid gid <!?> (_MissingGid # gid)
  addUserToAccount u a

removeUserFromAccount :: (CanExampleLdap m c e, Applicative m) => User -> Account -> m ()
removeUserFromAccount u a = updateAccount $ a
  & accountUniqueMembers %~ filter (/= u^.userDn)
  & accountMemberUids    %~ filter (/= u^.userUid)

accountsOfUser :: (CanExampleLdap m c e, Applicative m) => User -> m [Account]
accountsOfUser u = search
  (   "memberUid" ==. u^.userUid._Wrapped.from packed
  ||. "uniqueMember" ==. u^.userDn._Wrapped.from packed
  )
  accountAttrs

getAccountByGid
  :: (CanExampleLdap m c e,Applicative m)
  => GidNumber
  -> m (Maybe Account)
getAccountByGid gidNumber = searchFirst
   (isPosixGroup &&. "gidNumber" ==. (gidNumber^._Wrapped.to show))
   accountAttrs

getUser :: (CanExampleLdap m c e, Applicative m , Functor m) => Uid -> m (Maybe User)
getUser uid = searchFirst
   (isPosixAccount &&. "uid" ==. (uid^._Wrapped.from packed))
   userAttrs

searchUsers :: (CanExampleLdap m c e, Applicative m , Functor m) => NonEmpty UserSearchTerm -> m [User]
searchUsers sts = search
  (foldl (&&.) (NEL.head searchExprs) $ (NEL.tail searchExprs))
  userAttrs
  where
    searchExprs = fmap searchTerm sts
    searchTerm (UserSearchUsername uid) = "uid"       ==. uid^._Wrapped.from packed
    searchTerm (UserSearchFirstName fn) = "givenName" ==. fn^.from packed
    searchTerm (UserSearchLastName  sn) = "sn"        ==. sn^.from packed
    searchTerm (UserSearchEmail      e) = "mail"      ==. e^.from packed

updateUser :: (CanExampleLdap m c e, Applicative m, Functor m,AsExampleLdapError e) => User -> m ()
updateUser u = do
  (oldU :: Maybe User) <- findByDn (u^.userDn) userAttrs
  aMay <- oldU .>>=. (getAccountByGid . (^.userGidNumber))
  modifyEntry u
  case aMay of
   Just a | a^.accountGid /= u^.userGidNumber -> do
     removeUserFromAccount u a
     addUserToGid u (u^.userGidNumber)
   Nothing -> addUserToGid u (u^.userGidNumber)
   _       -> pure ()

insertUser :: (CanExampleLdap m c e, Applicative m, Functor m, AsExampleLdapError e) => NewUser -> m Text
insertUser nu = do
  let gid = nu^.userGidNumber
  account   <- getAccountByGid gid <!?> (_MissingGid # gid)
  uidNumber <- view _Wrapped <$> getNextUidNumber
  let user  = nu & userUidNumber .~ uidNumber
  insertEntry user
  addUserToAccount user account
  resetPassword $ nu^.userDn

deleteUser :: (CanExampleLdap m c e, Applicative m, Functor m, AsExampleLdapError e) => User -> m ()
deleteUser u = do
  deleteEntry u
  accountsOfUser u >>= traverse_ (removeUserFromAccount u)

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

instance FromLdapEntry Account where
  fromLdapEntry e = Account
    <$> (attrSingle "gidNumber" e <&> GidNumber)
    <*> pure (e ^.to ledn.packed.from _Wrapped)
    <*> attrSingle "cn" e
    <*> attrSingle "iseekAlias" e
    <*> (attrSingle "iseekCustomerNumber" e <&> CustomerNumber)
    <*> (attrSingle "iseekSalesforceId" e <&> AccountCrmId)
    <*> (attrList "memberUid" e <&> fmap Uid)
    <*> (attrList "uniqueMember" e <&> fmap Dn)

instance ToLdapEntry Account where
  toLdapDn      = view accountDn
  toLdapAttrs a =
    [ ("cn"                  ,[a^.accountName.from packed])
    , ("gidNumber"           ,[a^.accountGid._Wrapped.to show])
    , ("iseekAlias"          ,[a^.accountName.from packed])
    , ("iseekCustomerNumber" ,[a^.accountCustomerNumber._Wrapped.to show])
    , ("iseekSalesforceId"   ,[a^.accountCustomerNumber._Wrapped.from packed])
    , ("memberUid"           , a^..accountMemberUids.traverse._Wrapped.from packed)
    , ("uniqueMember"        , a^..accountUniqueMembers.traverse._Wrapped.from packed)
    ]

instance FromLdapEntry User where
  fromLdapEntry e = User
    <$> (attrSingle "uid" e <&> Uid)
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

instance FromLdapEntry NextGidNumber where
  fromLdapEntry e = NextGidNumber <$> attrSingle "gidNumber" e

main :: IO ()
main = printErr $ do
  LdapOpts h p d s uMay pMay <- liftIO $ execParser opts
  let conf = LdapConfig h p d s (LdapCredentials <$> uMay <*> pMay)
  let gid  = GidNumber 11121
  let dn   = Dn "uid=bkolera2,ou=customers,ou=users,dc=iseek,dc=com,dc=au"
  let newU = User (Uid "bkolera2") dn gid () "Ben" "Kolera" "Ben Kolera" "ben.kolera@email.com" (Just "0400123456")
  runLdap' conf $ do
    getAccountByGid gid >>= liftIO . print
    pw <- insertUser newU
    getAccountByGid gid >>= liftIO . print
    checkPassword dn pw
    setPassword dn "hunter2"
    checkPassword dn "hunter2"
    Just u <- getUser (Uid "bkolera2")
    liftIO $ print u
    void $ updateUser (u & userMobile .~ (Just "0499333555"))
    uMayAfter <- getUser (Uid "bkolera2")
    liftIO $ print (uMayAfter :: Maybe User)
    void $ updateUser (u & userGidNumber .~ (GidNumber 11124))
    getAccountByGid gid >>= liftIO . print
    getAccountByGid (GidNumber 11124) >>= liftIO . print
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
