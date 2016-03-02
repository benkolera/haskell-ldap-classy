{-# LANGUAGE FlexibleInstances     #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE NoImplicitPrelude     #-}
{-# LANGUAGE OverloadedStrings     #-}
{-# LANGUAGE TemplateHaskell       #-}
{-# LANGUAGE TypeFamilies          #-}
module LDAP.Classy.SSha where

import           Prelude                     (Eq, Int, Show,show,(==))

import           Control.Applicative         ((<$>))
import           Control.Category            ((.))
import           Control.Lens
import           Control.Monad               (replicateM)

import           Data.Bool                   (Bool (..))
import           Data.ByteString.Base64.Lazy (encode)
import           Data.ByteString.Lazy        (ByteString, pack)
import           Data.Digest.Pure.SHA        (bytestringDigest, sha1)
import           Data.Function               (flip, ($))
import           Data.Functor                (fmap)
import           Data.Monoid                 ((<>))
import           Data.Text.Lazy              (Text, unpack)
import           Data.Text.Lazy.Encoding     (decodeUtf8, encodeUtf8)

import           System.IO                   (IO)
import           System.Random               (getStdRandom, random)

newtype Salt = Salt ByteString deriving Eq
makeWrapped ''Salt

data SSha    = SSha
  { _sShaDigest :: ByteString
  , _sShaSalt   :: Salt
  } deriving (Eq)
makeLenses ''SSha

instance Show SSha where
  show = unpack . decodeUtf8 . sShaToByteString

toSSha :: Text -> IO SSha
toSSha t = hash t <$> getSalt 4

hash :: Text -> Salt -> SSha
hash pw s = SSha
   (bytestringDigest . sha1 $ encodeUtf8 pw <> s^._Wrapped)
   s

sShaToByteString :: SSha -> ByteString
sShaToByteString (SSha d (Salt s)) = "{SSHA}" <> encode (d <> s)

verifySSha :: SSha -> Text -> Bool
verifySSha sSha pw = sSha == hash pw (sSha^.sShaSalt)

getSalt :: Int -> IO Salt
getSalt = fmap (Salt . pack) . flip replicateM (getStdRandom random)
