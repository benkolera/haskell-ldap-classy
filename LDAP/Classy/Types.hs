{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE NoImplicitPrelude          #-}
{-# LANGUAGE TemplateHaskell            #-}
{-# LANGUAGE TypeFamilies               #-}
module LDAP.Classy.Types where

import           BasePrelude

import           Control.Lens
import           Data.Text    (Text)

newtype Uid = Uid Text deriving (Show,IsString)
makeWrapped ''Uid

newtype UidNumber = UidNumber Int deriving (Show,Num)
makeWrapped ''UidNumber

newtype Dn = Dn Text deriving (Show,IsString)
makeWrapped ''Dn
