{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE NoImplicitPrelude          #-}
{-# LANGUAGE TemplateHaskell            #-}
{-# LANGUAGE TypeFamilies               #-}
module LDAP.Classy.Types where

import           Control.Lens
import           Data.String  (IsString)
import           Data.Text    (Text)
import           Prelude      (Eq, Int, Num, Show)

newtype Uid = Uid Text deriving (Show,IsString,Eq)
makeWrapped ''Uid

newtype UidNumber = UidNumber Int deriving (Show,Num,Eq)
makeWrapped ''UidNumber

newtype GidNumber = GidNumber Int deriving (Show,Num,Eq)
makeWrapped ''GidNumber
